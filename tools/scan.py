#!/usr/bin/env python3
"""Run the raptor checkers over a project using its compile_commands.json.

  tools/scan.py compile_commands.json -o findings.json [--checkers raptor] [-j 8]
  tools/scan.py ... --checkers raptor,core,unix --report '.'   # keep all warnings

Each translation unit is analysed with its real build flags (so the
preprocessor resolves #if/#else exactly as the build did) and the plugin's
warnings are collected into a JSON list of {file, line, col, checker, message}.

`--analyze` makes the driver pass -w, so a second, parse-only pass
(-fsyntax-only) collects a few compiler warnings that catch bug patterns no
checker needs to reimplement (`--warnings`, empty to skip it); they are
reported with the flag as the checker, e.g. "-Wmisleading-indentation":
  -Wstring-compare          `s == "literal"` compares pointers
  -Wmisleading-indentation  `if (c) goto fail; goto fail;` (Apple goto fail)
  -Wunreachable-code        code that can never run
"""
import argparse
import concurrent.futures as cf
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIAG = re.compile(r'^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+): warning: (?P<msg>.*) \[(?P<checker>[\w.-]+)\]$', re.M)
# compiler errors, including the driver's own (`clang-18: error: clang frontend
# command failed ...` when clang crashes)
ERROR = re.compile(r'^(?:[^:\n]+:\d+:\d+: |clang[\w.+-]*: )?(?:fatal )?error: .*$', re.M)
# flags that make no sense for analysis
DROP_WITH_ARG = {'-o', '-MF', '-MT', '-MQ'}
DROP = {'-c', '-MD', '-MMD', '-M', '-MM', '-MP'}


def keep_w(flag):
    """-W flags that change what compiles: -Wno-* can turn off a diagnostic that
    is an error by default (e.g. incompatible-function-pointer-types since
    clang 16), and -Wp,-D/-U define macros."""
    return flag.startswith(('-Wno-', '-Wp,-D', '-Wp,-U'))


DEFAULT_WARNINGS = 'string-compare,misleading-indentation,unreachable-code'


def build_flags(entry):
    """The TU's compile command without output, dependency, optimisation and
    warning flags, with a clang compiler."""
    args = entry.get('arguments') or shlex.split(entry['command'])
    out, skip = [args[0]], False
    for a in args[1:]:
        if skip:
            skip = False
            continue
        if a in DROP_WITH_ARG:
            skip = True
            continue
        if a in DROP or a.startswith('-O') or (a.startswith('-W') and not keep_w(a)):
            continue
        out.append(a)
    if 'clang' not in pathlib.Path(out[0]).name:
        out[0] = 'clang++' if entry['file'].endswith(('.cpp', '.cc', '.cxx')) else 'clang'
    # colour codes would hide every diagnostic from DIAG
    return out + ['-fno-color-diagnostics']


def warnings_cmd(entry, warnings):
    return build_flags(entry) + ['-fsyntax-only', '-Wno-everything'] + [f'-W{w}' for w in warnings]


def analysis_cmd(entry, plugin, checkers, disabled):
    out = build_flags(entry)
    out += ['--analyze', '-w', '-o', '/dev/null',
            '-Xclang', '-load', '-Xclang', str(plugin),
            '-Xclang', f'-analyzer-checker={checkers}',
            '-Xclang', '-analyzer-output=text']
    if disabled:
        out += ['-Xclang', f'-analyzer-disable-checker={disabled}']
    return out


def diags(entry, stderr, keep):
    out = []
    for m in DIAG.finditer(stderr):
        if keep(m['checker']):
            f = os.path.normpath(os.path.join(entry['directory'], m['file']))
            out.append({'file': f, 'line': int(m['line']), 'col': int(m['col']),
                        'checker': m['checker'], 'message': m['msg']})
    return out


def run(entry, plugin, checkers, disabled, report, timeout, warnings=()):
    cmd = analysis_cmd(entry, plugin, checkers, disabled)
    try:
        p = subprocess.run(cmd, cwd=entry['directory'], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return entry['file'], [], 'timeout'
    found = diags(entry, p.stderr, lambda c: re.match(report, c))
    if warnings:
        wanted = {f'-W{w}' for w in warnings}
        try:
            w = subprocess.run(warnings_cmd(entry, warnings), cwd=entry['directory'],
                               capture_output=True, text=True, timeout=timeout)
            found += diags(entry, w.stderr, lambda c: c in wanted)
        except subprocess.TimeoutExpired:
            pass
    errors = ERROR.findall(p.stderr)
    if not errors and p.returncode != 0:
        errors = [f'clang exited with code {p.returncode}']
    return entry['file'], found, (errors[0] if errors else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cdb')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--plugin', default=str(ROOT / 'build' / 'RaptorCheckers.so'))
    ap.add_argument('--checkers', default='raptor')
    ap.add_argument('--disable', default='', help='checkers to disable (-analyzer-disable-checker)')
    ap.add_argument('--report', default=r'raptor\.', help='keep warnings of checkers matching this regex')
    ap.add_argument('--filter', default='', help='only TUs whose path matches this regex')
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count())
    ap.add_argument('--timeout', type=int, default=600)
    ap.add_argument('--warnings', default=DEFAULT_WARNINGS,
                    help='comma-separated compiler warnings (without -W) to collect in a '
                         'parse-only pass; empty to skip it')
    a = ap.parse_args()
    warnings = tuple(w for w in a.warnings.split(',') if w)

    entries = [e for e in json.load(open(a.cdb)) if re.search(a.filter, e['file'])]
    seen, findings, failures = set(), [], []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run, e, a.plugin, a.checkers, a.disable, a.report, a.timeout, warnings)
                for e in entries]
        for i, fut in enumerate(cf.as_completed(futs), 1):
            tu, found, err = fut.result()
            if err:
                failures.append({'file': tu, 'error': err})
            for f in found:  # headers are reported once per including TU
                key = (f['file'], f['line'], f['col'], f['checker'])
                if key not in seen:
                    seen.add(key)
                    findings.append(f)
            print(f'\r{i}/{len(entries)} TUs, {len(findings)} findings', end='', file=sys.stderr)
    print(file=sys.stderr)
    findings.sort(key=lambda f: (f['file'], f['line'], f['checker']))
    json.dump({'findings': findings, 'failures': failures, 'tus': len(entries)},
              open(a.output, 'w'), indent=1)
    print(f'{len(entries)} TUs, {len(findings)} findings, {len(failures)} TUs with errors/timeouts')


if __name__ == '__main__':
    main()
