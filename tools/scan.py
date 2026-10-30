#!/usr/bin/env python3
"""Run the raptor checkers over a project using its compile_commands.json.

  tools/scan.py compile_commands.json -o findings.json [--checkers raptor] [-j 8]

Each translation unit is analysed with its real build flags (so the
preprocessor resolves #if/#else exactly as the build did) and the plugin's
warnings are collected into a JSON list of {file, line, col, checker, message}.
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
DIAG = re.compile(r'^(?P<file>[^:\n]+):(?P<line>\d+):(?P<col>\d+): warning: (?P<msg>.*) \[(?P<checker>raptor\.\w+)\]$', re.M)
ERROR = re.compile(r'^(?:[^:\n]+:\d+:\d+: |clang: )?(?:fatal )?error: .*$', re.M)
# flags that make no sense for analysis
DROP_WITH_ARG = {'-o', '-MF', '-MT', '-MQ'}
DROP = {'-c', '-MD', '-MMD', '-M', '-MM', '-MP'}


def analysis_cmd(entry, plugin, checkers):
    args = entry.get('arguments') or shlex.split(entry['command'])
    out, skip = [args[0]], False
    for a in args[1:]:
        if skip:
            skip = False
            continue
        if a in DROP_WITH_ARG:
            skip = True
            continue
        if a in DROP or a.startswith('-O') or a.startswith('-W'):
            continue
        out.append(a)
    if 'clang' not in pathlib.Path(out[0]).name:
        out[0] = 'clang++' if entry['file'].endswith(('.cpp', '.cc', '.cxx')) else 'clang'
    out += ['--analyze', '-w', '-o', '/dev/null',
            '-Xclang', '-load', '-Xclang', str(plugin),
            '-Xclang', f'-analyzer-checker={checkers}',
            '-Xclang', '-analyzer-output=text']
    return out


def run(entry, plugin, checkers, timeout):
    cmd = analysis_cmd(entry, plugin, checkers)
    try:
        p = subprocess.run(cmd, cwd=entry['directory'], capture_output=True,
                           text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return entry['file'], [], 'timeout'
    found = []
    for m in DIAG.finditer(p.stderr):
        f = os.path.normpath(os.path.join(entry['directory'], m['file']))
        found.append({'file': f, 'line': int(m['line']), 'col': int(m['col']),
                      'checker': m['checker'], 'message': m['msg']})
    errors = ERROR.findall(p.stderr)
    return entry['file'], found, (errors[0] if errors else None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cdb')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--plugin', default=str(ROOT / 'build' / 'RaptorCheckers.so'))
    ap.add_argument('--checkers', default='raptor')
    ap.add_argument('--filter', default='', help='only TUs whose path matches this regex')
    ap.add_argument('-j', '--jobs', type=int, default=os.cpu_count())
    ap.add_argument('--timeout', type=int, default=600)
    a = ap.parse_args()

    entries = [e for e in json.load(open(a.cdb)) if re.search(a.filter, e['file'])]
    seen, findings, failures = set(), [], []
    with cf.ThreadPoolExecutor(a.jobs) as ex:
        futs = [ex.submit(run, e, a.plugin, a.checkers, a.timeout) for e in entries]
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
