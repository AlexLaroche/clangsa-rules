#!/usr/bin/env python3
"""Integration tests: real CVEs in real code, before and after the fix.

Each case in tests/integration/cases.json names a repository, the commit
that fixed a known vulnerability and that commit's parent, a checker, and
for each source file the regexes of the vulnerable lines (the sinks). The
sources are fetched at both commits (shallow, by SHA) and analysed with the
plugin:

  vulnerable commit   every sink line must be reported by the checker
  fixed commit        no sink line may be reported

Each sink regex must match exactly one line of the file at both commits, so
a test cannot pass because the line moved or vanished.

  tools/run_integration.py [CASE...] [--plugin build/RaptorCheckers.so]
"""
import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DIAG = re.compile(r'^(?P<file>[^:\n]+):(?P<line>\d+):\d+: warning: .*\[(?P<checker>[\w.]+)\]$', re.M)
ERROR = re.compile(r'^(?:[^:\n]+:\d+:\d+: |clang[\w.+-]*: )?(?:fatal )?error: .*$', re.M)


def sh(cmd, cwd, **kw):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, **kw)


def checkout(repo, sha, dest, setup):
    """Shallow checkout of repo at sha into dest (cached), then run setup."""
    stamp = dest / '.raptor-ready'
    if stamp.exists():
        return
    if dest.exists():
        subprocess.run(['rm', '-rf', str(dest)], check=True)
    dest.mkdir(parents=True)
    sh(['git', 'init', '-q'], dest)
    sh(['git', 'fetch', '-q', '--depth', '1', repo, sha], dest, timeout=600)
    sh(['git', '-c', 'advice.detachedHead=false', 'checkout', '-q', 'FETCH_HEAD'], dest)
    got = sh(['git', 'rev-parse', 'HEAD'], dest).stdout.strip()
    if got != sha:
        raise RuntimeError(f'{repo}: fetched {got}, expected {sha}')
    for cmd in setup:
        sh(cmd, dest, timeout=600)
    stamp.touch()


def analyze(plugin, src, rel, checker, args):
    cmd = ['clang', '--analyze', '-w', '-Wno-error=incompatible-pointer-types',
           '-Xclang', '-load', '-Xclang', str(plugin),
           '-Xclang', f'-analyzer-checker={checker}',
           '-Xclang', '-analyzer-output=text', '-o', '/dev/null', *args, rel]
    p = subprocess.run(cmd, cwd=src, capture_output=True, text=True)
    errors = ERROR.findall(p.stderr)
    lines = {int(m['line']) for m in DIAG.finditer(p.stderr)
             if m['checker'] == checker and os.path.normpath(m['file']) == os.path.normpath(rel)}
    return p.returncode, errors, lines


def sink_lines(path, pattern):
    rx = re.compile(pattern)
    text = path.read_text(errors='ignore').split('\n')
    return [i for i, l in enumerate(text, 1) if rx.search(l)]


def run_case(case, plugin, cache, verbose):
    ok = True
    for side in ('vulnerable', 'fixed'):
        sha = case[side]
        src = cache / case['name'] / sha
        try:
            checkout(case['repo'], sha, src, case.get('setup', []))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as e:
            out = getattr(e, 'stderr', '') or ''
            print(f'FAIL {case["name"]} {side} {sha[:10]}: checkout/setup failed: {e}\n{out[-2000:]}')
            return False
        for rel, sinks in case['files'].items():
            rc, errors, found = analyze(plugin, src, rel, case['checker'], case.get('args', []))
            label = f'{case["name"]:16} {side:10} {sha[:10]} {rel}'
            if errors or rc != 0:
                ok = False
                print(f'FAIL {label}: clang failed (rc={rc})')
                for e in errors[:10]:
                    print('    ' + e)
                continue
            problems = []
            for pat in sinks:
                hits = sink_lines(src / rel, pat)
                if len(hits) != 1:
                    problems.append(f'sink /{pat}/ matches {len(hits)} lines {hits}, expected 1')
                    continue
                line = hits[0]
                reported = line in found
                if side == 'vulnerable' and not reported:
                    problems.append(f'missed sink at line {line} /{pat}/')
                if side == 'fixed' and reported:
                    problems.append(f'reported fixed sink at line {line} /{pat}/')
            ok &= not problems
            print(f'{"FAIL" if problems else "PASS"} {label}'
                  + (f' ({len(found)} {case["checker"]} findings in file)' if verbose else ''))
            for p in problems:
                print('    ' + p)
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('cases', nargs='*', help='case names (default: all)')
    ap.add_argument('--plugin', default=str(ROOT / 'build' / 'RaptorCheckers.so'))
    ap.add_argument('--cases-file', default=str(ROOT / 'tests' / 'integration' / 'cases.json'))
    ap.add_argument('--cache', default=str(ROOT / 'build' / 'integration-src'),
                    help='where sources are checked out (reused between runs)')
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    cases = json.load(open(a.cases_file))
    if a.cases:
        unknown = set(a.cases) - {c['name'] for c in cases}
        if unknown:
            sys.exit(f'unknown case(s): {", ".join(sorted(unknown))}')
        cases = [c for c in cases if c['name'] in a.cases]
    cache = pathlib.Path(a.cache)
    plugin = pathlib.Path(a.plugin).resolve()
    passed = sum(run_case(c, plugin, cache, a.verbose) for c in cases)
    print(f'\n{passed}/{len(cases)} integration cases passed')
    sys.exit(0 if passed == len(cases) else 1)


if __name__ == '__main__':
    main()
