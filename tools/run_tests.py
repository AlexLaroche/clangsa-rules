#!/usr/bin/env python3
"""Run the raptor checkers on tests/ and compare with the semgrep-style
annotations, like `semgrep --test`.

  // ruleid: raptor-<rule>       a finding is expected (next line, or this
                                 line when the comment trails code)
  // ok: raptor-<rule>           no finding is expected
  // todoruleid: / todook:       known false negative / false positive

Each tests/<rule>.c(pp) is analysed with only raptor.<CamelRule> enabled.
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ANN = re.compile(r'//\s*(ruleid|ok|todoruleid|todook):\s*([\w-]+)')
ERROR = re.compile(r'^(?:[^:\n]+:\d+:\d+: |clang(?:\+\+)?: )?(?:fatal )?error: .*$', re.M)
DIAG = re.compile(r'^(?P<file>[^:\n]+):(?P<line>\d+):\d+: warning: .*\[(?P<checker>raptor\.\w+)\]$', re.M)


def camel(rule):
    return ''.join(p[:1].upper() + p[1:] for p in rule.split('-'))


def annotations(path):
    expect = {}  # kind -> set of lines
    lines = path.read_text(errors='ignore').split('\n')
    for i, line in enumerate(lines, 1):
        m = ANN.search(line)
        if not m:
            continue
        code_before = line[:m.start()].strip()
        target = i if code_before else i + 1
        # allow several stacked annotation lines above one statement
        while not code_before and target <= len(lines) and ANN.search(lines[target - 1]) \
                and not lines[target - 1][:ANN.search(lines[target - 1]).start()].strip():
            target += 1
        expect.setdefault(m.group(1), set()).add(target)
    return expect


def analyze(plugin, path, checker, extra=()):
    cc = 'clang++' if path.suffix in ('.cpp', '.cc') else 'clang'
    cmd = [cc, '--analyze', '-w', '-Xclang', '-load', '-Xclang', str(plugin),
           '-Xclang', f'-analyzer-checker={checker}',
           '-Xclang', '-analyzer-output=text', '-o', '/dev/null', *extra, str(path)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stderr


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rules', nargs='*', help='rule names (default: all tests)')
    ap.add_argument('--plugin', default=str(ROOT / 'build' / 'RaptorCheckers.so'))
    ap.add_argument('-v', '--verbose', action='store_true')
    a = ap.parse_args()

    tests = sorted(p for p in (ROOT / 'tests').iterdir() if p.suffix in ('.c', '.cpp'))
    if a.rules:
        tests = [t for t in tests if t.stem.removesuffix('-cpp') in a.rules or t.stem in a.rules]
    failed = 0
    for t in tests:
        rule = t.stem
        checker = 'raptor.' + camel(rule)
        rc, err = analyze(a.plugin, t, checker)
        errors = ERROR.findall(err)
        found = {int(m['line']) for m in DIAG.finditer(err)
                 if m['checker'] == checker and pathlib.Path(m['file']).name == t.name}
        exp = annotations(t)
        want = exp.get('ruleid', set())
        missed = sorted(want - found)
        incorrect = sorted(found - want - exp.get('todook', set()) - exp.get('todoruleid', set()))
        ok = not missed and not incorrect and not errors and rc == 0
        failed += not ok
        status = 'PASS' if ok else 'FAIL'
        print(f'{status} {checker:44} expected={len(want):3} found={len(found):3}'
              + (f' missed={missed}' if missed else '')
              + (f' incorrect={incorrect}' if incorrect else '')
              + (f' compile-errors={len(errors)}' if errors else ''))
        if errors and a.verbose:
            print('\n'.join('    ' + e for e in errors[:10]))
    print(f'\n{len(tests) - failed}/{len(tests)} checker tests passed')
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
