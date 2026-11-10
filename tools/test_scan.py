#!/usr/bin/env python3
"""Unit tests for scan.py's command rewriting:  python3 tools/test_scan.py"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import scan  # noqa: E402


def cmd(*flags, file='a.c'):
    entry = {'directory': '/src', 'file': file,
             'arguments': ['clang', *flags, '-c', file, '-o', 'a.o']}
    return scan.analysis_cmd(entry, '/p.so', 'raptor', '')


class AnalysisCmd(unittest.TestCase):
    def test_keeps_flags_that_turn_default_errors_off(self):
        # SymCrypt builds with these; clang >= 16 makes both errors by default,
        # so dropping them makes the TU fail to compile.
        out = cmd('-Wno-incompatible-function-pointer-types',
                  '-Wno-error=incompatible-pointer-types')
        self.assertIn('-Wno-incompatible-function-pointer-types', out)
        self.assertIn('-Wno-error=incompatible-pointer-types', out)

    def test_keeps_preprocessor_defines_passed_through_wp(self):
        out = cmd('-Wp,-D_FORTIFY_SOURCE=2', '-Wp,-UNDEBUG')
        self.assertIn('-Wp,-D_FORTIFY_SOURCE=2', out)
        self.assertIn('-Wp,-UNDEBUG', out)

    def test_drops_warning_and_dependency_flags(self):
        out = cmd('-Wall', '-Werror', '-Werror=format', '-Wp,-MD,a.d', '-MD', '-MF', 'a.d', '-O2')
        for f in ('-Wall', '-Werror', '-Werror=format', '-Wp,-MD,a.d', '-MD', '-MF', 'a.d', '-O2', '-c'):
            self.assertNotIn(f, out)

    def test_disables_colour_so_diagnostics_parse(self):
        out = cmd('-fdiagnostics-color=always')
        self.assertIn('-fno-color-diagnostics', out)
        self.assertGreater(out.index('-fno-color-diagnostics'), out.index('-fdiagnostics-color=always'))


if __name__ == '__main__':
    unittest.main()
