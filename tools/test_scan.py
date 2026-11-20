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


RLO, LRI, PDI, PDF, RLE = '‮', '⁦', '⁩', '‬', '‫'


class Bidi(unittest.TestCase):
    """Trojan Source (CVE-2021-42574): a bidi embedding, override or isolate
    left open at the end of a line reorders how the rest of the line is shown,
    so the code reads differently from how it compiles."""

    def lines(self, text):
        return [(f['line'], f['col']) for f in scan.bidi_findings_text('a.c', text)]

    def test_reports_override_left_open_in_string(self):
        # the paper's "stretched string": the comment is inside the literal
        src = 'int f(const char *r) {\n' \
              f'  if (strcmp(r, "user{RLO} {LRI}// admin{PDI} {LRI}")) return 1;\n' \
              '  return 0;\n}\n'
        self.assertEqual(self.lines(src), [(2, 22)])

    def test_reports_isolate_left_open_in_comment(self):
        # "commenting out": the early return is shown inside the comment
        src = f'/*{RLO} {LRI} if (isAdmin) {PDI} {LRI} begin admins only */\n'
        self.assertEqual(self.lines(src), [(1, 3)])

    def test_balanced_controls_are_not_reported(self):
        # right-to-left text that is closed again on the same line is legitimate
        src = f'const char *s = "{RLE}abc{PDF} {LRI}def{PDI}";\n'
        self.assertEqual(self.lines(src), [])

    def test_text_without_controls_is_not_reported(self):
        self.assertEqual(self.lines('int main(void) { return 0; }\n'), [])

    def test_finding_names_the_code_point(self):
        f = scan.bidi_findings_text('a.c', f'// {RLO}x\n')[0]
        self.assertEqual(f['checker'], 'bidi-control')
        self.assertIn('U+202E', f['message'])
        self.assertEqual(f['file'], 'a.c')

    def test_reads_the_entry_file_relative_to_its_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            pathlib.Path(d, 'src').mkdir()
            pathlib.Path(d, 'src', 'b.c').write_text(f'int x; // {RLO}\n', encoding='utf-8')
            found = scan.bidi_findings({'directory': d, 'file': 'src/b.c'})
            self.assertEqual([(f['file'], f['line']) for f in found],
                             [(str(pathlib.Path(d, 'src', 'b.c')), 1)])

    def test_run_adds_bidi_findings_unless_disabled(self):
        import tempfile
        from unittest import mock
        quiet = mock.Mock(return_value=mock.Mock(stderr='', returncode=0))
        with tempfile.TemporaryDirectory() as d, mock.patch.object(scan.subprocess, 'run', quiet):
            pathlib.Path(d, 'b.c').write_text(f'// {RLO}\n', encoding='utf-8')
            entry = {'directory': d, 'file': 'b.c', 'arguments': ['clang', '-c', 'b.c']}
            _, found, err = scan.run(entry, '/p.so', 'raptor', '', r'raptor\.', 60)
            self.assertEqual([f['checker'] for f in found], ['bidi-control'])
            self.assertIsNone(err)
            _, found, _ = scan.run(entry, '/p.so', 'raptor', '', r'raptor\.', 60, bidi=False)
            self.assertEqual(found, [])

    def test_unreadable_file_gives_no_findings(self):
        self.assertEqual(scan.bidi_findings({'directory': '/nonexistent', 'file': 'x.c'}), [])


if __name__ == '__main__':
    unittest.main()
