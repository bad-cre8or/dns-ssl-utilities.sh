#!/usr/bin/env python3
"""Report contracts: no missing values, clipped panels, or false successes."""

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'helpers'))
import render_report as report

SAMPLE = (ROOT / 'tests/fixtures/overview.txt').read_text()
ANSI = re.compile(r'\x1b\[[0-9;]*m')


class ReportTests(unittest.TestCase):
    def render(self, width=80, sample=SAMPLE, ascii_mode=False, host='example.test'):
        sections, counts = report.parse(sample)
        return report.Layout(width, False, ascii_mode).render(host, sections, counts)

    def test_layout_fits_narrow_and_wide_terminals(self):
        for width in (24, 32, 40, 80, 109, 110, 111, 124, 160):
            with self.subTest(width=width):
                output = self.render(width, host='long-label.' * 15 + 'example.test')
                self.assertLessEqual(max(map(report.cells, output.splitlines())), min(124, width))
                self.assertTrue(all(report.cells(line) == min(124, width)
                                    for line in output.splitlines() if line.startswith(('╭', '│', '╰'))))

    def test_values_survive_wrapping(self):
        for width in (24, 40, 80):
            output = self.render(width)
            # Unwrap a stacked layout, ignoring only presentation characters.
            flat = ''.join(c for c in output if not c.isspace() and c not in '╭╮╰╯─│')
            for value in ('192.0.2.10', '192.0.2.11', '2001:db8::10',
                          'ns1.example.test', 'ns2.example.test',
                          'v=spf1 include:_spf.example.test include:mail.example.test ~all',
                          "CN=E7,O=Let's Encrypt,C=US", '*.example.test',
                          'Dec 11 20:00:18 2026 GMT', 'resolver timed out'):
                self.assertIn(''.join(value.split()), flat)

    def test_wide_layout_pairs_related_sections(self):
        lines = self.render(124).splitlines()
        self.assertTrue(any('DNS RECORDS' in line and 'MAIL & POLICY' in line for line in lines))
        self.assertTrue(any('TLS CERTIFICATE' in line and 'HTTP & HTTPS' in line for line in lines))
        self.assertFalse(any('DNS RECORDS' in line and 'MAIL & POLICY' in line for line in self.render(80).splitlines()))

    def test_errors_and_expiry_keep_their_original_severity(self):
        sample = SAMPLE.replace('[OK]  SPF contains: v=spf1 include:_spf.example.test include:mail.example.test ~all',
                                '[X]  SPF lookup failed; record presence is unknown')
        sample = sample.replace('[OK]  Certificate hostname match', '[X]  Certificate hostname mismatch')
        sample = sample.replace('[OK]  Certificate expires in 55 days:', '[X]  Certificate expired:')
        output = self.render(sample=sample)
        self.assertIn('record presence is unknown', output)
        self.assertIn('mismatch', output)
        self.assertIn('Expired', output)
        self.assertIn('5 FAIL', output)

    def test_optional_reverse_dns_and_registrar_failure(self):
        sample = SAMPLE.split('\n== REVERSE DNS')[0]
        sample = sample.replace('  Example Registrar AS', '  [!]  WHOIS timed out after 10s')
        output = self.render(sample=sample)
        self.assertIn('WHOIS timed out after 10s', output)
        self.assertNotIn('REVERSE DNS', output)

    def test_unexpected_report_shape_falls_back_instead_of_losing_data(self):
        with self.assertRaises(ValueError):
            report.parse(SAMPLE + '\n== NEW SECTION\n  Important result\n')

    def test_terminal_controls_are_printed_literally(self):
        output = self.render(sample=SAMPLE.replace('Example Registrar AS', 'Registrar\x1b[2J 100%'))
        self.assertNotIn('\x1b', output)
        self.assertIn(r'Registrar\x1b[2J 100%', output)

    def test_ascii_borders_and_color_cli_modes(self):
        for colorterm, expected in [('truecolor', '\x1b[38;2;'), ('', '\x1b[38;5;')]:
            env = {**os.environ, 'COLORTERM': colorterm}
            output = subprocess.check_output([
                sys.executable, str(ROOT / 'helpers/render_report.py'), '--host', 'example.test',
                '--color', '1', '--ascii', '1', '--width', '80',
            ], input=SAMPLE, text=True, env=env)
            self.assertIn(expected, output)
            plain = ANSI.sub('', output)
            self.assertNotIn('╭', plain)
            self.assertNotIn('│', plain)
            self.assertIn('+ 15 OK', plain)

    def test_adapter_preserves_calls_errors_and_fallback_results(self):
        script = '''
source "$1/lib/core.sh"
source "$1/lib/report.sh"
dsu_site_check() {
  printf '%s\\n' "$*" >>"$CALL_LOG"
  cat "$FIXTURE"
  return "${PROBE_RC:-0}"
}
dsu_site_report "${@:2}"
'''
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / 'fixture.txt'
            log = Path(tmp) / 'calls.log'
            fixture.write_text(SAMPLE)
            env = {**os.environ, 'DSU_FORCE_COLOR': '1', 'DSU_PLAIN': '0',
                   'DSU_HOME': str(ROOT), 'FIXTURE': str(fixture), 'CALL_LOG': str(log)}
            for args, rc in [(['example.test', '--no-rdns'], 0),
                             (['example.test', '--dns', 'A'], 0),
                             (['example.test'], 2)]:
                log.write_text('')
                output = subprocess.run(['bash', '-c', script, '_', str(ROOT), *args],
                                        env={**env, 'PROBE_RC': str(rc)}, text=True, capture_output=True)
                self.assertEqual(output.returncode, rc)
                self.assertEqual(log.read_text().strip(), ' '.join(args))
                if '--dns' in args or rc:
                    self.assertEqual(output.stdout.strip(), SAMPLE.strip())
                else:
                    self.assertIn('DOMAIN REPORT', output.stdout)
            fixture.write_text('Unrecognized report with an important result\n')
            output = subprocess.run(['bash', '-c', script, '_', str(ROOT), 'example.test'],
                                    env=env, text=True, capture_output=True)
            self.assertEqual(output.returncode, 0)
            self.assertEqual(output.stdout.strip(), fixture.read_text().strip())

    @unittest.skipUnless(shutil.which('script'), 'PTY helper is unavailable')
    def test_terminal_defaults_and_width_without_exported_columns(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / 'terminal.sh'
            script.write_text('''
stty cols 124
unset COLUMNS
source "$1/lib/core.sh"
source "$1/lib/report.sh"
dsu_site_check() { cat "$DSU_TEST_FIXTURE"; }
dsu_site_report example.test
''')
            command = f'bash {shlex.quote(str(script))} {shlex.quote(str(ROOT))}'
            output = subprocess.check_output(['script', '-q', '-e', '-c', command, '/dev/null'],
                                             text=True, env={**os.environ, 'NO_COLOR': '1',
                                             'DSU_FORCE_COLOR': '0', 'DSU_PLAIN': '0',
                                             'DSU_TEST_FIXTURE': str(ROOT / 'tests/fixtures/overview.txt')})
            self.assertNotIn('\x1b', output)
            self.assertIn('DOMAIN REPORT', output)
            self.assertTrue(any('DNS RECORDS' in line and 'MAIL & POLICY' in line
                                for line in output.splitlines()))
            self.assertEqual(max(map(report.cells, output.splitlines())), 124)


if __name__ == '__main__':
    unittest.main()
