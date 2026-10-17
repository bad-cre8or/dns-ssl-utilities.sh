#!/usr/bin/env python3
"""CLI presentation contracts: help, exact fields, prompts and exit status."""

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
from cli_catalog import SSL, help_document
from render_report import Layout, cells
from render_ui import PREFIX, events, help_text, result_sections

ANSI = re.compile(r'\x1b\[[0-9;]*m')
SOURCES = '''
set -o pipefail
source "$1/lib/core.sh"
source "$1/lib/presentation.sh"
'''


class PresentationTests(unittest.TestCase):
    def shell(self, script, *args, input='', env=None):
        return subprocess.run(['bash', '-c', SOURCES + script, '_', str(ROOT), *map(str, args)],
                              input=input, text=True, capture_output=True, timeout=30,
                              env={**os.environ, 'DSU_FORCE_COLOR': '1', 'DSU_PLAIN': '0',
                                   'DSU_UI_CAPTURE': '0', 'COLUMNS': '124', **(env or {})})

    def test_every_help_document_fits_narrow_and_wide_terminals(self):
        topics = [('check', '')] + [('check', name) for name in
                  ['dns', 'reverse', 'mail', 'dnssec', 'trace', 'whois', 'hosting', 'audit', 'doctor']]
        topics += [('ssl', ''), ('setup', ''), ('update', '')] + [('ssl', name) for name in SSL]
        for family, topic in topics:
            for width in (24, 40, 80, 124):
                with self.subTest(family=family, topic=topic, width=width):
                    text = help_text(Layout(width, False, False), family, topic)
                    self.assertLessEqual(max(map(cells, text.splitlines())), width)
                    self.assertIn('HELP', text)
                    self.assertIn('USAGE', text)
                    self.assertNotIn(PREFIX, text)

    def test_aliases_share_the_canonical_help_document(self):
        for name, data in SSL.items():
            expected = help_document('ssl', name)
            for alias in data[2]:
                self.assertEqual(help_document('ssl', alias), expected)

    def test_cli_help_routes_without_running_any_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            for name in ['check', 'ssl']:
                (tmp / name).symlink_to(ROOT / 'dns-ssl-utilities.sh')
            for name in ['openssl', 'dig', 'curl', 'whois']:
                path = tmp / name
                path.write_text('#!/bin/sh\necho probe >>"$DSU_TEST_CALLS"\nexit 99\n')
                path.chmod(0o755)
            cases = [('check', ['--help'], 'check <domain-or-ip>'),
                     ('check', ['example.test', '--dns', '--help'], 'TYPE:'),
                     ('check', ['example.test', '--rdns', '--help'], 'PTR records'),
                     ('check', ['example.test', '--audit', '--help'], '--authorized'),
                     ('ssl', ['--help'], 'FILES & KEYS'),
                     ('ssl', ['c', '--help'], 'ssl cert <domain>'),
                     ('ssl', ['pk', '--help'], 'DSU_PFX_PASSWORD')]
            env = {**os.environ, 'PATH': str(tmp) + ':' + os.environ['PATH'],
                   'DSU_TEST_CALLS': str(tmp / 'calls'), 'DSU_FORCE_COLOR': '0'}
            for command, args, expected in cases:
                output = subprocess.run([str(tmp / command), *args, '--no-color'],
                                        text=True, capture_output=True, env=env, timeout=10)
                self.assertEqual(output.returncode, 0, output.stderr)
                self.assertIn(expected, output.stdout)
            self.assertFalse((tmp / 'calls').exists())

    def test_field_protocol_roundtrips_controls_and_recovers_plain_output(self):
        value = 'quotes " and slash \\ plus tab\tCR\r\nnext\n\x1eDSU\tlooks-like-metadata'
        body = r'''
dsu_disable_color
DSU_ASCII=1
dsu_section Sample
dsu_keyval 'Long label' "$2"
dsu_ok 'SPF: v=spf1 -all'
dsu_finding HIGH 'Original severity'
'''
        ordinary = self.shell(body, value, env={'DSU_UI_CAPTURE': '0'}).stdout
        annotated = self.shell(body, value, env={'DSU_UI_CAPTURE': '1'}).stdout
        records = list(events(annotated))
        self.assertIn(('field', 'Long label', value), records)
        self.assertIn(('finding', 'HIGH', 'Original severity'), records)
        recovered = self.shell('_dsu_ui_plain', input=annotated).stdout
        self.assertEqual(recovered, ordinary)
        rows = result_sections(annotated)[0][1]
        self.assertTrue(any(row.label == 'HIGH' and row.status == 'X' for row in rows))

    def test_command_runs_once_and_preserves_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'calls'
            script = r'''
task() { printf 'call\n' >>"$DSU_TEST_CALLS"; dsu_section Result; dsu_keyval Result exact; return "$2"; }
dsu_present 'fixture command' '--literal-target' task x "$2"
'''
            for rc in (0, 1, 2, 127):
                log.write_text('')
                output = self.shell(script, rc, env={'DSU_TEST_CALLS': str(log)})
                self.assertEqual(output.returncode, rc, output.stderr)
                self.assertEqual(log.read_text(), 'call\n')
                self.assertIn('COMMAND', output.stdout)
                self.assertIn('exact', output.stdout)
                self.assertNotIn(PREFIX, output.stdout)

    def test_renderer_failure_recovers_original_output_without_rerunning(self):
        script = r'''
_dsu_ui_run() { [[ "$1" == header ]]; }
task() { dsu_section Sample; dsu_keyval Name fixture; return 2; }
dsu_present fixture '' task
'''
        output = self.shell(script)
        self.assertEqual(output.returncode, 2)
        self.assertIn('== Sample', output.stdout)
        self.assertIn('fixture', output.stdout)
        self.assertNotIn(PREFIX, output.stdout)

    def test_help_remains_available_without_python(self):
        for command, expected in [('ssl cert', 'ssl cert'), ('setup', './setup.sh'), ('update', './update.sh')]:
            output = self.shell('dsu_has() { [[ "$1" != python3 ]]; }; dsu_help ' + command)
            self.assertEqual(output.returncode, 0)
            self.assertIn('Usage: ' + expected, output.stdout)
            self.assertIn('check --doctor', output.stdout)

    @unittest.skipUnless(shutil.which('script'), 'PTY helper is unavailable')
    def test_terminal_help_and_result_width_without_exported_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            check = Path(directory) / 'check'
            check.symlink_to(ROOT / 'dns-ssl-utilities.sh')
            for option in ['--help', '--doctor']:
                command = f'stty cols 124; unset COLUMNS; {shlex.quote(str(check))} {option} --no-color'
                env = {**os.environ, 'NO_COLOR': '1', 'DSU_FORCE_COLOR': '0', 'DSU_PLAIN': '0'}
                result = subprocess.check_output(['script', '-q', '-e', '-c', command, '/dev/null'],
                                                 text=True, env=env, timeout=20)
                self.assertNotIn('\x1b', result)
                self.assertNotIn(PREFIX, result)
                framed = [line for line in result.splitlines() if line.startswith(('╭', '│', '╰'))]
                self.assertTrue(framed)
                self.assertTrue(all(cells(line) == 124 for line in framed))

    def test_maintenance_help_has_no_install_or_update_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            git = tmp / 'git'
            git.write_text('#!/bin/sh\necho called >>"$DSU_TEST_GIT_LOG"\nexit 99\n')
            git.chmod(0o755)
            env = {**os.environ, 'PATH': str(tmp) + ':' + os.environ['PATH'],
                   'DSU_TEST_GIT_LOG': str(tmp / 'calls'), 'DSU_INSTALL_DIR': str(tmp / 'install'),
                   'DSU_BIN_DIR': str(tmp / 'bin'), 'DSU_FORCE_COLOR': '0'}
            for name in ['setup.sh', 'update.sh']:
                result = subprocess.run([str(ROOT / name), '--help', '--no-color'],
                                        env=env, text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Usage: ./' + name, result.stdout)
            self.assertFalse((tmp / 'calls').exists())
            self.assertFalse((tmp / 'install').exists())
            self.assertFalse((tmp / 'bin').exists())

    def test_native_output_is_not_reformatted(self):
        output = self.shell(r'''
source "$1/lib/ssl.sh"
dsu_ssl_dispatch() { printf '%s\n' '-----BEGIN RAW-----'; return 7; }
_dsu_present_ssl CHAIN example.test
''')
        self.assertEqual(output.returncode, 7)
        self.assertIn('-----BEGIN RAW-----\n', output.stdout)
        self.assertNotIn(PREFIX, output.stdout)

    def test_stderr_diagnostics_never_leak_metadata(self):
        output = self.shell('DSU_UI_CAPTURE=1 dsu_die failure')
        self.assertEqual(output.returncode, 1)
        self.assertIn('failure', output.stderr)
        self.assertNotIn(PREFIX, output.stderr)

    def test_audit_findings_totals_and_strict_exit_are_preserved(self):
        output = self.shell(r'''
source "$1/lib/security.sh"
dig() { return 0; }
curl() { return 0; }
_dsu_audit_dns() { dsu_section 'DNS policy'; dsu_finding HIGH 'Fixture finding'; }
_dsu_audit_tls() { :; }
_dsu_audit_headers() { :; }
_dsu_audit_http_behavior() { :; }
dsu_present 'check --audit' example.test dsu_security_audit example.test --strict --no-paths
''')
        self.assertEqual(output.returncode, 2, output.stderr)
        text = ANSI.sub('', output.stdout)
        self.assertIn('HIGH', text)
        self.assertIn('Fixture finding', text)
        self.assertIn('Audit summary', text)
        self.assertRegex(text, r'High\s+1')

    def test_native_scanner_honors_no_color(self):
        for color, expected in [('0', '--no-colour example.test:443'), ('1', 'SCANNER_ARGS=example.test:443')]:
            output = self.shell(r'''
source "$1/lib/ssl.sh"
sslscan() { printf 'SCANNER_ARGS=%s\n' "$*"; }
_dsu_color_enabled="$2"
dsu_ssl_scan example.test
''', color)
            self.assertEqual(output.returncode, 0)
            self.assertIn(expected, output.stdout)

    def test_tabular_ct_output_and_hosting_fields_are_readable(self):
        sections = result_sections(PREFIX + 'section\tCertificate Transparency\t\t2\n\n== Certificate Transparency\n'
                                   'example.test\t2028-01-01\tExample CA\n')
        row = sections[0][1][0]
        self.assertEqual((row.label, row.value), ('example.test', '2028-01-01 | Example CA'))
        sections = result_sections('Provider: Example Hosting\nConfidence: high\n')
        self.assertEqual(sections[0][1][0].label, 'Provider')

    def test_rich_pack_and_extract_preserve_password_input(self):
        with tempfile.TemporaryDirectory() as directory:
            tmp = Path(directory)
            key, cert, bundle = tmp / 'key.pem', tmp / 'cert.pem', tmp / 'bundle.pfx'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=example.test',
                            '-days', '1', '-keyout', str(key), '-out', str(cert)],
                           check=True, capture_output=True)
            script = r'''
source "$1/lib/ssl.sh"
unset DSU_PFX_PASSWORD
dsu_present 'ssl pack' fixture dsu_ssl_pack "$2" "$3" '' "$4"
'''
            packed = self.shell(script, cert, key, bundle, input='fixture-password\nfixture-password\n')
            self.assertEqual(packed.returncode, 0, packed.stderr)
            self.assertTrue(bundle.exists())
            self.assertIn('PFX password', packed.stderr)
            self.assertIn('Created', ANSI.sub('', packed.stdout))
            self.assertNotIn('fixture-password', packed.stdout + packed.stderr)
            output_dir = tmp / 'extracted'
            extracted = self.shell(r'''
source "$1/lib/ssl.sh"
dsu_present 'ssl extract' fixture dsu_ssl_extract "$2" "$3"
''', bundle, output_dir, input='fixture-password\n')
            self.assertEqual(extracted.returncode, 0, extracted.stderr)
            self.assertEqual((output_dir / 'private-key.pem').stat().st_mode & 0o777, 0o600)
            self.assertNotIn('fixture-password', extracted.stdout + extracted.stderr)


if __name__ == '__main__':
    unittest.main()
