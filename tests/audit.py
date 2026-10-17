#!/usr/bin/env python3
"""Offline regressions for the project reliability audit."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SOURCES = '''
set -o pipefail
for module in core dns ssl site security; do source "$DSU_TEST_ROOT/lib/$module.sh"; done
'''


class AuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        cls.key = cls.directory / 'key.pem'
        cls.ca = cls.directory / 'ca.pem'
        cls.run_openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', cls.key, '-out', cls.ca, '-days', '2', '-subj', '/CN=Audit CA')
        csr = cls.directory / 'leaf.csr'
        cls.run_openssl('req', '-new', '-key', cls.key, '-out', csr, '-subj', '/CN=example.test')
        extensions = cls.directory / 'ext.cnf'
        extensions.write_text('subjectAltName=DNS:example.test,IP:127.0.0.1\n'
                              'crlDistributionPoints=URI:http://crl.example.test/list\n')
        for serial in ['12', '1234']:
            cls.run_openssl('x509', '-req', '-in', csr, '-CA', cls.ca, '-CAkey', cls.key,
                            '-set_serial', '0x' + serial, '-days', '2', '-extfile', extensions,
                            '-out', cls.directory / f'leaf-{serial}.pem')
        cls.cert = cls.directory / 'leaf-12.pem'
        (cls.directory / 'index').touch()
        (cls.directory / 'serial').write_text('01\n')
        config = cls.directory / 'ca.cnf'
        config.write_text(f'''[ca]
default_ca=local
[local]
database={cls.directory}/index
serial={cls.directory}/serial
new_certs_dir={cls.directory}
certificate={cls.ca}
private_key={cls.key}
default_md=sha256
default_crl_days=1
''')
        cls.run_openssl('ca', '-config', config, '-revoke', cls.directory / 'leaf-1234.pem')
        for name, dates in [('fresh', []),
                            ('stale', ['-crl_lastupdate', '20200101000000Z', '-crl_nextupdate', '20200102000000Z']),
                            ('future', ['-crl_lastupdate', '20400101000000Z', '-crl_nextupdate', '20400102000000Z'])]:
            cls.run_openssl('ca', '-config', config, '-gencrl', *dates,
                            '-out', cls.directory / f'{name}.crl')

    @classmethod
    def run_openssl(cls, *args):
        subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True, timeout=15)

    def shell(self, code, *args, input='', env=None):
        environment = {**os.environ, 'DSU_TEST_ROOT': str(ROOT), 'DSU_ASCII': '1',
                       'DSU_FORCE_COLOR': '0', 'NO_COLOR': '1', 'DSU_TEST_CERT': str(self.cert),
                       'DSU_TEST_CA': str(self.ca), 'DSU_TEST_KEY': str(self.key)}
        environment.pop('DSU_PFX_PASSWORD', None)
        environment.update(env or {})
        return subprocess.run(['bash', '-c', SOURCES + code, '_', *map(str, args)],
                              input=input, text=True, capture_output=True, env=environment, timeout=20)

    def test_target_ports(self):
        for target, host, port in [('https://[2001:db8::1]:8443/a?b', '2001:db8::1', '8443'),
                                   ('[::1]:9443?x', '::1', '9443'),
                                   ('example.test:8443#x', 'example.test', '8443'),
                                   ('2001:db8::443', '2001:db8::443', '443')]:
            with self.subTest(target=target):
                result = self.shell('dsu_target_parts "$1"', target)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), host + '\t' + port)
        for target in ['example.test:bad', '[::1]:', '[::1]:65536', 'example.test:18446744073709551617']:
            with self.subTest(target=target):
                self.assertNotEqual(self.shell('dsu_target_parts "$1"', target).returncode, 0)

    def test_expiry_rounds_negative_values_down(self):
        for delta, expected in [(-1, '-1'), (-3600, '-1'), (-86401, '-2'), (1, '0'), (86400, '1')]:
            result = self.shell('''
date() { if [[ "$1" == -d ]]; then printf '%s' "$1" >/dev/null; printf '%s' "$DSU_TEST_EXPIRY";
         else printf 2000000000; fi; }
dsu_days_until ignored
''', env={'DSU_TEST_EXPIRY': str(2000000000 + delta)})
            self.assertEqual(result.stdout, expected)

    def test_real_tls13_only_endpoint(self):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        process = subprocess.Popen(['openssl', 's_server', '-quiet', '-www', '-tls1_3',
                                    '-accept', f'127.0.0.1:{port}', '-cert', str(self.cert),
                                    '-key', str(self.key)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.05):
                        break
                except OSError:
                    time.sleep(.02)
            result = self.shell('dsu_ssl_versions 127.0.0.1 "$1"', port)
            self.assertIn('TLSv1.3 supported', result.stdout)
            self.assertIn('TLSv1.2 not negotiated', result.stdout)
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_tls_probe_rejects_unnegotiated_cipher_and_timeouts(self):
        for output, rc in [('Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384', 0),
                           ('Protocol : TLSv1.2\nCipher : (NONE)', 0),
                           ('Protocol : TLSv1.2', 1),
                           ('Protocol version: TLSv1.3\nCiphersuite: TLS_AES_256_GCM_SHA384', 124)]:
            result = self.shell('timeout() { printf "%s\\n" "$DSU_TEST_OUTPUT"; return "$DSU_TEST_RC"; }; '
                                '_dsu_tls_probe -tls1_3 example.test 443',
                                env={'DSU_TEST_OUTPUT': output, 'DSU_TEST_RC': str(rc)})
            self.assertEqual(result.returncode == 0, rc == 0 and 'TLS_AES' in output)
            if rc == 124:
                self.assertEqual(result.returncode, 2)

    def test_fingerprint_mismatch_and_invalid_input_fail(self):
        fp = subprocess.check_output(['openssl', 'x509', '-in', str(self.cert), '-noout',
                                      '-fingerprint', '-sha256'], text=True).strip().split('=')[1]
        code = 'dsu_fetch_leaf_cert() { cp "$DSU_TEST_CERT" "$3"; }; dsu_ssl_fingerprint example.test "$1"'
        for fingerprint, expected_rc in [(fp.lower(), 0), ('00' * 32, 1), ('bad', 2), (' ', 2)]:
            result = self.shell(code, fingerprint)
            self.assertEqual(result.returncode, expected_rc, result.stderr)

    def test_dns_errors_and_negative_answers_are_distinct(self):
        for status, expected in [('SERVFAIL', 1), ('REFUSED', 1), ('NOERROR', 0), ('NXDOMAIN', 0)]:
            result = self.shell('dig() { printf ";; ->>HEADER<<- opcode: QUERY, status: %s, id: 1\\n" "$DSU_TEST_STATUS"; }; '
                                '_dsu_dig_lines TXT example.test', env={'DSU_TEST_STATUS': status})
            self.assertEqual(result.returncode, expected)
            self.assertEqual(result.stdout, '')
        result = self.shell('dig() { return 9; }; dsu_dns_lookup example.test')
        self.assertEqual(result.returncode, 1)
        self.assertIn('lookup failed; record presence is unknown', result.stdout)

    def test_policy_servfail_uses_fallback_and_preserves_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('''
dig() {
  if [[ "$*" == @* ]]; then printf ';; status: NOERROR, id: 1\n"v=spf1 -all"\n';
  else printf ';; status: SERVFAIL, id: 1\n'; fi
}
_dsu_site_policy_query TXT example.test "$1/status"
cat "$1/status"
''', tmp)
            self.assertIn('v=spf1 -all', result.stdout)
            self.assertIn('OK', result.stdout)
            result = self.shell('dig() { printf ";; status: SERVFAIL, id: 1\\n"; }; '
                                '_dsu_site_policy_query TXT example.test "$1/status"; cat "$1/status"', tmp)
            self.assertEqual(result.stdout, 'ERROR\n')

    def test_dns_audit_and_mail_do_not_call_failures_missing(self):
        for command in ['dsu_dns_mail example.test selector', '_dsu_audit_dns example.test']:
            result = self.shell('dig() { printf ";; status: SERVFAIL, id: 1\\n"; }; ' + command)
            self.assertIn('unknown', result.stdout)
            for misleading in ['SPF: missing', 'DMARC: missing', 'DNSSEC is not published', 'CAA is absent']:
                self.assertNotIn(misleading, result.stdout)

    def test_mail_includes_mx_in_preference_order(self):
        result = self.shell('dig() { [[ " $* " != *" MX "* ]] || printf "20 backup.example.test.\\n10 mail.example.test.\\n"; }; '
                            'dsu_dns_mail example.test selector')
        self.assertIn('10 mail.example.test', result.stdout)
        self.assertLess(result.stdout.index('10 mail.example.test'), result.stdout.index('20 backup.example.test'))

    def test_failed_redirect_discards_partial_headers(self):
        for function in ['dsu_http_final_headers', 'dsu_http_headers']:
            result = self.shell('curl() { printf "HTTP/1.1 302 Found\\r\\nLocation: https://down.test\\r\\n\\r\\n"; return 7; }; '
                                + function + ' https://example.test')
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
        result = self.shell('curl() { printf 200; return 28; }; dsu_http_status https://example.test')
        self.assertEqual(result.stdout, '000')

    def test_failed_http_probes_are_not_clean_results(self):
        result = self.shell('curl() { return 7; }; _dsu_audit_http_behavior example.test 443; '
                            '_dsu_probe_path_result https://example.test /.env SECRET CRITICAL Secrets')
        for expected in ['TRACE request failed', 'CORS request failed', 'Cookie request failed',
                         'security.txt request failed', 'Exposure probe failed']:
            self.assertIn(expected, result.stdout)
        self.assertNotIn('No obviously permissive CORS', result.stdout)
        self.assertNotIn('TRACE not accepted', result.stdout)
        result = self.shell('curl() { printf 200; return 28; }; '
                            '_dsu_probe_path_result https://example.test /.env SECRET CRITICAL Secrets')
        self.assertIn('Exposure probe incomplete', result.stdout)

    def test_failed_inventory_is_an_incomplete_finding(self):
        result = self.shell('nmap() { return 1; }; _dsu_audit_nmap example.test 443 1')
        self.assertIn('nmap web/TLS inventory failed', result.stdout)
        self.assertIn('nmap TCP inventory failed', result.stdout)
        self.assertIn('MEDIUM', result.stdout)

    def test_crl_freshness_and_exact_serial_matching(self):
        code = '''
dsu_openssl_connection() { cat "$DSU_TEST_CERT" "$DSU_TEST_CA"; }
curl() { local prev='' arg; for arg in "$@"; do
  if [[ "$prev" == -o ]]; then cp "$DSU_TEST_CRL" "$arg"; return; fi; prev="$arg"; done; return 1; }
dsu_ssl_crl example.test
'''
        for crl, serial, rc, text in [('fresh', '12', 0, 'not found in a verified CRL'),
                                      ('fresh', '1234', 2, 'REVOKED'),
                                      ('stale', '12', 1, 'UNKNOWN'),
                                      ('future', '12', 1, 'UNKNOWN')]:
            with self.subTest(crl=crl, serial=serial):
                result = self.shell(code, env={'DSU_TEST_CRL': str(self.directory / f'{crl}.crl'),
                                               'DSU_TEST_CERT': str(self.directory / f'leaf-{serial}.pem')})
                self.assertEqual(result.returncode, rc, result.stderr + result.stdout)
                self.assertIn(text, result.stdout)

    def test_private_bundle_permissions_and_overwrite_protection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'private.pfx'
            result = self.shell('umask 000; dsu_ssl_pack "$DSU_TEST_CERT" "$DSU_TEST_KEY" "$1"',
                                path, env={'DSU_PFX_PASSWORD': 'test'})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            original = path.read_bytes()
            result = self.shell('dsu_ssl_pack "$DSU_TEST_CERT" "$DSU_TEST_KEY" "$1"', path,
                                env={'DSU_PFX_PASSWORD': 'test'})
            self.assertEqual(result.returncode, 2)
            self.assertEqual(path.read_bytes(), original)
            extraction = Path(tmp) / 'nested/extracted'
            result = self.shell('dsu_ssl_extract "$1" "$2"', path, extraction, input='test\n')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((extraction / 'private-key.pem').stat().st_mode & 0o777, 0o600)

    def test_password_eof_and_failed_csr_leave_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = self.shell('dsu_ssl_pack "$DSU_TEST_CERT" "$DSU_TEST_KEY" "$1/private.pfx"', tmp)
            self.assertEqual(result.returncode, 1)
            result = self.shell('dsu_ssl_new example.test --ec invalid_curve --out "$1/private"', tmp)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_worktree_updater_and_installed_documentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source, worktree, bare = [base / name for name in ['source', 'worktree', 'origin.git']]
            source.mkdir()
            for name in ['lib', 'helpers', 'docs']:
                shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns('__pycache__'))
            for name in ['dns-ssl-utilities.sh', 'setup.sh', 'update.sh', 'README.md']:
                shutil.copy2(ROOT / name, source / name)

            def git(*args, cwd=source):
                return subprocess.run(['git', *map(str, args)], cwd=cwd, check=True,
                                      capture_output=True, text=True, timeout=15)

            git('init', '-b', 'main')
            git('add', '.')
            git('-c', 'user.name=Test Fixture', '-c', 'user.email=fixture@example.test',
                'commit', '-m', 'Local fixture')
            git('clone', '--bare', source, bare, cwd=base)
            git('remote', 'add', 'origin', bare)
            git('fetch', 'origin')
            git('worktree', 'add', '-b', 'installed-test', worktree, 'main')
            git('branch', '--set-upstream-to=origin/main', 'installed-test')
            install, bins = base / 'installed', base / 'bin'
            result = subprocess.run([str(worktree / 'update.sh'), '--plain'], capture_output=True,
                                    text=True, timeout=15,
                                    env={**os.environ, 'DSU_INSTALL_DIR': str(install), 'DSU_BIN_DIR': str(bins)})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((bins / 'check').is_symlink())
            self.assertTrue((install / 'docs/help-preview.png').exists())
            self.assertFalse((install / '.git').exists())

    def test_ct_chooses_latest_expiry_independent_of_order(self):
        spec = importlib.util.spec_from_file_location('ct_query', ROOT / 'helpers/ct_query.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        rows = [{'name_value': 'example.test', 'not_after': '2028-01-01', 'issuer_name': 'New CA'},
                {'name_value': 'example.test', 'not_after': '2020-01-01', 'issuer_name': 'Old CA'}]
        for data in [rows, list(reversed(rows)), {'error': 'rate limited'}]:
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(sys, 'argv', ['ct_query', 'example.test']), \
                 patch.object(module, 'urlopen', return_value=io.BytesIO(json.dumps(data).encode())), \
                 patch('sys.stdout', stdout), patch('sys.stderr', stderr):
                rc = module.main()
            if isinstance(data, list):
                self.assertEqual(rc, 0)
                self.assertIn('2028-01-01', stdout.getvalue())
                self.assertNotIn('Old CA', stdout.getvalue())
            else:
                self.assertEqual(rc, 1)
                self.assertIn('expected a list', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
