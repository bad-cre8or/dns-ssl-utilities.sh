#!/usr/bin/env python3
"""Regressions for certificate identity and public-key false successes."""

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCES = '''
set -o pipefail
source "$DSU_TEST_ROOT/lib/core.sh"
source "$DSU_TEST_ROOT/lib/dns.sh"
source "$DSU_TEST_ROOT/lib/ssl.sh"
source "$DSU_TEST_ROOT/lib/site.sh"
source "$DSU_TEST_ROOT/lib/security.sh"
'''

# Only the transport is replaced. Identity decisions use real OpenSSL and certs.
TRANSPORT = '''
dsu_openssl_connection() {
  cat "$DSU_TEST_CERT"
  printf '\\nVerify return code: 0 (ok)\\n'
}
timeout() {
  local limit="$1"; shift
  if [[ "${1:-}" == openssl && "${2:-}" == s_client ]]; then
    dsu_openssl_connection
  else
    command timeout "$limit" "$@"
  fi
}
curl() { return 7; }
dig() { return 0; }
_dsu_tls_probe() { return 1; }
_dsu_dig_lines() { return 0; }
_dsu_site_registrar_probe() { printf 'OK\\tFixture Registrar\\n'; }
_dsu_site_policy_query() { printf 'OK\\n' >"$3"; }
_dsu_site_curl_probe() {
  printf 'code=200\\n' >"$3.meta"
  printf 'HTTP/1.1 200\\r\\n\\r\\n' >"$3.headers"
}
_dsu_site_extract_leaf_cert() { cp "$DSU_TEST_CERT" "$2"; }
'''


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.directory = Path(cls.tmp.name)
        cls.files = {}
        for kind, key_args in [('rsa', ['rsa:2048']),
                               ('ec', ['ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1'])]:
            key = cls.directory / f'{kind} private.key'
            cert = cls.directory / f'{kind}.crt'
            csr = cls.directory / f'{kind}.csr'
            subprocess.run([
                'openssl', 'req', '-x509', '-newkey', *key_args, '-nodes',
                '-keyout', str(key), '-out', str(cert), '-days', '2',
                '-subj', '/CN=ignored.example.test', '-addext',
                'subjectAltName=DNS:real.example.test,DNS:*.wild.example.test,IP:127.0.0.1,IP:2001:db8::1',
            ], check=True, capture_output=True)
            subprocess.run(['openssl', 'req', '-new', '-key', str(key), '-out', str(csr),
                            '-subj', '/CN=real.example.test'], check=True, capture_output=True)
            cls.files[kind] = (cert, csr, key)
        cls.invalid = []
        for name, content in [('first.txt', 'unrelated text'), ('second.txt', 'different text'),
                              ('empty.txt', ''), ('broken.pem', '-----BEGIN CERTIFICATE-----\nbroken\n')]:
            path = cls.directory / name
            path.write_text(content)
            cls.invalid.append(path)

    def run_shell(self, code, *args, extra_env=None):
        env = {**os.environ, 'DSU_TEST_ROOT': str(ROOT), 'NO_COLOR': '1',
               'DSU_FORCE_COLOR': '0', 'DSU_ASCII': '1', 'LC_ALL': 'C',
               'DSU_TEST_CERT': str(self.files['rsa'][0])}
        env.update(extra_env or {})
        return subprocess.run(['bash', '-c', SOURCES + code, '_', *map(str, args)],
                              input='', text=True, capture_output=True, env=env, timeout=20)

    def test_dns_wildcard_and_ip_identity(self):
        expectations = {
            'real.example.test': True, 'wrong.example.test': False,
            'ignored.example.test': False, 'one.wild.example.test': True,
            'two.one.wild.example.test': False, 'wild.example.test': False,
            '127.0.0.1': True, '127.0.0.2': False,
            '2001:db8::1': True, '2001:0db8:0:0:0:0:0:1': True,
            '2001:db8::2': False,
        }
        for host, matches in expectations.items():
            with self.subTest(host=host):
                result = self.run_shell('dsu_cert_matches_host "$1" "$2"', self.files['rsa'][0], host)
                self.assertEqual(result.returncode == 0, matches, result.stderr)
                self.assertEqual(result.stdout, '')
        result = self.run_shell('dsu_cert_matches_host "$1" real.example.test', self.invalid[0])
        self.assertNotEqual(result.returncode, 0)

    def test_all_identity_callers_reject_the_wrong_name(self):
        for host, matches in [('real.example.test', True), ('wrong.example.test', False)]:
            for command, positive, negative in [
                ('dsu_site_check "$1" --no-rdns', 'Certificate hostname match', 'Certificate hostname mismatch'),
                ('dsu_ssl_cert "$1"', 'Hostname matches certificate', 'Hostname does not match certificate'),
                ('dsu_ssl_fetch 192.0.2.10 "$1"', f'Certificate matches {host}', f'Certificate does not match {host}'),
                ('_dsu_audit_tls "$1" 443 0', f'Certificate identity matches {host}', f'Certificate identity does not match {host}'),
            ]:
                with self.subTest(command=command, host=host):
                    result = self.run_shell(TRANSPORT + command, host)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(positive if matches else negative, result.stdout)
                    self.assertNotIn(negative if matches else positive, result.stdout)
                    if command.startswith('_dsu_audit_tls') and not matches:
                        self.assertIn('CRITICAL', result.stdout)

    def test_zero_exit_without_positive_identity_is_not_success(self):
        code = '''
openssl() { printf '%s\\n' "$DSU_TEST_MESSAGE"; return "$DSU_TEST_EXIT"; }
dsu_cert_matches_host "$DSU_TEST_CERT" wrong.example.test
'''
        for message, rc in [('Hostname wrong.example.test does NOT match certificate', 0),
                            ('', 0), ('Unexpected OpenSSL output', 0),
                            ('Hostname other.example.test does match certificate', 0),
                            ('Hostname wrong.example.test does match certificate', 1)]:
            with self.subTest(message=message, rc=rc):
                result = self.run_shell(code, extra_env={'DSU_TEST_MESSAGE': message, 'DSU_TEST_EXIT': str(rc)})
                self.assertNotEqual(result.returncode, 0)

    def test_matching_rsa_and_ec_certificates_csrs_and_keys(self):
        for kind, files in self.files.items():
            with self.subTest(kind=kind):
                result = self.run_shell('dsu_ssl_match "$@"', *files)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('All supplied files use the same public key', result.stdout)
                der = subprocess.check_output(['openssl', 'pkey', '-in', str(files[2]), '-pubout', '-outform', 'DER'])
                self.assertIn(hashlib.sha256(der).hexdigest(), result.stdout)

    def test_invalid_missing_and_different_keys_cannot_match(self):
        for files in [self.invalid[:2], self.invalid[2:],
                      [self.files['rsa'][0], self.invalid[0]],
                      [self.files['rsa'][0], self.directory / 'missing.pem'],
                      [self.files['rsa'][2], self.files['ec'][2]]]:
            with self.subTest(files=files):
                result = self.run_shell('dsu_ssl_match "$@"', *files)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('All supplied files use the same public key', result.stdout)
                self.assertNotIn(hashlib.sha256(b'').hexdigest(), result.stdout)

    def test_extraction_conversion_and_hash_failures_are_rejected(self):
        fault = '''
openssl() {
  if [[ "$DSU_TEST_FAILURE" == extract && " $* " == *' -pubkey '* ]]; then return 1; fi
  if [[ "${1:-}" == pkey && " $* " == *' -pubin '* ]]; then
    [[ "$DSU_TEST_FAILURE" == decode ]] && return 1
    [[ "$DSU_TEST_FAILURE" == empty ]] && return 0
  fi
  if [[ "${1:-}" == dgst ]]; then
    [[ "$DSU_TEST_FAILURE" == digest ]] && return 1
    [[ "$DSU_TEST_FAILURE" == malformed ]] && { printf 'not a hash\\n'; return 0; }
  fi
  command openssl "$@"
}
dsu_ssl_match "$@"
'''
        scratch = self.directory / 'hash-temp'
        scratch.mkdir()
        for failure in ['extract', 'decode', 'empty', 'digest', 'malformed']:
            with self.subTest(failure=failure):
                result = self.run_shell(fault, self.files['rsa'][0], self.files['rsa'][2],
                                        extra_env={'DSU_TEST_FAILURE': failure, 'TMPDIR': str(scratch)})
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertNotIn('All supplied files use the same public key', result.stdout)
                self.assertEqual(list(scratch.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
