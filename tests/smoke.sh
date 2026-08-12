#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$ROOT/dns-ssl-utilities.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/dsu-smoke.XXXXXX")"
SERVER_PID=''
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

for file in "$ROOT"/*.sh "$ROOT"/lib/*.sh; do bash -n "$file"; done
python3 -m py_compile "$ROOT"/helpers/*.py
pass 'shell/python syntax'

help_out=$($SUITE --no-color --ascii --help)
grep -q 'ssl cert, c' <<<"$help_out" || fail 'top-level help lacks ssl aliases'
grep -q 'audit, a' <<<"$help_out" || fail 'top-level help lacks audit'
$SUITE --no-color ssl cert --help | grep -q 'Usage: ssl cert' || fail 'leaf help'
pass 'hierarchical help'

mkdir -p "$TMP/files"; cd "$TMP/files"
$SUITE --no-color --ascii ssl new smoke.example --san www.smoke.example --out smoke >/dev/null
openssl req -in smoke.csr -x509 -key smoke.key -days 2 -out smoke.crt >/dev/null 2>&1
$SUITE --no-color --ascii ssl match smoke.crt smoke.csr smoke.key | grep -q 'All supplied files use the same public key' || fail 'public-key matching'
DSU_PFX_PASSWORD=testpass $SUITE --no-color --ascii ssl pack smoke.crt smoke.key '' smoke.pfx >/dev/null
printf 'testpass\n' | $SUITE --no-color --ascii ssl extract smoke.pfx extracted >/dev/null 2>&1
openssl x509 -in extracted/certificate.pem -noout >/dev/null
openssl pkey -in extracted/private-key.pem -noout >/dev/null
pass 'CSR/match/PFX workflows'

mkdir -p "$TMP/tls"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/tls/key.pem" -out "$TMP/tls/cert.pem" -days 3 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
openssl s_server -quiet -accept 18443 -cert "$TMP/tls/cert.pem" -key "$TMP/tls/key.pem" -www >"$TMP/tls/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.4
tls_cert_out=$($SUITE --no-color --ascii ssl cert 127.0.0.1 18443); grep -q 'Hostname matches certificate' <<<"$tls_cert_out" || fail 'local TLS cert check'
tls_versions_out=$($SUITE --no-color --ascii ssl versions 127.0.0.1 18443); grep -q 'TLSv1.2 supported' <<<"$tls_versions_out" || fail 'TLS version probe'
kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; SERVER_PID=''
pass 'live local TLS checks'

mkdir -p "$TMP/mockbin"
cat >"$TMP/mockbin/dig" <<'MOCK'
#!/usr/bin/env bash
args=" $* "
if [[ "$args" == *" +dnssec "* ]]; then echo ';; flags: qr rd ra ad; QUERY: 1, ANSWER: 1'; exit 0; fi
if [[ "$args" == *" +short "* ]]; then
  type=''; name=''
  for a in "$@"; do
    case "$a" in A|AAAA|MX|NS|TXT|CAA|SOA|DNSKEY|DS|CNAME) type="$a" ;; +*) ;; *) name="$a" ;; esac
  done
  case "$type" in
    A) echo '192.0.2.10' ;;
    MX) echo '10 mail.example.test.' ;;
    NS) echo 'ns1.example.test.' ;;
    TXT) [[ "$name" == _dmarc.* ]] && echo '"v=DMARC1; p=reject"' || echo '"v=spf1 -all"' ;;
    CAA) echo '0 issue "letsencrypt.org"' ;;
    DNSKEY) echo '257 3 13 MOCKKEY' ;;
    DS) echo '123 13 2 MOCKDS' ;;
  esac
fi
MOCK
chmod +x "$TMP/mockbin/dig"
dns_out=$(PATH="$TMP/mockbin:$PATH" $SUITE --no-color --ascii dns lookup example.test); grep -q '192.0.2.10' <<<"$dns_out" || fail 'DNS lookup mock'
mail_out=$(PATH="$TMP/mockbin:$PATH" $SUITE --no-color --ascii dns mail example.test); grep -q 'DMARC policy: reject' <<<"$mail_out" || fail 'mail DNS mock'
pass 'DNS routing/parsing'

set +e
$SUITE --no-color --ascii audit example.test --deep >"$TMP/auth.out" 2>&1
rc=$?
set -e
[[ $rc -eq 2 ]] || fail 'deep audit authorization gate exit code'
grep -q 'require --authorized' "$TMP/auth.out" || fail 'deep audit authorization gate message'
pass 'deep audit authorization gate'

TEST_HOME="$TMP/home"
mkdir -p "$TEST_HOME"
HOME="$TEST_HOME" DSU_INSTALL_DIR="$TEST_HOME/share/dsu" DSU_BIN_DIR="$TEST_HOME/bin" "$ROOT/setup.sh" >/dev/null
[[ -x "$TEST_HOME/share/dsu/dns-ssl-utilities.sh" ]] || fail 'installer copy'
[[ -L "$TEST_HOME/bin/ssl" && -L "$TEST_HOME/bin/dsu" ]] || fail 'installer aliases'
alias_out=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" ssl --no-color cert --help); grep -q 'Usage: ssl cert' <<<"$alias_out" || fail 'installed ssl alias'
pass 'installer and convenience entry points'

printf '\nAll smoke tests passed.\n'
