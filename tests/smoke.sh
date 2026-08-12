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
grep -q 'check.*<domain>' <<<"$help_out" || fail 'top-level help lacks primary check usage'
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

# Registrar regression: preserve the proven WHOIS sequence exactly.
# The mock timeout refuses anything except 10 seconds, so a future attempt to
# "speed up" WHOIS by shrinking the guard will fail this test immediately.
mkdir -p "$TMP/regbin"
cat >"$TMP/regbin/timeout" <<'MOCK'
#!/usr/bin/env bash
[[ "${1:-}" == 10 ]] || { echo "unexpected WHOIS timeout: ${1:-}" >&2; exit 124; }
shift
exec "$@"
MOCK
cat >"$TMP/regbin/whois" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "${1:-}" >>"${REG_WHOIS_LOG:?}"
case "${1:-}" in
  example.com)
    echo 'Registrar: Key-Systems GmbH'
    ;;
  multiline.net)
    cat <<'OUT'
Registrar:
  Example Multiline Registrar Ltd
OUT
    ;;
  example.no)
    cat <<'OUT'
Domain Name................: example.no
Registrar Handle...........: REG42-NORID
OUT
    ;;
  REG42-NORID)
    echo 'Registrar Name.............: Domeneshop AS'
    ;;
  kommune.no)
    echo 'Registrar: Kommune Registrar AS'
    ;;
esac
MOCK
chmod +x "$TMP/regbin/"*
: >"$TMP/reg-whois.log"
export REG_WHOIS_LOG="$TMP/reg-whois.log"

registrar_direct=$(PATH="$TMP/regbin:$PATH" $SUITE --no-color --ascii dns whois www.example.com)
grep -q 'Registrar.*Key-Systems GmbH' <<<"$registrar_direct" || fail 'direct Registrar field'
[[ "$(head -1 "$REG_WHOIS_LOG")" == example.com ]] || fail 'subdomain WHOIS reduction'

: >"$REG_WHOIS_LOG"
registrar_multiline=$(PATH="$TMP/regbin:$PATH" $SUITE --no-color --ascii dns whois multiline.net)
grep -q 'Registrar.*Example Multiline Registrar Ltd' <<<"$registrar_multiline" || fail 'multiline Registrar field'

: >"$REG_WHOIS_LOG"
registrar_handle=$(PATH="$TMP/regbin:$PATH" $SUITE --no-color --ascii dns whois example.no)
grep -q 'Registrar.*REG42-NORID \[Domeneshop AS\]' <<<"$registrar_handle" || fail 'Registrar Handle -> Registrar Name fallback'
grep -qx 'REG42-NORID' "$REG_WHOIS_LOG" || fail 'registrar handle WHOIS object lookup'

# kommune.no was the explicit FQDN exception in the source logic.
whois_domain=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/dns.sh"; _dsu_registrar_whois_domain "foo.oslo.kommune.no"' _ "$ROOT")
[[ "$whois_domain" == foo.oslo.kommune.no ]] || fail 'kommune.no WHOIS exception'
pass 'exact registrar WHOIS logic'

# PTR regression: resolver transport failures are errors, never successful PTRs.
mkdir -p "$TMP/ptrbin"
cat >"$TMP/ptrbin/dig" <<'MOCK'
#!/usr/bin/env bash
if [[ " $* " == *" +comments "* && " $* " == *" -x "* ]]; then
  if [[ "${PTR_MODE:-timeout}" == ok ]]; then
    cat <<'OUT'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
10.2.0.192.in-addr.arpa. 60 IN PTR ptr.example.test.
OUT
    exit 0
  fi
  echo ';; communications error to 10.255.255.254#53: timed out'
  echo ';; communications error to 10.255.255.254#53: timed out'
  exit 9
fi
# Authority lookup used only for the genuine no-PTR path.
exit 0
MOCK
chmod +x "$TMP/ptrbin/dig"
ptr_fail_out=$(PATH="$TMP/ptrbin:$PATH" $SUITE --no-color --ascii dns reverse 192.0.2.10)
grep -q '\[X\].*PTR lookup failed (resolver timed out)' <<<"$ptr_fail_out" || fail 'PTR resolver failure classification'
! grep -q '\[OK\].*communications error' <<<"$ptr_fail_out" || fail 'PTR transport error marked successful'
ptr_ok_out=$(PTR_MODE=ok PATH="$TMP/ptrbin:$PATH" $SUITE --no-color --ascii dns reverse 192.0.2.10)
grep -q '\[OK\].*192.0.2.10.*ptr.example.test' <<<"$ptr_ok_out" || fail 'valid PTR classification'
pass 'PTR success/error classification'

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
[[ -L "$TEST_HOME/bin/check" && -L "$TEST_HOME/bin/ssl" && -L "$TEST_HOME/bin/dsu" ]] || fail 'installer aliases'
alias_out=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" ssl --no-color cert --help); grep -q 'Usage: ssl cert' <<<"$alias_out" || fail 'installed ssl alias'
check_help=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" check --no-color --ascii --help); grep -q 'check.*<domain>' <<<"$check_help" || fail 'installed check help'
check_version=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" check --version); grep -q '2.2.2' <<<"$check_version" || fail 'installed check version'
check_dns=$(HOME="$TEST_HOME" PATH="$TMP/mockbin:$TEST_HOME/bin:$PATH" check --no-color --ascii dns lookup example.test); grep -q '192.0.2.10' <<<"$check_dns" || fail 'check dns routing'
pass 'installer and convenience entry points'

# Regression: documentation files are optional and must never block install.
MIN_SRC="$TMP/minimal-source"
cp -a "$ROOT" "$MIN_SRC"
rm -f "$MIN_SRC/.README"
MIN_HOME="$TMP/minimal-home"
mkdir -p "$MIN_HOME"
HOME="$MIN_HOME" DSU_INSTALL_DIR="$MIN_HOME/share/dsu" DSU_BIN_DIR="$MIN_HOME/bin" "$MIN_SRC/setup.sh" >/dev/null
[[ -x "$MIN_HOME/share/dsu/dns-ssl-utilities.sh" ]] || fail 'installer without .README'
[[ -L "$MIN_HOME/bin/check" && -L "$MIN_HOME/bin/dsu" ]] || fail 'installer aliases without .README'
pass 'installer tolerates optional docs missing'

printf '\nAll smoke tests passed.\n'
