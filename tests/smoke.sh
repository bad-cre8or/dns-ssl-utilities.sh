#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$ROOT/dns-ssl-utilities.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/dsu-smoke.XXXXXX")"
ln -s "$SUITE" "$TMP/check"
ln -s "$SUITE" "$TMP/ssl"
CHECK="$TMP/check"
SSL="$TMP/ssl"
SERVER_PID=''
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -rf "$TMP"
}
trap cleanup EXIT

pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1" >&2; exit 1; }

for file in "$ROOT"/*.sh "$ROOT"/lib/*.sh; do bash -n "$file"; done
PYTHONPYCACHEPREFIX="$TMP/pycache" python3 -m py_compile "$ROOT"/helpers/*.py
pass 'shell/python syntax'

validation_out=$(bash -c '
  source "$1/lib/core.sh"
  dsu_valid_port 1 && dsu_valid_port 65535
  ! dsu_valid_port 0 && ! dsu_valid_port 65536 && ! dsu_valid_port nope
  [[ "$(dsu_socket_target 2001:db8::1 443)" == "[2001:db8::1]:443" ]]
  [[ "$(dsu_url_authority 2001:db8::1 8443 443)" == "[2001:db8::1]:8443" ]]
' _ "$ROOT" 2>&1) || fail "target validation helpers: $validation_out"
set +e
invalid_port_out=$($SSL --no-color --ascii cert example.com 65536 2>&1)
invalid_port_rc=$?
set -e
[[ $invalid_port_rc -eq 2 && "$invalid_port_out" == *'Invalid host or port'* ]] || fail 'invalid SSL port rejection'
pass 'target and port validation'

help_out=$($CHECK --no-color --ascii --help)
target_help_out=$($CHECK example.test --no-color --ascii --help)
[[ "$target_help_out" == "$help_out" ]] || fail 'target --help differs from check --help'
grep -q 'ssl <command> \[flags\]' <<<"$help_out" || fail 'top-level help lacks ssl command usage'
grep -q '^  --audit' <<<"$help_out" || fail 'top-level help lacks audit flag'
grep -q 'check <domain-or-ip> \[flags\]' <<<"$help_out" || fail 'top-level help lacks primary check usage'
for required_flag in --dns --reverse --mail --dnssec --trace --whois --hosting --audit; do
  grep -q -- "$required_flag" <<<"$help_out" || fail "top-level help lacks $required_flag"
done
$SSL --no-color cert --help | grep -q 'Usage: ssl cert' || fail 'leaf help'
ssl_help=$($SSL --no-color --ascii --help)
grep -q 'ssl.*<command>' <<<"$ssl_help" || fail 'ssl help lacks command usage'
audit_help=$($CHECK example.test --no-color --ascii --audit --help)
grep -q 'check.*--audit' <<<"$audit_help" || fail 'audit help lacks flag-first usage'
! grep -q 'check help performance' <<<"$help_out" || fail 'top-level help still advertises performance tuning'
! grep -q 'DSU_CHECK_DNS_TIMEOUT' <<<"$help_out" || fail 'top-level help exposes internal timeout knobs'
! grep -Eq '\b(dsu|dnsutil|vulncheck|sitecheck)\b' <<<"$help_out" || fail 'top-level help advertises obsolete commands'
pass 'hierarchical help'

mkdir -p "$TMP/files"; cd "$TMP/files"
$SSL --no-color --ascii new smoke.example --san www.smoke.example --out smoke >/dev/null
set +e
overwrite_out=$($SSL --no-color --ascii new smoke.example --out smoke 2>&1)
overwrite_rc=$?
set -e
[[ $overwrite_rc -eq 2 && "$overwrite_out" == *'Refusing to overwrite'* ]] || fail 'key/CSR overwrite protection'
openssl req -in smoke.csr -x509 -key smoke.key -days 2 -out smoke.crt >/dev/null 2>&1
mail_summary=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/site.sh"; dsu_disable_color; DSU_ASCII=1; _dsu_site_print_mail_policy "v=spf1 include:_spf.example.test -all" "v=DMARC1; rua=mailto:dmarc@example.test; p=Quarantine; pct=100"' _ "$ROOT")
grep -q 'SPF contains: v=spf1 include:_spf.example.test -all' <<<"$mail_summary" || fail 'fast check SPF contents'
grep -q 'DMARC policy: quarantine' <<<"$mail_summary" || fail 'fast check DMARC policy only'
! grep -q 'rua=' <<<"$mail_summary" || fail 'fast check exposes full DMARC record'
lookup_error_summary=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/site.sh"; dsu_disable_color; DSU_ASCII=1; _dsu_site_print_mail_policy "" "" ERROR ERROR' _ "$ROOT")
grep -q 'SPF lookup failed; record presence is unknown' <<<"$lookup_error_summary" || fail 'SPF lookup failure mislabeled as missing'
grep -q 'DMARC lookup failed; record presence is unknown' <<<"$lookup_error_summary" || fail 'DMARC lookup failure mislabeled as missing'
cert_cn=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/site.sh"; _dsu_site_cert_cn "$2"' _ "$ROOT" smoke.crt)
[[ "$cert_cn" == smoke.example ]] || fail 'fast check certificate CN parsing'
cert_issuer=$(bash -c 'source "$1/lib/core.sh"; source "$1/lib/site.sh"; _dsu_site_cert_issuer "$2"' _ "$ROOT" smoke.crt)
[[ "$cert_issuer" == *'CN=smoke.example'* ]] || fail 'fast check certificate issuer parsing'
$SSL --no-color --ascii match smoke.crt smoke.csr smoke.key | grep -q 'All supplied files use the same public key' || fail 'public-key matching'
DSU_PFX_PASSWORD=testpass $SSL --no-color --ascii pack smoke.crt smoke.key '' smoke.pfx >/dev/null
printf 'testpass\n' | $SSL --no-color --ascii extract smoke.pfx extracted >/dev/null 2>&1
openssl x509 -in extracted/certificate.pem -noout >/dev/null
openssl pkey -in extracted/private-key.pem -noout >/dev/null
[[ "$(stat -c '%a' extracted)" == 700 && "$(stat -c '%a' extracted/private-key.pem)" == 600 ]] || fail 'extracted private-key permissions'
pass 'CSR/match/PFX workflows'

mkdir -p "$TMP/fallbackbin"
cat >"$TMP/fallbackbin/dig" <<'MOCK'
#!/usr/bin/env bash
[[ " $* " == *" @1.1.1.1 "* ]] || exit 9
[[ " $* " == *" _dmarc.example.test "* ]] && echo '"v=DMARC1; p=quarantine"' || echo '"v=spf1 include:_spf.example.test ~all"'
MOCK
chmod +x "$TMP/fallbackbin/dig"
fallback_result=$(PATH="$TMP/fallbackbin:$PATH" bash -c 'source "$1/lib/core.sh"; source "$1/lib/site.sh"; status="$2/status"; _dsu_site_policy_query TXT example.test "$status"; printf "STATE=%s\n" "$(cat "$status")"' _ "$ROOT" "$TMP")
grep -q 'v=spf1 include:_spf.example.test ~all' <<<"$fallback_result" || fail 'policy DNS fallback did not return SPF'
grep -q 'STATE=OK' <<<"$fallback_result" || fail 'policy DNS fallback reported failure'
pass 'policy DNS resolver fallback'

mkdir -p "$TMP/tls"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/tls/key.pem" -out "$TMP/tls/cert.pem" -days 3 \
  -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1
openssl s_server -quiet -accept 18443 -cert "$TMP/tls/cert.pem" -key "$TMP/tls/key.pem" -www >"$TMP/tls/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.4
tls_cert_out=$($SSL --no-color --ascii cert 127.0.0.1 18443); grep -q 'Hostname matches certificate' <<<"$tls_cert_out" || fail 'local TLS cert check'
tls_versions_out=$($SSL --no-color --ascii versions 127.0.0.1 18443); grep -q 'TLSv1.2 supported' <<<"$tls_versions_out" || fail 'TLS version probe'
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
dns_out=$(PATH="$TMP/mockbin:$PATH" $CHECK example.test --no-color --ascii --dns); grep -q '192.0.2.10' <<<"$dns_out" || fail 'DNS lookup mock'
mail_out=$(PATH="$TMP/mockbin:$PATH" $CHECK example.test --no-color --ascii --mail); grep -q 'DMARC policy: reject' <<<"$mail_out" || fail 'mail DNS mock'
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

registrar_direct=$(PATH="$TMP/regbin:$PATH" $CHECK www.example.com --no-color --ascii --whois)
grep -q 'Registrar.*Key-Systems GmbH' <<<"$registrar_direct" || fail 'direct Registrar field'
[[ "$(head -1 "$REG_WHOIS_LOG")" == example.com ]] || fail 'subdomain WHOIS reduction'

: >"$REG_WHOIS_LOG"
registrar_multiline=$(PATH="$TMP/regbin:$PATH" $CHECK multiline.net --no-color --ascii --whois)
grep -q 'Registrar.*Example Multiline Registrar Ltd' <<<"$registrar_multiline" || fail 'multiline Registrar field'

: >"$REG_WHOIS_LOG"
registrar_handle=$(PATH="$TMP/regbin:$PATH" $CHECK example.no --no-color --ascii --whois)
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
ptr_fail_out=$(PATH="$TMP/ptrbin:$PATH" $CHECK 192.0.2.10 --no-color --ascii --reverse)
grep -q '\[X\].*PTR lookup failed (resolver timed out)' <<<"$ptr_fail_out" || fail 'PTR resolver failure classification'
! grep -q '\[OK\].*communications error' <<<"$ptr_fail_out" || fail 'PTR transport error marked successful'
ptr_ok_out=$(PTR_MODE=ok PATH="$TMP/ptrbin:$PATH" $CHECK 192.0.2.10 --no-color --ascii --reverse)
grep -q '\[OK\].*192.0.2.10.*ptr.example.test' <<<"$ptr_ok_out" || fail 'valid PTR classification'
pass 'PTR success/error classification'

set +e
$CHECK example.test --no-color --ascii --audit --deep >"$TMP/auth.out" 2>&1
rc=$?
set -e
[[ $rc -eq 2 ]] || fail 'deep audit authorization gate exit code'
grep -q 'require --authorized' "$TMP/auth.out" || fail 'deep audit authorization gate message'
pass 'deep audit authorization gate'

TEST_HOME="$TMP/home"
mkdir -p "$TEST_HOME"
HOME="$TEST_HOME" DSU_INSTALL_DIR="$TEST_HOME/share/dsu" DSU_BIN_DIR="$TEST_HOME/bin" "$ROOT/setup.sh" >/dev/null
[[ -x "$TEST_HOME/share/dsu/dns-ssl-utilities.sh" ]] || fail 'installer copy'
[[ -L "$TEST_HOME/bin/check" && -L "$TEST_HOME/bin/ssl" ]] || fail 'installer command links'
for obsolete in dsu dnsutil vulncheck sitecheck dns-ssl-utilities; do
  ln -s "$TEST_HOME/share/dsu/dns-ssl-utilities.sh" "$TEST_HOME/bin/$obsolete"
done
HOME="$TEST_HOME" DSU_INSTALL_DIR="$TEST_HOME/share/dsu" DSU_BIN_DIR="$TEST_HOME/bin" "$ROOT/setup.sh" >/dev/null
for obsolete in dsu dnsutil vulncheck sitecheck dns-ssl-utilities; do
  [[ ! -e "$TEST_HOME/bin/$obsolete" && ! -L "$TEST_HOME/bin/$obsolete" ]] || fail "obsolete command link retained: $obsolete"
done
alias_out=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" ssl --no-color cert --help); grep -q 'Usage: ssl cert' <<<"$alias_out" || fail 'installed ssl alias'
check_help=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" check --no-color --ascii --help); grep -q 'check <domain-or-ip> \[flags\]' <<<"$check_help" || fail 'installed check help'
check_version=$(HOME="$TEST_HOME" PATH="$TEST_HOME/bin:$PATH" check --version); grep -q '2.2.2' <<<"$check_version" || fail 'installed check version'
check_dns=$(HOME="$TEST_HOME" PATH="$TMP/mockbin:$TEST_HOME/bin:$PATH" check example.test --no-color --ascii --dns); grep -q '192.0.2.10' <<<"$check_dns" || fail 'check --dns routing'
pass 'installer and public entry points'

# Regression: documentation files are optional and must never block install.
MIN_SRC="$TMP/minimal-source"
cp -a "$ROOT" "$MIN_SRC"
rm -f "$MIN_SRC/README.md"
MIN_HOME="$TMP/minimal-home"
mkdir -p "$MIN_HOME"
HOME="$MIN_HOME" DSU_INSTALL_DIR="$MIN_HOME/share/dsu" DSU_BIN_DIR="$MIN_HOME/bin" "$MIN_SRC/setup.sh" >/dev/null
[[ -x "$MIN_HOME/share/dsu/dns-ssl-utilities.sh" ]] || fail 'installer without README.md'
[[ -L "$MIN_HOME/bin/check" && -L "$MIN_HOME/bin/ssl" ]] || fail 'installer commands without README.md'
pass 'installer tolerates optional docs missing'

printf '\nAll smoke tests passed.\n'

python3 "$ROOT/tests/report.py"
python3 "$ROOT/tests/certificate.py"
