#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SUITE="$ROOT/dns-ssl-utilities.sh"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/dsu-perf.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"

cat >"$TMP/bin/dig" <<'MOCK'
#!/usr/bin/env bash
sleep "${DSU_TEST_DELAY:-0.20}"
args=" $* "
if [[ "$args" == *" -x "* ]]; then
  [[ "$args" == *" +short "* ]] && echo 'ptr.example.test.' || echo 'example.test. 60 IN SOA ns1.example.test. hostmaster.example.test. 1 2 3 4 5'
  exit 0
fi
if [[ "$args" == *" +dnssec "* && "$args" != *" +short "* ]]; then
  echo ';; flags: qr rd ra ad; QUERY: 1, ANSWER: 1'
  exit 0
fi
if [[ "$args" == *" SOA "* && "$args" == *" +noall "* ]]; then
  echo 'example.test. 60 IN SOA ns1.example.test. hostmaster.example.test. 1 2 3 4 5'
  exit 0
fi
pos=()
for x in "$@"; do [[ "$x" == +* ]] || pos+=("$x"); done
type="${pos[0]:-}"; name="${pos[1]:-}"
case "$type:$name" in
  A:*) echo '192.0.2.10' ;;
  AAAA:*) echo '2001:db8::10' ;;
  NS:*) printf 'ns1.example.test.\nns2.example.test.\n' ;;
  MX:*) echo '10 mail.example.test.' ;;
  DNSKEY:*) echo '257 3 13 TESTKEY' ;;
  DS:*) echo '12345 13 2 TESTDS' ;;
  CAA:*) echo '0 issue "letsencrypt.org"' ;;
  TXT:_dmarc.*) echo '"v=DMARC1; p=reject"' ;;
  TXT:_mta-sts.*) echo '"v=STSv1; id=1"' ;;
  TXT:_smtp._tls.*) echo '"v=TLSRPTv1; rua=mailto:tls@example.test"' ;;
  TXT:*._domainkey.*) ;;
  TXT:*) echo '"v=spf1 -all"' ;;
  CNAME:*) ;;
esac
MOCK

cat >"$TMP/bin/whois" <<'MOCK'
#!/usr/bin/env bash
sleep "${DSU_TEST_DELAY:-0.20}"
cat <<OUT
Domain Name: EXAMPLE.TEST
Registrar: Example Registrar AS
Registry Expiry Date: 2028-01-01T00:00:00Z
OUT
MOCK

cat >"$TMP/bin/curl" <<'MOCK'
#!/usr/bin/env bash
sleep "${DSU_TEST_DELAY:-0.20}"
url=''
header_file=''
writeout=''
prev=''
for x in "$@"; do
  [[ "$x" == http://* || "$x" == https://* ]] && url="$x"
  [[ "$prev" == -D ]] && header_file="$x"
  [[ "$prev" == -w ]] && writeout="$x"
  prev="$x"
done

if [[ -n "$header_file" && "$header_file" != '-' ]]; then
  if [[ "$url" == http://* ]]; then
    printf 'HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test/\r\n\r\n' >"$header_file"
  else
    printf 'HTTP/2 200\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Security-Policy: default-src '\''self'\''\r\nServer: mock\r\n\r\n' >"$header_file"
  fi
fi

if [[ "$writeout" == *'code=%{http_code}'* ]]; then
  if [[ "$url" == http://* ]]; then
    printf 'code=301\nurl=http://example.test/\n'
  else
    cat <<'OUT'
code=200
url=https://example.test/
certs_begin
-----BEGIN CERTIFICATE-----
TEST
-----END CERTIFICATE-----
certs_end
OUT
  fi
elif [[ "$writeout" == *'%{http_code}'* ]]; then
  [[ "$url" == http://* ]] && printf 301 || printf 200
fi
MOCK

cat >"$TMP/bin/openssl" <<'MOCK'
#!/usr/bin/env bash
if [[ "${1:-}" == s_client ]]; then
  if [[ " $* " == *" -help "* ]]; then
    echo '-ssl3 -tls1 -tls1_1 -tls1_2 -tls1_3'
    exit 0
  fi
  sleep "${DSU_TEST_DELAY:-0.20}"
  cat <<OUT
-----BEGIN CERTIFICATE-----
TEST
-----END CERTIFICATE-----
Verify return code: 0 (ok)
Protocol  : TLSv1.2
Compression: NONE
OUT
  exit 0
fi
if [[ "${1:-}" == x509 ]]; then
  if [[ "$*" == *'-outform PEM'* ]]; then
    cat >/dev/null
    printf '%s\n' '-----BEGIN CERTIFICATE-----' TEST '-----END CERTIFICATE-----'
    exit 0
  fi
  [[ "$*" == *'-enddate'* ]] && { echo 'notAfter=Jan  1 00:00:00 2030 GMT'; exit 0; }
  [[ "$*" == *'-checkhost'* ]] && exit 0
  [[ "$*" == *'-text'* ]] && { echo 'Signature Algorithm: sha256WithRSAEncryption'; echo 'Public Key Algorithm: rsaEncryption'; echo 'Public-Key: (2048 bit)'; exit 0; }
fi
exec /usr/bin/openssl "$@"
MOCK
chmod +x "$TMP/bin/"*
ln -s "$SUITE" "$TMP/bin/check"

measure_ms() {
  local start end
  start=$(date +%s%N)
  "$@" >/dev/null
  end=$(date +%s%N)
  printf '%d' $(( (end - start) / 1000000 ))
}

export PATH="$TMP/bin:$PATH"
export DSU_TEST_DELAY=0.20
export XDG_CACHE_HOME="$TMP/cache"

check_ms=$(measure_ms check --no-color --ascii example.test --fresh)
lookup_ms=$(measure_ms "$SUITE" --no-color --ascii dns lookup example.test)
mail_ms=$(measure_ms "$SUITE" --no-color --ascii dns mail example.test)
reverse_ms=$(measure_ms "$SUITE" --no-color --ascii dns reverse example.test)

printf 'check:       %d ms\n' "$check_ms"
printf 'dns lookup:  %d ms\n' "$lookup_ms"
printf 'dns mail:    %d ms\n' "$mail_ms"
printf 'dns reverse: %d ms\n' "$reverse_ms"

# Thresholds are deliberately loose enough for loaded CI machines while still
# catching a regression back to fully serial network execution.
(( check_ms < 2600 )) || { echo 'FAIL: fast check exceeded cold-cache latency budget' >&2; exit 1; }
(( lookup_ms < 1800 )) || { echo 'FAIL: dns lookup path appears serialized' >&2; exit 1; }
(( mail_ms < 2800 )) || { echo 'FAIL: dns mail path appears serialized' >&2; exit 1; }
(( reverse_ms < 1800 )) || { echo 'FAIL: dns reverse path appears serialized' >&2; exit 1; }


# The everyday check is payload-first: no product banner, no target echo, no tip.
export DSU_TEST_DELAY=0
check_out=$(check --no-color --ascii example.test --fresh)
! grep -q '^DNS + SSL Utilities$' <<<"$check_out" || { echo 'FAIL: check printed suite banner' >&2; exit 1; }
! grep -q '^Target:' <<<"$check_out" || { echo 'FAIL: check echoed target' >&2; exit 1; }
! grep -qi '^Tip:' <<<"$check_out" || { echo 'FAIL: check printed promotional tip' >&2; exit 1; }
first_payload=$(printf '%s\n' "$check_out" | awk 'NF {print; exit}')
[[ "$first_payload" == *'REGISTRAR'* ]] || { echo 'FAIL: registrar is not the first check section' >&2; exit 1; }
grep -q 'Example Registrar' <<<"$check_out" || { echo 'FAIL: registrar missing from check' >&2; exit 1; }
grep -q 'Certificate hostname match' <<<"$check_out" || { echo 'FAIL: TLS certificate data missing from reused HTTPS probe' >&2; exit 1; }

printf 'presentation: clean\n'
printf '\nPerformance regression checks passed.\n'
