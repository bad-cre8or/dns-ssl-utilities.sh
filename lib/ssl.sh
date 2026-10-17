#!/usr/bin/env bash

_dsu_ssl_usage() { dsu_help ssl; }

_dsu_ssl_leaf_help() { dsu_help ssl "${1:-}"; }

_dsu_ssl_target() {
  dsu_target_parts "${1:-}" "${2:-}" 443
}

dsu_ssl_cert() {
  local input="${1:-}" explicit_port="${2:-}" host port tmp conn verify subject issuer start end serial fp sig pub san days
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl cert <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "$explicit_port" 443) || { dsu_bad "Invalid host or port: ${input}${explicit_port:+ $explicit_port}"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  trap 'dsu_cleanup_dir "$tmp"' RETURN
  conn=$(dsu_openssl_connection "$host" "$port")
  printf '%s\n' "$conn" | openssl x509 -outform PEM >"$tmp/leaf.pem" 2>/dev/null || true
  [[ -s "$tmp/leaf.pem" ]] || { dsu_bad "Could not retrieve a certificate from $host:$port"; return 1; }

  dsu_section "TLS certificate · $host:$port"
  verify=$(printf '%s\n' "$conn" | sed -n 's/^Verify return code: //p' | tail -1)
  subject=$(openssl x509 -in "$tmp/leaf.pem" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/^subject=//')
  issuer=$(openssl x509 -in "$tmp/leaf.pem" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')
  start=$(openssl x509 -in "$tmp/leaf.pem" -noout -startdate 2>/dev/null | cut -d= -f2-)
  end=$(openssl x509 -in "$tmp/leaf.pem" -noout -enddate 2>/dev/null | cut -d= -f2-)
  serial=$(openssl x509 -in "$tmp/leaf.pem" -noout -serial 2>/dev/null | cut -d= -f2-)
  fp=$(openssl x509 -in "$tmp/leaf.pem" -noout -sha256 -fingerprint 2>/dev/null | cut -d= -f2-)
  sig=$(openssl x509 -in "$tmp/leaf.pem" -noout -text 2>/dev/null | awk -F': ' '/Signature Algorithm:/ {print $2; exit}')
  pub=$(openssl x509 -in "$tmp/leaf.pem" -noout -text 2>/dev/null | awk '/Public-Key:|ASN1 OID:/ {gsub(/^[[:space:]]+/,""); print; if (++n==2) exit}' | paste -sd '; ' -)
  san=$(openssl x509 -in "$tmp/leaf.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//')

  dsu_keyval "Subject" "$subject"
  dsu_keyval "Issuer" "$issuer"
  dsu_keyval "Not before" "$start"
  dsu_keyval "Not after" "$end"
  [[ -n "$serial" ]] && dsu_keyval "Serial" "$serial"
  [[ -n "$sig" ]] && dsu_keyval "Signature" "$sig"
  [[ -n "$pub" ]] && dsu_keyval "Public key" "$pub"
  [[ -n "$fp" ]] && dsu_keyval "SHA-256" "$fp"
  [[ -n "$san" ]] && dsu_keyval "SANs" "$san"

  if [[ "$verify" == 0*'(ok)'* || "$verify" == 0* ]]; then dsu_ok "CA chain verification: $verify"; else dsu_warn "CA chain verification: ${verify:-unknown}"; fi
  if dsu_cert_matches_host "$tmp/leaf.pem" "$host"; then dsu_ok "Hostname matches certificate"; else dsu_bad "Hostname does not match certificate"; fi
  if days=$(dsu_days_until "$end" 2>/dev/null); then
    if (( days < 0 )); then dsu_bad "Certificate expired $((-days)) days ago"; elif (( days < 14 )); then dsu_bad "Certificate expires in $days days"; elif (( days < 30 )); then dsu_warn "Certificate expires in $days days"; else dsu_ok "Certificate valid for $days more days"; fi
  fi
  trap - RETURN
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_quick() {
  local input="${1:-}" port host tmp end days issuer
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl quick <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  if ! dsu_fetch_leaf_cert "$host" "$port" "$tmp/cert.pem"; then dsu_cleanup_dir "$tmp"; dsu_bad "$host:$port · no certificate retrieved"; return 1; fi
  end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate | cut -d= -f2-)
  issuer=$(openssl x509 -in "$tmp/cert.pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//' | sed -n 's/.*CN=\([^,]*\).*/\1/p')
  days=$(dsu_days_until "$end" 2>/dev/null || printf '?')
  if [[ "$days" =~ ^-?[0-9]+$ ]] && (( days < 0 )); then dsu_bad "$host:$port · EXPIRED · $end · ${issuer:-issuer unknown}"; elif [[ "$days" =~ ^[0-9]+$ ]] && (( days < 30 )); then dsu_warn "$host:$port · $days days left · $end · ${issuer:-issuer unknown}"; else dsu_ok "$host:$port · ${days} days left · $end · ${issuer:-issuer unknown}"; fi
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_chain() {
  local input="${1:-}" port host target
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl chain <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  target=$(dsu_socket_target "$host" "$port")
  dsu_section "Certificate chain · $host:$port"
  timeout "$DSU_MAX_TIME" openssl s_client -servername "$host" -connect "$target" -showcerts </dev/null 2>&1
}

dsu_ssl_fetch() {
  local ip="${1:-}" domain="${2:-}" port="${3:-443}" tmp conn verify end target authority resolve_ip
  [[ -n "$ip" && -n "$domain" ]] || { dsu_bad "Usage: ssl fetch <server-ip> <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  dsu_need curl curl || return
  domain=$(dsu_normalize_host "$domain")
  dsu_is_ip "$ip" || { dsu_bad "Invalid server IP: $ip"; return 2; }
  dsu_valid_host "$domain" || { dsu_bad "Invalid domain: $domain"; return 2; }
  dsu_valid_port "$port" || { dsu_bad "Invalid port: $port"; return 2; }
  target=$(dsu_socket_target "$ip" "$port")
  tmp=$(dsu_tmpdir) || return 1
  conn=$(timeout "$DSU_MAX_TIME" openssl s_client -servername "$domain" -connect "$target" -showcerts </dev/null 2>&1)
  printf '%s\n' "$conn" | openssl x509 -outform PEM >"$tmp/leaf.pem" 2>/dev/null || true
  dsu_section "SNI endpoint · $domain → $ip:$port"
  if [[ ! -s "$tmp/leaf.pem" ]]; then dsu_bad "No certificate retrieved"; dsu_cleanup_dir "$tmp"; return 1; fi
  verify=$(printf '%s\n' "$conn" | sed -n 's/^Verify return code: //p' | tail -1)
  end=$(openssl x509 -in "$tmp/leaf.pem" -noout -enddate | cut -d= -f2-)
  dsu_keyval "Expires" "$end"
  dsu_keyval "OpenSSL verify" "${verify:-unknown}"
  if dsu_cert_matches_host "$tmp/leaf.pem" "$domain"; then dsu_ok "Certificate matches $domain"; else dsu_bad "Certificate does not match $domain"; fi
  authority=$(dsu_url_authority "$domain" "$port" 443)
  resolve_ip="$ip"; [[ "$ip" == *:* ]] && resolve_ip="[$ip]"
  if curl -fsSI --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" --resolve "$domain:$port:$resolve_ip" "https://$authority/" >/dev/null 2>&1; then dsu_ok "curl CA + hostname validation passed against $ip"; else dsu_warn "curl validation/request failed against $ip"; fi
  dsu_cleanup_dir "$tmp"
}

_dsu_tls_probe() {
  local flag="$1" host="$2" port="$3" target
  target=$(dsu_socket_target "$host" "$port")
  timeout "$DSU_MAX_TIME" openssl s_client "$flag" -servername "$host" -connect "$target" </dev/null 2>&1 | grep -qE '^Protocol *:|^ *Protocol *:'
}

dsu_ssl_versions() {
  local input="${1:-}" port host flag label
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl versions <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  dsu_section "TLS versions · $host:$port"
  while IFS=$'\t' read -r flag label; do
    if openssl s_client -help 2>&1 | grep -q -- "$flag"; then
      if _dsu_tls_probe "$flag" "$host" "$port"; then
        case "$flag" in -tls1|-tls1_1|-ssl3) dsu_warn "$label supported (legacy)" ;; *) dsu_ok "$label supported" ;; esac
      else
        dsu_info "$label not supported"
      fi
    else
      dsu_dim "$label probe unavailable in this OpenSSL build"
    fi
  done <<'VERSIONS'
-ssl3	SSLv3
-tls1	TLSv1.0
-tls1_1	TLSv1.1
-tls1_2	TLSv1.2
-tls1_3	TLSv1.3
VERSIONS
}

dsu_ssl_ciphers() {
  local input="${1:-}" port host target
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl ciphers <domain> [port]"; return 2; }
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  target=$(dsu_socket_target "$host" "$port")
  dsu_section "Cipher enumeration · $host:$port"
  if dsu_has sslscan; then
    sslscan --no-colour "$target"
  elif dsu_has nmap; then
    nmap -Pn -p "$port" --script ssl-enum-ciphers "$host"
  else
    dsu_bad "Install sslscan (preferred) or nmap for cipher enumeration"
    return 127
  fi
}

dsu_ssl_scan() {
  local input="${1:-}" port host target
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl scan <domain> [port]"; return 2; }
  dsu_need sslscan sslscan || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  target=$(dsu_socket_target "$host" "$port")
  if [[ "${_dsu_color_enabled:-0}" == 1 ]]; then sslscan "$target"; else sslscan --no-colour "$target"; fi
}

_dsu_extract_chain_files() {
  local conn="$1" dir="$2"
  printf '%s\n' "$conn" | awk -v dir="$dir" '
    /-----BEGIN CERTIFICATE-----/ {n++; f=sprintf("%s/cert-%02d.pem", dir, n); in_cert=1}
    in_cert {print > f}
    /-----END CERTIFICATE-----/ {close(f); in_cert=0}
  '
}

dsu_ssl_ocsp() {
  local input="${1:-}" port host tmp conn uri issuer output rc
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl ocsp <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  conn=$(dsu_openssl_connection "$host" "$port")
  _dsu_extract_chain_files "$conn" "$tmp"
  [[ -s "$tmp/cert-01.pem" ]] || { dsu_bad "Could not retrieve leaf certificate"; dsu_cleanup_dir "$tmp"; return 1; }
  uri=$(openssl x509 -in "$tmp/cert-01.pem" -noout -ocsp_uri 2>/dev/null)
  dsu_section "OCSP · $host:$port"
  [[ -n "$uri" ]] || { dsu_warn "Leaf certificate has no OCSP responder URI"; dsu_cleanup_dir "$tmp"; return 1; }
  dsu_keyval "Responder" "$uri"
  issuer="$tmp/cert-02.pem"
  if [[ ! -s "$issuer" ]]; then dsu_warn "Server did not send an issuer certificate; cannot construct direct OCSP request"; dsu_cleanup_dir "$tmp"; return 1; fi
  output=$(timeout "$DSU_MAX_TIME" openssl ocsp -no_nonce -timeout "$DSU_CONNECT_TIMEOUT" \
    -issuer "$issuer" -cert "$tmp/cert-01.pem" -url "$uri" -verify_other "$issuer" 2>&1)
  rc=$?
  printf '%s\n' "$output" | sed 's/^/  /'
  if (( rc == 124 )); then dsu_bad "OCSP responder timed out"; dsu_cleanup_dir "$tmp"; return 1
  elif (( rc != 0 )); then dsu_bad "OCSP status is unknown because the response could not be verified"; dsu_cleanup_dir "$tmp"; return 1
  elif printf '%s\n' "$output" | grep -qiE ': revoked([[:space:]]|$)'; then dsu_bad "Certificate is REVOKED"; dsu_cleanup_dir "$tmp"; return 2
  elif printf '%s\n' "$output" | grep -qiE ': good([[:space:]]|$)'; then dsu_ok "Certificate status is GOOD (verified OCSP response)"
  else dsu_warn "OCSP response was verified but did not contain a recognized certificate status"; dsu_cleanup_dir "$tmp"; return 1
  fi
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_crl() {
  local input="${1:-}" port host tmp uri serial format conn issuer leaf_issuer crl_issuer
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl crl <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  dsu_need curl curl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  conn=$(dsu_openssl_connection "$host" "$port")
  _dsu_extract_chain_files "$conn" "$tmp"
  [[ -s "$tmp/cert-01.pem" ]] || { dsu_bad "Could not retrieve certificate"; dsu_cleanup_dir "$tmp"; return 1; }
  cp -- "$tmp/cert-01.pem" "$tmp/leaf.pem"
  issuer="$tmp/cert-02.pem"
  uri=$(openssl x509 -in "$tmp/leaf.pem" -noout -text | awk '/CRL Distribution Points:/{incrl=1; next} incrl && /URI:/{sub(/.*URI:/,""); print; exit} incrl && /^[^ ]/{exit}')
  dsu_section "CRL · $host:$port"
  [[ -n "$uri" ]] || { dsu_info "No CRL Distribution Point advertised"; dsu_cleanup_dir "$tmp"; return 1; }
  dsu_keyval "Distribution point" "$uri"
  if ! curl -fsSL --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time 20 -A "$DSU_USER_AGENT" "$uri" -o "$tmp/crl"; then dsu_bad "Could not download CRL"; dsu_cleanup_dir "$tmp"; return 1; fi
  if openssl crl -in "$tmp/crl" -inform PEM -noout >/dev/null 2>&1; then format=PEM
  elif openssl crl -in "$tmp/crl" -inform DER -noout >/dev/null 2>&1; then format=DER
  else dsu_bad "Downloaded CRL is malformed or unsupported; revocation status is UNKNOWN"; dsu_cleanup_dir "$tmp"; return 1
  fi
  [[ -s "$issuer" ]] || { dsu_bad "Server did not provide the issuer certificate; CRL status is UNKNOWN"; dsu_cleanup_dir "$tmp"; return 1; }
  leaf_issuer=$(openssl x509 -in "$tmp/leaf.pem" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')
  crl_issuer=$(openssl crl -in "$tmp/crl" -inform "$format" -noout -issuer -nameopt RFC2253 2>/dev/null | sed 's/^issuer=//')
  [[ -n "$leaf_issuer" && "$leaf_issuer" == "$crl_issuer" ]] || { dsu_bad "CRL issuer does not match the certificate issuer; status is UNKNOWN"; dsu_cleanup_dir "$tmp"; return 1; }
  if ! openssl crl -in "$tmp/crl" -inform "$format" -noout -verify -CAfile "$issuer" >/dev/null 2>&1; then
    dsu_bad "CRL signature verification failed; revocation status is UNKNOWN"
    dsu_cleanup_dir "$tmp"
    return 1
  fi
  serial=$(openssl x509 -in "$tmp/leaf.pem" -noout -serial | cut -d= -f2 | tr -d ':')
  if openssl crl -in "$tmp/crl" -inform "$format" -noout -text 2>/dev/null | tr -d ':' | grep -qi "Serial Number *$serial"; then
    dsu_bad "Certificate serial is listed as REVOKED"
    dsu_cleanup_dir "$tmp"
    return 2
  else
    dsu_ok "Certificate serial not found in a verified CRL"
  fi
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_ct() {
  local input="${1:-}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl ct <domain>"; return 2; }
  dsu_need python3 python3 || return
  host=$(dsu_normalize_host "$input")
  dsu_section "Certificate Transparency · $host"
  python3 "$DSU_HOME/helpers/ct_query.py" "$host"
}

dsu_ssl_headers() {
  local input="${1:-}" host headers h value
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl headers <domain-or-url>"; return 2; }
  dsu_need curl curl || return
  host=$(dsu_normalize_url "$input")
  headers=$(dsu_http_final_headers "$host")
  [[ -n "$headers" ]] || { dsu_bad "Could not fetch headers"; return 1; }
  dsu_section "HTTPS security headers · $host"
  for h in strict-transport-security content-security-policy x-frame-options x-content-type-options referrer-policy permissions-policy cross-origin-opener-policy cross-origin-resource-policy; do
    value=$(dsu_header_value "$headers" "$h")
    [[ -n "$value" ]] && dsu_ok "$h: $value" || dsu_warn "$h: missing"
  done
  for h in server x-powered-by; do
    value=$(dsu_header_value "$headers" "$h")
    [[ -n "$value" ]] && dsu_warn "$h exposed: $value" || dsu_ok "$h not exposed"
  done
}

dsu_ssl_performance() {
  local input="${1:-}" port seconds="${3:-5}" host target
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl performance <domain> [port] [seconds]"; return 2; }
  dsu_need openssl openssl || return
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${2:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  [[ "$seconds" =~ ^[1-9][0-9]*$ && "$seconds" -le 300 ]] || { dsu_bad "Seconds must be between 1 and 300"; return 2; }
  target=$(dsu_socket_target "$host" "$port")
  dsu_section "TLS handshake benchmark · $host:$port"
  openssl s_time -connect "$target" -new -www / -time "$seconds"
}

dsu_ssl_fingerprint() {
  local input="${1:-}" expected="${2:-}" port host tmp fp norm_expected norm_actual
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl fingerprint <domain> [expected-sha256] [port]"; return 2; }
  IFS=$'\t' read -r host port < <(dsu_target_parts "$input" "${3:-}" 443) || { dsu_bad "Invalid host or port"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  if ! dsu_fetch_leaf_cert "$host" "$port" "$tmp/cert.pem"; then dsu_bad "Could not retrieve certificate"; dsu_cleanup_dir "$tmp"; return 1; fi
  fp=$(openssl x509 -in "$tmp/cert.pem" -noout -sha256 -fingerprint | cut -d= -f2-)
  dsu_section "Certificate fingerprint · $host:$port"
  dsu_keyval "SHA-256" "$fp"
  if [[ -n "$expected" ]]; then
    norm_expected=$(printf '%s' "$expected" | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')
    norm_actual=$(printf '%s' "$fp" | tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]')
    [[ "$norm_actual" == "$norm_expected" ]] && dsu_ok "Fingerprint matches expected value" || dsu_bad "Fingerprint does not match expected value"
  fi
  dsu_cleanup_dir "$tmp"
}

_dsu_file_kind() {
  local file="$1"
  if openssl x509 -in "$file" -noout >/dev/null 2>&1; then echo cert
  elif openssl req -in "$file" -noout >/dev/null 2>&1; then echo csr
  elif openssl pkey -in "$file" -noout >/dev/null 2>&1; then echo key
  else echo unknown; fi
}

dsu_ssl_decode() {
  local file="${1:-}" kind
  [[ -f "$file" ]] || { dsu_bad "Usage: ssl decode <certificate|csr|key-file>"; return 2; }
  dsu_need openssl openssl || return
  kind=$(_dsu_file_kind "$file")
  dsu_section "Decode · $file ($kind)"
  case "$kind" in
    cert) openssl x509 -in "$file" -noout -subject -issuer -serial -startdate -enddate -fingerprint -sha256; printf '\n'; openssl x509 -in "$file" -noout -ext subjectAltName 2>/dev/null || true ;;
    csr) openssl req -in "$file" -noout -subject -verify; printf '\n'; openssl req -in "$file" -noout -text | awk '/Requested Extensions:/{p=1} p{print}' ;;
    key) openssl pkey -in "$file" -noout -text_pub ;;
    *) dsu_bad "File is not a PEM certificate, CSR, or readable private key"; return 1 ;;
  esac
}

_dsu_public_key_hash() (
  # DER is binary, so use temporary files rather than shell variables.
  # The subshell confines cleanup traps to this one extraction attempt.
  local file="$1" kind="${2:-}" tmp digest
  [[ -n "$kind" ]] || kind=$(_dsu_file_kind "$file")
  case "$kind" in cert|csr|key) ;; *) return 1 ;; esac
  tmp=$(dsu_tmpdir) || return 1
  trap 'dsu_cleanup_dir "$tmp"' EXIT
  case "$kind" in
    cert) openssl x509 -in "$file" -pubkey -noout >"$tmp/public.pem" 2>/dev/null || return 1 ;;
    csr) openssl req -in "$file" -pubkey -noout >"$tmp/public.pem" 2>/dev/null || return 1 ;;
    key) openssl pkey -in "$file" -pubout >"$tmp/public.pem" 2>/dev/null || return 1 ;;
  esac
  openssl pkey -pubin -in "$tmp/public.pem" -outform DER -out "$tmp/public.der" 2>/dev/null || return 1
  [[ -s "$tmp/public.der" ]] || return 1
  digest=$(openssl dgst -sha256 <"$tmp/public.der" 2>/dev/null) || return 1
  digest="${digest##* }"
  [[ "$digest" =~ ^[[:xdigit:]]{64}$ ]] || return 1
  printf '%s\n' "$digest"
)

dsu_ssl_match() {
  (( $# >= 2 )) || { dsu_bad "Usage: ssl match <cert|csr|key> <cert|csr|key> [more files...]"; return 2; }
  dsu_need openssl openssl || return
  local first_hash='' file hash kind mismatch=0
  dsu_section "Public-key match"
  for file in "$@"; do
    [[ -f "$file" ]] || { dsu_bad "File not found: $file"; mismatch=1; continue; }
    kind=$(_dsu_file_kind "$file")
    if ! hash=$(_dsu_public_key_hash "$file" "$kind"); then
      dsu_bad "$file: unreadable/unsupported"; mismatch=1; continue
    fi
    dsu_keyval "$kind" "$file · $hash"
    [[ -z "$first_hash" ]] && first_hash="$hash"
    [[ "$hash" == "$first_hash" ]] || mismatch=1
  done
  if (( mismatch )); then dsu_bad "Public keys do not all match"; return 1; else dsu_ok "All supplied files use the same public key"; fi
}

dsu_ssl_new() {
  local cn="${1:-}"; shift || true
  [[ -n "$cn" && "$cn" != --* ]] || { dsu_bad "Usage: ssl new <common-name> [--san NAME] [--out PREFIX] [--rsa BITS|--ec CURVE] [--encrypted]"; return 2; }
  dsu_need openssl openssl || return
  local prefix="$cn" key_type=rsa bits=2048 curve=prime256v1 encrypted=0 arg
  local sans=("$cn")
  while (( $# )); do
    arg="$1"; shift
    case "$arg" in
      --san) [[ $# -gt 0 ]] || { dsu_bad "--san requires a value"; return 2; }; sans+=("$1"); shift ;;
      --out) [[ $# -gt 0 ]] || { dsu_bad "--out requires a prefix"; return 2; }; prefix="$1"; shift ;;
      --rsa) key_type=rsa; [[ $# -gt 0 ]] && [[ "$1" =~ ^[0-9]+$ ]] && { bits="$1"; shift; } ;;
      --ec) key_type=ec; [[ $# -gt 0 ]] && { curve="$1"; shift; } ;;
      --encrypted) encrypted=1 ;;
      --help|-h) dsu_info "Usage: ssl new <CN> [--san NAME] [--out PREFIX] [--rsa BITS|--ec CURVE] [--encrypted]"; return 0 ;;
      *) dsu_bad "Unknown option: $arg"; return 2 ;;
    esac
  done
  local key="${prefix}.key" csr="${prefix}.csr" san_csv='' name
  dsu_valid_host "$cn" || { dsu_bad "Invalid common name: $cn"; return 2; }
  [[ "$bits" =~ ^[0-9]+$ && "$bits" -ge 2048 && "$bits" -le 16384 ]] || { dsu_bad "RSA bits must be between 2048 and 16384"; return 2; }
  [[ "$curve" =~ ^[A-Za-z0-9._-]+$ ]] || { dsu_bad "Invalid EC curve name"; return 2; }
  [[ ! -e "$key" && ! -L "$key" && ! -e "$csr" && ! -L "$csr" ]] || { dsu_bad "Refusing to overwrite existing key or CSR (choose another --out prefix)"; return 2; }
  for name in "${sans[@]}"; do
    dsu_valid_host "$name" || { dsu_bad "Invalid SAN: $name"; return 2; }
    [[ -n "$san_csv" ]] && san_csv+=","
    if dsu_is_ip "$name"; then san_csv+="IP:$name"; else san_csv+="DNS:$name"; fi
  done
  dsu_section "Create CSR · $cn"
  if [[ "$key_type" == rsa ]]; then
    if (( encrypted )); then openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -aes-256-cbc -out "$key" || return 1
    else openssl genpkey -quiet -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" -out "$key" || return 1; fi
  else
    if (( encrypted )); then openssl genpkey -quiet -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" -aes-256-cbc -out "$key" || return 1
    else openssl genpkey -quiet -algorithm EC -pkeyopt "ec_paramgen_curve:$curve" -out "$key" || return 1; fi
  fi
  if openssl req -help 2>&1 | grep -q -- '-addext'; then
    openssl req -new -key "$key" -out "$csr" -subj "/CN=$cn" -addext "subjectAltName=$san_csv" || return 1
  else
    local tmpcfg; tmpcfg=$(mktemp)
    cat >"$tmpcfg" <<CFG
[req]
distinguished_name=dn
req_extensions=req_ext
prompt=no
[dn]
CN=$cn
[req_ext]
subjectAltName=$san_csv
CFG
    openssl req -new -key "$key" -out "$csr" -config "$tmpcfg" || { rm -f "$tmpcfg"; return 1; }
    rm -f "$tmpcfg"
  fi
  chmod 600 "$key"
  dsu_ok "Private key: $key"
  dsu_ok "CSR: $csr"
  dsu_keyval "SANs" "$san_csv"
  openssl req -in "$csr" -noout -verify >/dev/null 2>&1 && dsu_ok "CSR signature verifies"
}

dsu_ssl_pack() {
  local cert="${1:-}" key="${2:-}" chain="${3:-}" out="${4:-certificate.pfx}"
  [[ -f "$cert" && -f "$key" ]] || { dsu_bad "Usage: ssl pack <certificate.pem> <private.key> [chain.pem] [output.pfx]"; return 2; }
  dsu_need openssl openssl || return
  if [[ -n "$chain" && ! -f "$chain" ]]; then
    if [[ "$chain" == *.pfx || "$chain" == *.p12 ]]; then out="$chain"; chain=""; else dsu_bad "Chain file not found: $chain"; return 2; fi
  fi
  [[ ! -e "$out" && ! -L "$out" ]] || { dsu_bad "Refusing to overwrite existing bundle: $out"; return 2; }
  local password="${DSU_PFX_PASSWORD:-}" confirm=""
  if [[ -z "${DSU_PFX_PASSWORD+x}" ]]; then
    printf '%s' "PFX password (blank allowed): " >&2
    IFS= read -rs password; printf '\n' >&2
    printf '%s' "Confirm PFX password: " >&2
    IFS= read -rs confirm; printf '\n' >&2
    [[ "$password" == "$confirm" ]] || { dsu_bad "Passwords do not match"; return 2; }
  fi
  export DSU_PFX_PASS="$password"
  local args=(pkcs12 -export -out "$out" -inkey "$key" -in "$cert" -passout env:DSU_PFX_PASS)
  [[ -n "$chain" ]] && args+=(-certfile "$chain")
  dsu_section "Create PKCS#12 · $out"
  if openssl "${args[@]}"; then
    dsu_ok "Created $out"
    unset DSU_PFX_PASS password confirm
  else
    unset DSU_PFX_PASS password confirm
    dsu_bad "PFX creation failed"
    return 1
  fi
}

dsu_ssl_extract() {
  local pfx="${1:-}" outdir="${2:-}"
  [[ -f "$pfx" ]] || { dsu_bad "Usage: ssl extract <bundle.pfx> [output-directory]"; return 2; }
  dsu_need openssl openssl || return
  if [[ -z "$outdir" ]]; then outdir="${pfx##*/}"; outdir="${outdir%.*}-extracted"; fi
  [[ ! -e "$outdir" && ! -L "$outdir" ]] || { dsu_bad "Refusing to overwrite existing extraction directory: $outdir"; return 2; }
  mkdir -p "$outdir" || return 1
  chmod 700 "$outdir" || { dsu_cleanup_dir "$outdir"; return 1; }
  local password
  printf '%s' "PFX password (blank if none): " >&2
  IFS= read -rs password; printf '\n' >&2
  export DSU_PFX_PASS="$password"
  dsu_section "Extract PKCS#12 · $pfx"
  : >"$outdir/private-key.pem"; chmod 600 "$outdir/private-key.pem"
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -clcerts -nokeys -out "$outdir/certificate.pem" || { unset DSU_PFX_PASS; dsu_cleanup_dir "$outdir"; return 1; }
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -cacerts -nokeys -out "$outdir/ca-chain.pem" || true
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -nocerts -nodes -out "$outdir/private-key.pem" || { unset DSU_PFX_PASS; dsu_cleanup_dir "$outdir"; return 1; }
  unset DSU_PFX_PASS password
  chmod 600 "$outdir/private-key.pem"
  [[ -s "$outdir/ca-chain.pem" ]] || rm -f "$outdir/ca-chain.pem"
  dsu_ok "Certificate: $outdir/certificate.pem"
  [[ -f "$outdir/ca-chain.pem" ]] && dsu_ok "CA chain: $outdir/ca-chain.pem"
  dsu_warn "Private key extracted unencrypted: $outdir/private-key.pem (mode 600)"
}

dsu_ssl_dispatch() {
  local cmd="${1:-help}"; shift || true
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then _dsu_ssl_leaf_help "$cmd"; return 0; fi
  case "${cmd,,}" in
    help|--help|-h) _dsu_ssl_usage ;;
    cert|certificate|c) dsu_ssl_cert "$@" ;;
    quick|q) dsu_ssl_quick "$@" ;;
    chain|ch) dsu_ssl_chain "$@" ;;
    fetch|f) dsu_ssl_fetch "$@" ;;
    versions|version|v) dsu_ssl_versions "$@" ;;
    ciphers|cipher|ci) dsu_ssl_ciphers "$@" ;;
    scan|s) dsu_ssl_scan "$@" ;;
    ocsp|o) dsu_ssl_ocsp "$@" ;;
    crl) dsu_ssl_crl "$@" ;;
    ct|ctlogs|transparency) dsu_ssl_ct "$@" ;;
    headers|header|h) dsu_ssl_headers "$@" ;;
    performance|perf|bench) dsu_ssl_performance "$@" ;;
    fingerprint|pinning|pin|fp) dsu_ssl_fingerprint "$@" ;;
    decode|d) dsu_ssl_decode "$@" ;;
    match|modulus|m) dsu_ssl_match "$@" ;;
    new|csr|n) dsu_ssl_new "$@" ;;
    pack|pfx-pack|pk) dsu_ssl_pack "$@" ;;
    extract|pfx-extract|x) dsu_ssl_extract "$@" ;;
    *) dsu_bad "Unknown ssl command: $cmd"; printf '\n'; _dsu_ssl_usage; return 2 ;;
  esac
}
