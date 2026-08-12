#!/usr/bin/env bash

_dsu_ssl_usage() {
  cat <<EOF_HELP
${DSU_BOLD}${DSU_CYAN}SSL / certificate commands${DSU_RESET}

${DSU_BOLD}Usage:${DSU_RESET}
  dns-ssl-utilities.sh ssl <command> [arguments]
  ssl <command> [arguments]                  ${DSU_GRAY}# after setup.sh${DSU_RESET}

${DSU_GREEN}cert, c${DSU_RESET}          Certificate identity, validity, SANs, key and fingerprint
${DSU_GREEN}quick, q${DSU_RESET}         Compact certificate health line
${DSU_GREEN}chain, ch${DSU_RESET}        Show the full server certificate chain
${DSU_GREEN}fetch, f${DSU_RESET}         Test a domain against a specific IP/SNI endpoint
${DSU_GREEN}versions, v${DSU_RESET}      Probe TLS protocol-version support
${DSU_GREEN}ciphers, ci${DSU_RESET}      Enumerate accepted ciphers with sslscan/nmap
${DSU_GREEN}scan, s${DSU_RESET}          Run sslscan directly when installed
${DSU_GREEN}ocsp, o${DSU_RESET}          Check OCSP status using the served issuer certificate
${DSU_GREEN}crl${DSU_RESET}              Check the leaf serial against its CRL distribution point
${DSU_GREEN}ct, ctlogs${DSU_RESET}       Query Certificate Transparency names through crt.sh
${DSU_GREEN}headers, h${DSU_RESET}       Inspect HTTPS security headers
${DSU_GREEN}performance, perf${DSU_RESET} Benchmark TLS handshakes with openssl s_time
${DSU_GREEN}fingerprint, fp${DSU_RESET}  Show/compare SHA-256 certificate fingerprint

${DSU_MAGENTA}Certificate-file tools${DSU_RESET}
${DSU_GREEN}decode, d${DSU_RESET}        Decode a certificate, CSR or key file
${DSU_GREEN}match, m${DSU_RESET}         Verify cert/CSR/private-key public keys match
${DSU_GREEN}new, n${DSU_RESET}           Create a private key and CSR with SAN support
${DSU_GREEN}pack, pk${DSU_RESET}         Build a PFX/PKCS#12 bundle
${DSU_GREEN}extract, x${DSU_RESET}       Extract cert/CA/key material from a PFX

${DSU_BLUE}Examples${DSU_RESET}
  ssl cert example.com
  ssl c example.com 8443
  ssl fetch 203.0.113.10 example.com
  ssl versions example.com
  ssl match site.crt site.csr site.key
  ssl new example.com --san www.example.com --san mail.example.com
  ssl pack site.crt site.key chain.pem site.pfx
EOF_HELP
}


_dsu_ssl_leaf_help() {
  local cmd="${1,,}"
  case "$cmd" in
    cert|certificate|c) cat <<EOF
${DSU_BOLD}ssl cert${DSU_RESET} — inspect a live server certificate
Usage: ssl cert <domain> [port]
Aliases: ssl c, ssl certificate
Shows subject, issuer, validity, SANs, signature/key details, SHA-256 fingerprint,
CA verification result, hostname match and days remaining.
EOF
      ;;
    quick|q) cat <<EOF
${DSU_BOLD}ssl quick${DSU_RESET} — compact certificate health
Usage: ssl quick <domain> [port]
Alias: ssl q
EOF
      ;;
    chain|ch) cat <<EOF
${DSU_BOLD}ssl chain${DSU_RESET} — raw served chain and OpenSSL handshake output
Usage: ssl chain <domain> [port]
Alias: ssl ch
EOF
      ;;
    fetch|f) cat <<EOF
${DSU_BOLD}ssl fetch${DSU_RESET} — validate a domain/SNI against a chosen server IP
Usage: ssl fetch <server-ip> <domain> [port]
Alias: ssl f
Useful before DNS changes or while testing a specific hosting node.
EOF
      ;;
    versions|version|v) cat <<EOF
${DSU_BOLD}ssl versions${DSU_RESET} — probe protocol support
Usage: ssl versions <domain> [port]
Alias: ssl v
Probes the TLS/SSL version flags available in your local OpenSSL build.
EOF
      ;;
    ciphers|cipher|ci) cat <<EOF
${DSU_BOLD}ssl ciphers${DSU_RESET} — enumerate accepted cipher suites
Usage: ssl ciphers <domain> [port]
Alias: ssl ci
Uses sslscan when available, otherwise nmap ssl-enum-ciphers.
EOF
      ;;
    scan|s) cat <<EOF
${DSU_BOLD}ssl scan${DSU_RESET} — run sslscan
Usage: ssl scan <domain> [port]
Alias: ssl s
Requires the optional sslscan package.
EOF
      ;;
    ocsp|o) printf '%b\n' "${DSU_BOLD}ssl ocsp${DSU_RESET} — Usage: ssl ocsp <domain> [port]  (alias: ssl o)" ;;
    crl) printf '%b\n' "${DSU_BOLD}ssl crl${DSU_RESET} — Usage: ssl crl <domain> [port]" ;;
    ct|ctlogs|transparency) printf '%b\n' "${DSU_BOLD}ssl ct${DSU_RESET} — Usage: ssl ct <domain>  (queries crt.sh)" ;;
    headers|header|h) printf '%b\n' "${DSU_BOLD}ssl headers${DSU_RESET} — Usage: ssl headers <domain-or-url>  (alias: ssl h)" ;;
    performance|perf|bench) printf '%b\n' "${DSU_BOLD}ssl performance${DSU_RESET} — Usage: ssl performance <domain> [port] [seconds]" ;;
    fingerprint|pinning|pin|fp) cat <<EOF
${DSU_BOLD}ssl fingerprint${DSU_RESET} — show or compare SHA-256 certificate fingerprint
Usage: ssl fingerprint <domain> [expected-sha256] [port]
Aliases: ssl fp, ssl pin
EOF
      ;;
    decode|d) printf '%b\n' "${DSU_BOLD}ssl decode${DSU_RESET} — Usage: ssl decode <certificate.pem|request.csr|private.key>" ;;
    match|modulus|m) cat <<EOF
${DSU_BOLD}ssl match${DSU_RESET} — verify files contain the same public key
Usage: ssl match <cert|csr|key> <cert|csr|key> [more files...]
Alias: ssl m
Uses SHA-256 of canonical DER public keys and supports RSA and EC.
EOF
      ;;
    new|csr|n) cat <<EOF
${DSU_BOLD}ssl new${DSU_RESET} — create a private key and CSR
Usage: ssl new <common-name> [--san NAME] [--out PREFIX] [--rsa BITS|--ec CURVE] [--encrypted]
Alias: ssl n
Example: ssl n example.com --san www.example.com --rsa 4096 --out example
EOF
      ;;
    pack|pfx-pack|pk) cat <<EOF
${DSU_BOLD}ssl pack${DSU_RESET} — create a PKCS#12/PFX bundle
Usage: ssl pack <certificate.pem> <private.key> [chain.pem] [output.pfx]
Alias: ssl pk
Prompts for a PFX password; DSU_PFX_PASSWORD can be used for automation.
EOF
      ;;
    extract|pfx-extract|x) cat <<EOF
${DSU_BOLD}ssl extract${DSU_RESET} — extract a PFX bundle
Usage: ssl extract <bundle.pfx> [output-directory]
Alias: ssl x
The extracted private key is unencrypted and chmodded 0600.
EOF
      ;;
    *) _dsu_ssl_usage ;;
  esac
}

_dsu_ssl_target() {
  local input="${1:-}" host port
  host=$(dsu_normalize_host "$input")
  port=$(dsu_extract_port "$input" "${2:-443}")
  printf '%s\t%s\n' "$host" "$port"
}

dsu_ssl_cert() {
  local input="${1:-}" explicit_port="${2:-}" host port tmp conn verify subject issuer start end serial fp sig pub san days
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl cert <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  port="${explicit_port:-$(dsu_extract_port "$input" 443)}"
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
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
  if openssl x509 -in "$tmp/leaf.pem" -noout -checkhost "$host" >/dev/null 2>&1; then dsu_ok "Hostname matches certificate"; else dsu_bad "Hostname does not match certificate"; fi
  if days=$(dsu_days_until "$end" 2>/dev/null); then
    if (( days < 0 )); then dsu_bad "Certificate expired $((-days)) days ago"; elif (( days < 14 )); then dsu_bad "Certificate expires in $days days"; elif (( days < 30 )); then dsu_warn "Certificate expires in $days days"; else dsu_ok "Certificate valid for $days more days"; fi
  fi
  trap - RETURN
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_quick() {
  local input="${1:-}" port="${2:-443}" host tmp end days issuer
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl quick <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  tmp=$(dsu_tmpdir) || return 1
  if ! dsu_fetch_leaf_cert "$host" "$port" "$tmp/cert.pem"; then dsu_cleanup_dir "$tmp"; dsu_bad "$host:$port · no certificate retrieved"; return 1; fi
  end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate | cut -d= -f2-)
  issuer=$(openssl x509 -in "$tmp/cert.pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//' | sed -n 's/.*CN=\([^,]*\).*/\1/p')
  days=$(dsu_days_until "$end" 2>/dev/null || printf '?')
  if [[ "$days" =~ ^-?[0-9]+$ ]] && (( days < 0 )); then dsu_bad "$host:$port · EXPIRED · $end · ${issuer:-issuer unknown}"; elif [[ "$days" =~ ^[0-9]+$ ]] && (( days < 30 )); then dsu_warn "$host:$port · $days days left · $end · ${issuer:-issuer unknown}"; else dsu_ok "$host:$port · ${days} days left · $end · ${issuer:-issuer unknown}"; fi
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_chain() {
  local input="${1:-}" port="${2:-443}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl chain <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  dsu_section "Certificate chain · $host:$port"
  openssl s_client -servername "$host" -connect "$host:$port" -showcerts </dev/null 2>&1
}

dsu_ssl_fetch() {
  local ip="${1:-}" domain="${2:-}" port="${3:-443}" tmp conn verify end
  [[ -n "$ip" && -n "$domain" ]] || { dsu_bad "Usage: ssl fetch <server-ip> <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  dsu_need curl curl || return
  domain=$(dsu_normalize_host "$domain")
  dsu_is_ip "$ip" || { dsu_bad "Invalid server IP: $ip"; return 2; }
  dsu_valid_host "$domain" || { dsu_bad "Invalid domain: $domain"; return 2; }
  tmp=$(dsu_tmpdir) || return 1
  conn=$(timeout "$DSU_MAX_TIME" openssl s_client -servername "$domain" -connect "$ip:$port" -showcerts </dev/null 2>&1)
  printf '%s\n' "$conn" | openssl x509 -outform PEM >"$tmp/leaf.pem" 2>/dev/null || true
  dsu_section "SNI endpoint · $domain → $ip:$port"
  if [[ ! -s "$tmp/leaf.pem" ]]; then dsu_bad "No certificate retrieved"; dsu_cleanup_dir "$tmp"; return 1; fi
  verify=$(printf '%s\n' "$conn" | sed -n 's/^Verify return code: //p' | tail -1)
  end=$(openssl x509 -in "$tmp/leaf.pem" -noout -enddate | cut -d= -f2-)
  dsu_keyval "Expires" "$end"
  dsu_keyval "OpenSSL verify" "${verify:-unknown}"
  if openssl x509 -in "$tmp/leaf.pem" -noout -checkhost "$domain" >/dev/null 2>&1; then dsu_ok "Certificate matches $domain"; else dsu_bad "Certificate does not match $domain"; fi
  if curl -fsSI --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" --resolve "$domain:$port:$ip" "https://$domain:$port/" >/dev/null 2>&1; then dsu_ok "curl CA + hostname validation passed against $ip"; else dsu_warn "curl validation/request failed against $ip"; fi
  dsu_cleanup_dir "$tmp"
}

_dsu_tls_probe() {
  local flag="$1" host="$2" port="$3"
  timeout "$DSU_MAX_TIME" openssl s_client "$flag" -servername "$host" -connect "$host:$port" </dev/null 2>&1 | grep -qE '^Protocol *:|^ *Protocol *:'
}

dsu_ssl_versions() {
  local input="${1:-}" port="${2:-443}" host flag label
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl versions <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
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
  local input="${1:-}" port="${2:-443}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl ciphers <domain> [port]"; return 2; }
  host=$(dsu_normalize_host "$input")
  dsu_section "Cipher enumeration · $host:$port"
  if dsu_has sslscan; then
    sslscan --no-colour "$host:$port"
  elif dsu_has nmap; then
    nmap -Pn -p "$port" --script ssl-enum-ciphers "$host"
  else
    dsu_bad "Install sslscan (preferred) or nmap for cipher enumeration"
    return 127
  fi
}

dsu_ssl_scan() {
  local input="${1:-}" port="${2:-443}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl scan <domain> [port]"; return 2; }
  dsu_need sslscan sslscan || return
  host=$(dsu_normalize_host "$input")
  sslscan "$host:$port"
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
  local input="${1:-}" port="${2:-443}" host tmp conn uri issuer
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl ocsp <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
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
  openssl ocsp -no_nonce -issuer "$issuer" -cert "$tmp/cert-01.pem" -url "$uri" -CAfile /etc/ssl/certs/ca-certificates.crt 2>&1 | sed 's/^/  /'
  dsu_cleanup_dir "$tmp"
}

dsu_ssl_crl() {
  local input="${1:-}" port="${2:-443}" host tmp uri serial format
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl crl <domain> [port]"; return 2; }
  dsu_need openssl openssl || return
  dsu_need curl curl || return
  host=$(dsu_normalize_host "$input")
  tmp=$(dsu_tmpdir) || return 1
  if ! dsu_fetch_leaf_cert "$host" "$port" "$tmp/leaf.pem"; then dsu_bad "Could not retrieve certificate"; dsu_cleanup_dir "$tmp"; return 1; fi
  uri=$(openssl x509 -in "$tmp/leaf.pem" -noout -text | awk '/CRL Distribution Points:/{incrl=1; next} incrl && /URI:/{sub(/.*URI:/,""); print; exit} incrl && /^[^ ]/{exit}')
  dsu_section "CRL · $host:$port"
  [[ -n "$uri" ]] || { dsu_info "No CRL Distribution Point advertised"; dsu_cleanup_dir "$tmp"; return 1; }
  dsu_keyval "Distribution point" "$uri"
  if ! curl -fsSL --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time 20 -A "$DSU_USER_AGENT" "$uri" -o "$tmp/crl"; then dsu_bad "Could not download CRL"; dsu_cleanup_dir "$tmp"; return 1; fi
  format=PEM
  openssl crl -in "$tmp/crl" -noout >/dev/null 2>&1 || format=DER
  serial=$(openssl x509 -in "$tmp/leaf.pem" -noout -serial | cut -d= -f2 | tr -d ':')
  if openssl crl -in "$tmp/crl" -inform "$format" -noout -text 2>/dev/null | tr -d ':' | grep -qi "Serial Number: *$serial"; then dsu_bad "Certificate serial is listed as REVOKED"; else dsu_ok "Certificate serial not found in downloaded CRL"; fi
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
  local input="${1:-}" port="${2:-443}" seconds="${3:-5}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl performance <domain> [port] [seconds]"; return 2; }
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  dsu_section "TLS handshake benchmark · $host:$port"
  openssl s_time -connect "$host:$port" -new -www / -time "$seconds"
}

dsu_ssl_fingerprint() {
  local input="${1:-}" expected="${2:-}" port="${3:-443}" host tmp fp norm_expected norm_actual
  [[ -n "$input" ]] || { dsu_bad "Usage: ssl fingerprint <domain> [expected-sha256] [port]"; return 2; }
  host=$(dsu_normalize_host "$input")
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

_dsu_public_key_hash() {
  local file="$1" kind
  kind=$(_dsu_file_kind "$file")
  case "$kind" in
    cert) openssl x509 -in "$file" -pubkey -noout 2>/dev/null ;;
    csr) openssl req -in "$file" -pubkey -noout 2>/dev/null ;;
    key) openssl pkey -in "$file" -pubout 2>/dev/null ;;
    *) return 1 ;;
  esac | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}'
}

dsu_ssl_match() {
  (( $# >= 2 )) || { dsu_bad "Usage: ssl match <cert|csr|key> <cert|csr|key> [more files...]"; return 2; }
  dsu_need openssl openssl || return
  local first_hash='' file hash kind mismatch=0
  dsu_section "Public-key match"
  for file in "$@"; do
    [[ -f "$file" ]] || { dsu_bad "File not found: $file"; mismatch=1; continue; }
    kind=$(_dsu_file_kind "$file")
    hash=$(_dsu_public_key_hash "$file" || true)
    [[ -n "$hash" ]] || { dsu_bad "$file: unreadable/unsupported"; mismatch=1; continue; }
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
  for name in "${sans[@]}"; do [[ -n "$san_csv" ]] && san_csv+=","; san_csv+="DNS:$name"; done
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
  mkdir -p "$outdir"
  local password
  printf '%s' "PFX password (blank if none): " >&2
  IFS= read -rs password; printf '\n' >&2
  export DSU_PFX_PASS="$password"
  dsu_section "Extract PKCS#12 · $pfx"
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -clcerts -nokeys -out "$outdir/certificate.pem" || { unset DSU_PFX_PASS; return 1; }
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -cacerts -nokeys -out "$outdir/ca-chain.pem" || true
  openssl pkcs12 -in "$pfx" -passin env:DSU_PFX_PASS -nocerts -nodes -out "$outdir/private-key.pem" || { unset DSU_PFX_PASS; return 1; }
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
