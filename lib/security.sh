#!/usr/bin/env bash

_dsu_audit_usage() {
  cat <<EOF_HELP
${DSU_BOLD}${DSU_CYAN}Web security exposure audit${DSU_RESET}

${DSU_BOLD}Usage:${DSU_RESET}
  dns-ssl-utilities.sh audit <domain-or-url> [options]
  vulncheck <domain-or-url> [options]          ${DSU_GRAY}# after setup.sh${DSU_RESET}

The default audit is non-destructive and low-impact: DNS policy, certificate/TLS,
HTTP-to-HTTPS behavior, security headers, cookies, CORS, methods, mixed content,
and a small set of common accidental-exposure paths. It does not attempt SQLi,
XSS, password attacks, destructive fuzzing, authentication bypass, or exploitation.

${DSU_BOLD}Options${DSU_RESET}
  ${DSU_GREEN}--deep${DSU_RESET}          Add DNS AXFR/recursion checks, extended exposure paths,
                  TLS cipher review and safe nmap web/TLS scripts when available.
  ${DSU_GREEN}--authorized${DSU_RESET}    Confirm you are authorized to actively assess this target.
                  Required for --deep and --ports.
  ${DSU_GREEN}--ports${DSU_RESET}         With --deep, run an nmap top-100 TCP port inventory.
  ${DSU_GREEN}--no-paths${DSU_RESET}      Skip accidental sensitive-path exposure checks.
  ${DSU_GREEN}--port N${DSU_RESET}        HTTPS/TLS port (default: 443).
  ${DSU_GREEN}--strict${DSU_RESET}        Exit non-zero when MEDIUM-or-higher findings exist.
  ${DSU_GREEN}--help, -h${DSU_RESET}      Show this help.

${DSU_BOLD}Severity model${DSU_RESET}
  ${DSU_RED}CRITICAL/HIGH${DSU_RESET}  Direct exposure, certificate identity failure, severe legacy crypto
  ${DSU_YELLOW}MEDIUM${DSU_RESET}         Material hardening gap or risky server behavior
  ${DSU_MAGENTA}LOW${DSU_RESET}            Defense-in-depth / information exposure
  ${DSU_CYAN}INFO${DSU_RESET}           Context or recommended hardening

${DSU_BLUE}Examples${DSU_RESET}
  dns-ssl-utilities.sh audit example.com
  dns-ssl-utilities.sh a https://example.com
  vulncheck example.com --deep --authorized
  vulncheck example.com --deep --ports --authorized --strict

${DSU_YELLOW}Important:${DSU_RESET} only use deep/port scanning against systems you are authorized to test.
EOF_HELP
}

_dsu_audit_dns() {
  local host="$1" dnskey ds caa mx spf dmarc cname cname_target cname_status spf_count dmarc_count mx_target mx_cname
  dsu_section "DNS + domain policy"
  cname=$(_dsu_dig_lines CNAME "$host" | head -1)
  if [[ -n "$cname" ]]; then
    cname_target="${cname%.}"
    cname_status=$(dig A "$cname_target" +noall +comments 2>/dev/null || true)
    if [[ -z "$(_dsu_dig_lines A "$cname_target")$(_dsu_dig_lines AAAA "$cname_target")$(_dsu_dig_lines CNAME "$cname_target")" ]] && [[ "$cname_status" == *'status: NXDOMAIN'* ]]; then
      dsu_finding HIGH "CNAME points to NXDOMAIN target $cname_target; investigate dangling-DNS/subdomain-takeover risk"
    else
      dsu_finding INFO "CNAME target: $cname_target"
    fi
  fi
  dnskey=$(_dsu_dig_lines DNSKEY "$host")
  ds=$(_dsu_dig_lines DS "$host")
  if [[ -n "$dnskey" && -n "$ds" ]]; then
    if dig A "$host" +dnssec 2>/dev/null | grep -q 'flags:.* ad[; ]'; then dsu_finding INFO "DNSSEC chain is present and validated by the configured resolver"
    else dsu_finding MEDIUM "DNSSEC records exist but the resolver did not return an AD validation flag"; fi
  elif [[ -n "$dnskey" || -n "$ds" ]]; then
    dsu_finding MEDIUM "DNSSEC appears partially configured (DNSKEY/DS mismatch)"
  else
    dsu_finding LOW "DNSSEC is not published"
  fi

  caa=$(_dsu_dig_lines CAA "$host")
  [[ -n "$caa" ]] && dsu_finding INFO "CAA restricts certificate issuance: $(printf '%s' "$caa" | paste -sd ', ' -)" || dsu_finding LOW "CAA is absent; any publicly trusted CA permitted by policy may issue"

  mx=$(_dsu_dig_lines MX "$host")
  spf_count=$(_dsu_dig_lines TXT "$host" | tr -d '"' | grep -ic '^v=spf1' || true)
  dmarc_count=$(_dsu_dig_lines TXT "_dmarc.$host" | tr -d '"' | grep -ic '^v=DMARC1' || true)
  spf=$(_dsu_dig_lines TXT "$host" | tr -d '"' | grep -i '^v=spf1' | head -1)
  dmarc=$(_dsu_dig_lines TXT "_dmarc.$host" | tr -d '"' | grep -i '^v=DMARC1' | head -1)
  if [[ -n "$mx" ]]; then
    [[ -n "$spf" ]] || dsu_finding MEDIUM "Domain has MX records but no SPF policy was found"
    [[ -n "$dmarc" ]] || dsu_finding MEDIUM "Domain has MX records but no DMARC policy was found"
    while read -r _ mx_target; do
      [[ -n "${mx_target:-}" ]] || continue
      mx_target="${mx_target%.}"
      mx_cname=$(_dsu_dig_lines CNAME "$mx_target" | head -1)
      [[ -n "$mx_cname" ]] && dsu_finding MEDIUM "MX target $mx_target is a CNAME ($mx_cname); MX targets should resolve directly"
    done <<< "$mx"
  fi
  (( spf_count > 1 )) && dsu_finding HIGH "Multiple SPF records were found; SPF requires one policy record"
  (( dmarc_count > 1 )) && dsu_finding MEDIUM "Multiple DMARC records were found; DMARC expects one policy record"
  [[ "$spf" == *'+all'* ]] && dsu_finding HIGH "SPF contains +all, effectively authorizing arbitrary senders"
  if [[ "$dmarc" =~ (^|[;[:space:]])p=none([;[:space:]]|$) ]]; then dsu_finding LOW "DMARC is monitoring-only (p=none)"; fi
}

_dsu_audit_tls() {
  local host="$1" port="$2" deep="$3" tmp conn verify end days sig text bits keytype stapling compression alpn
  dsu_section "TLS + certificate"
  tmp=$(dsu_tmpdir) || return 1
  conn=$(dsu_openssl_connection "$host" "$port")
  printf '%s\n' "$conn" | openssl x509 -outform PEM >"$tmp/leaf.pem" 2>/dev/null || true
  if [[ ! -s "$tmp/leaf.pem" ]]; then
    dsu_finding HIGH "No TLS certificate could be retrieved from $host:$port"
    dsu_cleanup_dir "$tmp"
    return 0
  fi

  verify=$(printf '%s\n' "$conn" | sed -n 's/^Verify return code: //p' | tail -1)
  if [[ "$verify" == 0* ]]; then dsu_finding INFO "Certificate chain verification returned: $verify"; else dsu_finding HIGH "Certificate chain verification returned: ${verify:-unknown}"; fi
  if openssl x509 -in "$tmp/leaf.pem" -noout -checkhost "$host" >/dev/null 2>&1; then dsu_finding INFO "Certificate identity matches $host"; else dsu_finding CRITICAL "Certificate identity does not match $host"; fi

  end=$(openssl x509 -in "$tmp/leaf.pem" -noout -enddate | cut -d= -f2-)
  if days=$(dsu_days_until "$end" 2>/dev/null); then
    if (( days < 0 )); then dsu_finding CRITICAL "Certificate expired $((-days)) days ago"
    elif (( days < 7 )); then dsu_finding HIGH "Certificate expires in $days days"
    elif (( days < 30 )); then dsu_finding MEDIUM "Certificate expires in $days days"
    else dsu_finding INFO "Certificate expires in $days days"; fi
  fi

  text=$(openssl x509 -in "$tmp/leaf.pem" -noout -text 2>/dev/null)
  sig=$(printf '%s\n' "$text" | awk -F': ' '/Signature Algorithm:/ {print tolower($2); exit}')
  [[ "$sig" == *md5* || "$sig" == *sha1* ]] && dsu_finding HIGH "Weak certificate signature algorithm: $sig" || dsu_finding INFO "Certificate signature algorithm: ${sig:-unknown}"
  bits=$(printf '%s\n' "$text" | sed -n 's/.*Public-Key: *(\([0-9][0-9]*\) bit).*/\1/p' | head -1)
  keytype=$(printf '%s\n' "$text" | awk -F': ' '/Public Key Algorithm:/ {print $2; exit}')
  if [[ "$keytype" == *rsaEncryption* && "$bits" =~ ^[0-9]+$ && "$bits" -lt 2048 ]]; then dsu_finding HIGH "RSA public key is only $bits bits"; elif [[ -n "$bits" ]]; then dsu_finding INFO "Public key: ${keytype:-unknown}, $bits bits"; fi

  local label flag
  while IFS=$'\t' read -r flag label; do
    if openssl s_client -help 2>&1 | grep -q -- "$flag" && _dsu_tls_probe "$flag" "$host" "$port"; then
      case "$flag" in
        -ssl3) dsu_finding HIGH "$label is accepted" ;;
        -tls1|-tls1_1) dsu_finding MEDIUM "$label is accepted; disable legacy TLS where possible" ;;
        *) dsu_finding INFO "$label is accepted" ;;
      esac
    fi
  done <<'VERSIONS'
-ssl3	SSLv3
-tls1	TLSv1.0
-tls1_1	TLSv1.1
-tls1_2	TLSv1.2
-tls1_3	TLSv1.3
VERSIONS

  compression=$(printf '%s\n' "$conn" | awk -F': ' '/^Compression:/ {print $2; exit}')
  if [[ -n "$compression" && "${compression^^}" != "NONE" ]]; then dsu_finding HIGH "TLS compression is enabled ($compression), exposing CRIME-style risk"; elif [[ -n "$compression" ]]; then dsu_finding INFO "TLS compression: $compression"; fi
  alpn=$(printf '%s\n' "$conn" | sed -n 's/^ALPN protocol: //p' | head -1)
  [[ -n "$alpn" ]] && dsu_finding INFO "ALPN negotiated: $alpn"
  stapling=$(timeout "$DSU_MAX_TIME" openssl s_client -status -servername "$host" -connect "$host:$port" </dev/null 2>/dev/null | awk '/OCSP response:/ {sub(/^.*OCSP response:[[:space:]]*/, ""); print; exit}')
  if [[ "$stapling" == *'no response sent'* || -z "$stapling" ]]; then dsu_finding INFO "OCSP stapling was not observed (not universally required)"; else dsu_finding INFO "OCSP stapling response was presented"; fi

  if (( deep )); then
    if dsu_has sslscan; then
      local scan weak
      scan=$(sslscan --no-colour "$host:$port" 2>/dev/null || true)
      weak=$(printf '%s\n' "$scan" | grep -iE 'Accepted.*(NULL|RC4|3DES|DES-CBC|EXP|anon|MD5)' | head -10 || true)
      if [[ -n "$weak" ]]; then
        dsu_finding HIGH "Weak/legacy cipher suites were accepted"
        while IFS= read -r line; do dsu_dim "$line"; done <<< "$weak"
      else
        dsu_finding INFO "sslscan did not identify obvious NULL/RC4/DES/3DES/EXPORT/anonymous/MD5 accepted ciphers"
      fi
    elif dsu_has nmap; then
      dsu_finding INFO "sslscan not installed; deep nmap TLS script will provide cipher detail later"
    else
      dsu_finding INFO "Install sslscan for deep cipher-suite enumeration"
    fi
  fi
  dsu_cleanup_dir "$tmp"
}

_dsu_audit_headers() {
  local host="$1" port="$2" base="https://$host" headers hsts maxage csp xfo nosniff referrer permissions coop corp server powered
  [[ "$port" != 443 ]] && base="https://$host:$port"
  headers=$(dsu_http_final_headers "$base/")
  dsu_section "HTTP security headers"
  if [[ -z "$headers" ]]; then dsu_finding HIGH "Could not retrieve HTTPS headers"; return 0; fi

  hsts=$(dsu_header_value "$headers" strict-transport-security)
  if [[ -z "$hsts" ]]; then
    dsu_finding MEDIUM "Strict-Transport-Security (HSTS) is missing"
  else
    maxage=$(printf '%s' "$hsts" | grep -oiE 'max-age=[0-9]+' | cut -d= -f2 | head -1)
    if [[ "$maxage" =~ ^[0-9]+$ && "$maxage" -lt 15552000 ]]; then dsu_finding LOW "HSTS max-age is short ($maxage seconds)"; else dsu_finding INFO "HSTS: $hsts"; fi
    [[ "$hsts" != *includeSubDomains* ]] && dsu_finding INFO "HSTS does not include subdomains"
  fi

  csp=$(dsu_header_value "$headers" content-security-policy)
  if [[ -z "$csp" ]]; then
    dsu_finding MEDIUM "Content-Security-Policy is missing"
  else
    dsu_finding INFO "Content-Security-Policy is present"
    [[ "$csp" == *"'unsafe-eval'"* ]] && dsu_finding MEDIUM "CSP permits 'unsafe-eval'"
    [[ "$csp" == *"'unsafe-inline'"* ]] && dsu_finding LOW "CSP permits 'unsafe-inline'"
    [[ "$csp" == *' * '* || "$csp" =~ (^|[[:space:]])\*([[:space:];]|$) ]] && dsu_finding LOW "CSP contains a wildcard source"
  fi

  xfo=$(dsu_header_value "$headers" x-frame-options)
  if [[ -n "$xfo" || "$csp" == *frame-ancestors* ]]; then dsu_finding INFO "Clickjacking protection is declared"; else dsu_finding MEDIUM "No X-Frame-Options or CSP frame-ancestors protection found"; fi
  nosniff=$(dsu_header_value "$headers" x-content-type-options)
  [[ "${nosniff,,}" == *nosniff* ]] && dsu_finding INFO "X-Content-Type-Options: nosniff" || dsu_finding LOW "X-Content-Type-Options: nosniff is missing"
  referrer=$(dsu_header_value "$headers" referrer-policy)
  [[ -n "$referrer" ]] && dsu_finding INFO "Referrer-Policy: $referrer" || dsu_finding LOW "Referrer-Policy is missing"
  permissions=$(dsu_header_value "$headers" permissions-policy)
  [[ -n "$permissions" ]] && dsu_finding INFO "Permissions-Policy is present" || dsu_finding INFO "Permissions-Policy is not set"
  coop=$(dsu_header_value "$headers" cross-origin-opener-policy)
  corp=$(dsu_header_value "$headers" cross-origin-resource-policy)
  [[ -n "$coop" ]] || dsu_finding INFO "Cross-Origin-Opener-Policy is not set"
  [[ -n "$corp" ]] || dsu_finding INFO "Cross-Origin-Resource-Policy is not set"
  server=$(dsu_header_value "$headers" server)
  powered=$(dsu_header_value "$headers" x-powered-by)
  if [[ -n "$server" ]]; then
    if [[ "$server" =~ /[0-9] ]]; then dsu_finding LOW "Server header exposes product/version: $server"; else dsu_finding INFO "Server header exposed: $server"; fi
  fi
  [[ -n "$powered" ]] && dsu_finding LOW "X-Powered-By exposes implementation detail: $powered"
}

_dsu_audit_http_behavior() {
  local host="$1" port="$2" base="https://$host" http_headers location code trace options allow cors_headers acao acac html cookies cookie name
  [[ "$port" != 443 ]] && base="https://$host:$port"
  dsu_section "HTTP behavior + browser-facing controls"

  http_headers=$(dsu_http_headers "http://$host/")
  location=$(dsu_header_value "$http_headers" location)
  code=$(printf '%s\n' "$http_headers" | awk '/^HTTP\// {c=$2} END{print c}')
  if [[ "$location" == https://* ]]; then dsu_finding INFO "Plain HTTP redirects to HTTPS ($code → $location)"; else dsu_finding MEDIUM "Plain HTTP does not clearly redirect to HTTPS${location:+ (Location: $location)}"; fi

  trace=$(dsu_http_status "$base/" -X TRACE)
  [[ "$trace" == 200 ]] && dsu_finding MEDIUM "HTTP TRACE is enabled (HTTP 200)" || dsu_finding INFO "HTTP TRACE not accepted (status $trace)"

  options=$(dsu_http_headers "$base/" -X OPTIONS)
  allow=$(dsu_header_value "$options" allow)
  if [[ -n "$allow" ]]; then
    dsu_finding INFO "Allow header: $allow"
    [[ "${allow^^}" == *CONNECT* ]] && dsu_finding HIGH "HTTP CONNECT is advertised by the origin"
    [[ "${allow^^}" == *TRACE* ]] && dsu_finding MEDIUM "TRACE is advertised in Allow"
    [[ "${allow^^}" == *PUT* || "${allow^^}" == *DELETE* ]] && dsu_finding LOW "State-changing methods are advertised; verify authorization controls: $allow"
  fi

  cors_headers=$(dsu_http_headers "$base/" -H 'Origin: https://dns-ssl-utilities.invalid')
  acao=$(dsu_header_value "$cors_headers" access-control-allow-origin)
  acac=$(dsu_header_value "$cors_headers" access-control-allow-credentials)
  if [[ "$acao" == 'https://dns-ssl-utilities.invalid' && "${acac,,}" == true ]]; then
    dsu_finding HIGH "CORS reflects an arbitrary Origin and allows credentials"
  elif [[ "$acao" == '*' && "${acac,,}" == true ]]; then
    dsu_finding MEDIUM "CORS returns wildcard ACAO with credentials; browsers reject this combination, but configuration is inconsistent"
  elif [[ "$acao" == 'https://dns-ssl-utilities.invalid' ]]; then
    dsu_finding MEDIUM "CORS appears to reflect an arbitrary Origin"
  elif [[ "$acao" == '*' ]]; then
    dsu_finding LOW "CORS allows any origin (*)"
  else
    dsu_finding INFO "No obviously permissive CORS behavior observed on /"
  fi

  cookies=$(dsu_header_values "$(dsu_http_headers "$base/")" set-cookie)
  if [[ -n "$cookies" ]]; then
    while IFS= read -r cookie; do
      name=${cookie%%=*}
      if [[ ! "${cookie,,}" =~ \;[[:space:]]*secure([;[:space:]]|$) ]]; then
        if [[ "${name,,}" =~ (session|sess|auth|token|sid|jwt) ]]; then dsu_finding MEDIUM "Sensitive-looking cookie '$name' lacks Secure"; else dsu_finding LOW "Cookie '$name' lacks Secure"; fi
      fi
      if [[ ! "${cookie,,}" =~ \;[[:space:]]*httponly([;[:space:]]|$) ]]; then
        if [[ "${name,,}" =~ (session|sess|auth|token|sid|jwt) ]]; then dsu_finding MEDIUM "Sensitive-looking cookie '$name' lacks HttpOnly"; else dsu_finding INFO "Cookie '$name' lacks HttpOnly (may be intentional)"; fi
      fi
      [[ ! "${cookie,,}" =~ \;[[:space:]]*samesite= ]] && dsu_finding LOW "Cookie '$name' has no SameSite attribute"
    done <<< "$cookies"
  else
    dsu_finding INFO "No Set-Cookie headers observed on /"
  fi

  html=$(curl -ksS --compressed --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" --max-filesize 1048576 -A "$DSU_USER_AGENT" "$base/" 2>/dev/null | head -c 1048576 || true)
  if [[ -n "$html" ]]; then
    if printf '%s' "$html" | grep -Eqi "<(script|img|iframe|link|form)[^>]+(src|href|action)=[\"']http://"; then dsu_finding MEDIUM "HTTPS page contains active/passive mixed-content HTTP references"; else dsu_finding INFO "No obvious http:// mixed-content references found in the first 1 MiB"; fi
    if printf '%s' "$html" | grep -Eqi "<input[^>]+type=[\"']?password"; then
      if printf '%s' "$html" | grep -Eqi "<form[^>]+action=[\"']http://"; then dsu_finding HIGH "Password form appears to submit to plain HTTP"; else dsu_finding INFO "Password input detected; page itself is HTTPS"; fi
    fi
    printf '%s' "$html" | grep -Eqi '<title>[[:space:]]*Index of /' && dsu_finding LOW "Root page appears to expose a directory listing"
  fi

  code=$(dsu_http_status "$base/.well-known/security.txt")
  [[ "$code" == 200 ]] && dsu_finding INFO "security.txt is published" || dsu_finding INFO "security.txt not found (status $code)"
}

_dsu_probe_path() {
  local base="$1" path="$2" marker="$3" severity="$4" description="$5" tmp status ctype
  tmp=$(mktemp)
  local raw_status rc
  raw_status=$(curl -ksS --range 0-65535 --max-filesize 1048576 --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" -A "$DSU_USER_AGENT" \
    -o "$tmp" -w '%{http_code}' "$base$path" 2>/dev/null)
  rc=$?
  if [[ "$raw_status" =~ ([0-9]{3})$ ]]; then status="${BASH_REMATCH[1]}"; elif (( rc != 0 )); then status=000; else status="${raw_status:-000}"; fi
  if [[ "$status" == 200 || "$status" == 206 ]]; then
    if [[ -n "$marker" ]] && grep -Eqi "$marker" "$tmp" 2>/dev/null; then
      dsu_finding "$severity" "$description exposed at $path"
    elif [[ "$path" == *.zip || "$path" == *.tar.gz || "$path" == *.sql ]]; then
      ctype=$(file -b "$tmp" 2>/dev/null || true)
      if [[ "$ctype" == *Zip* || "$ctype" == *SQL* || "$ctype" == *archive* ]]; then dsu_finding "$severity" "$description may be exposed at $path ($ctype)"; fi
    fi
  elif [[ "$status" == 403 ]]; then
    dsu_finding INFO "$path exists or is filtered (403); access was denied"
  fi
  rm -f "$tmp"
}

_dsu_audit_paths() {
  local host="$1" port="$2" deep="$3" base="https://$host"
  [[ "$port" != 443 ]] && base="https://$host:$port"
  dsu_section "Accidental exposure paths"
  _dsu_probe_path "$base" '/.git/HEAD' '^ref: refs/' HIGH 'Git repository metadata'
  _dsu_probe_path "$base" '/.env' '(^|\n)(APP_KEY|DB_PASSWORD|DATABASE_URL|AWS_SECRET_ACCESS_KEY|SECRET_KEY)=' CRITICAL 'Environment secrets'
  _dsu_probe_path "$base" '/server-status' 'Apache Server Status|Server Version:' MEDIUM 'Apache server-status'
  _dsu_probe_path "$base" '/phpinfo.php' 'phpinfo\(\)|PHP Version' HIGH 'phpinfo output'
  _dsu_probe_path "$base" '/wp-config.php.bak' 'DB_(NAME|USER|PASSWORD)' HIGH 'WordPress configuration backup'
  _dsu_probe_path "$base" '/actuator/env' 'propertySources|activeProfiles|systemProperties' HIGH 'Spring Boot actuator environment'
  if (( deep )); then
    _dsu_probe_path "$base" '/.svn/entries' 'dir|svn' HIGH 'Subversion metadata'
    _dsu_probe_path "$base" '/debug/vars' '"cmdline"|"memstats"|"goroutines"' MEDIUM 'Go expvar debug data'
    _dsu_probe_path "$base" '/dump.sql' 'CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump' CRITICAL 'Database dump'
    _dsu_probe_path "$base" '/backup.zip' '' HIGH 'Backup archive'
    _dsu_probe_path "$base" '/config.php.bak' '(password|passwd|DB_PASSWORD|database)' HIGH 'Configuration backup'
    _dsu_probe_path "$base" '/.DS_Store' 'Bud1|DSDB' LOW 'Finder metadata'
    _dsu_probe_path "$base" '/composer.json' '"require"[[:space:]]*:' LOW 'Composer dependency manifest'
    _dsu_probe_path "$base" '/package.json' '"dependencies"[[:space:]]*:' LOW 'Node package manifest'
  fi
  dsu_finding INFO "Exposure probes are signature-checked to reduce soft-404 false positives"
}

_dsu_audit_deep_dns() {
  local host="$1" ns output recursion
  dsu_section "Deep DNS exposure checks"
  while IFS= read -r ns; do
    [[ -n "$ns" ]] || continue
    ns="${ns%.}"
    # Cap captured transfer output so a large zone cannot consume unbounded memory.
    output=$(timeout 15 dig AXFR "$host" "@$ns" +time=4 +tries=1 2>/dev/null | head -n 120 || true)
    if [[ "$output" != *"Transfer failed"* ]] && printf '%s\n' "$output" | awk '
      $0 !~ /^;/ && NF >= 4 { rr++ }
      $4 == "SOA" { soa=1 }
      END { exit !(soa && rr >= 2) }'; then
      dsu_finding HIGH "Authoritative server $ns allowed AXFR zone transfer for $host"
    else
      dsu_finding INFO "AXFR refused/not available on $ns"
    fi
    recursion=$(timeout 8 dig @"$ns" example.net A +recurse +time=3 +tries=1 2>/dev/null || true)
    if printf '%s\n' "$recursion" | grep -qE 'flags:.* ra[; ]' && printf '%s\n' "$recursion" | awk '/^;; ANSWER SECTION:/{getline; if($0 !~ /^$/) found=1} END{exit !found}'; then
      dsu_finding MEDIUM "$ns appears willing to provide recursive answers to this client"
    else
      dsu_finding INFO "$ns did not appear to offer open recursion to this client"
    fi
  done < <(_dsu_dig_lines NS "$host")
}

_dsu_audit_nmap() {
  local host="$1" port="$2" ports="$3"
  dsu_section "Deep network/TLS inventory"
  if ! dsu_has nmap; then dsu_finding INFO "nmap not installed; safe NSE checks skipped"; return 0; fi
  dsu_info "Running safe web/TLS NSE scripts on ports 80 and $port"
  nmap -Pn -T3 -p "80,$port" --script 'ssl-cert,ssl-enum-ciphers,http-security-headers,http-methods' "$host" 2>/dev/null | sed 's/^/  /'
  if (( ports )); then
    dsu_info "Running authorized top-100 TCP port inventory"
    nmap -Pn -T3 --top-ports 100 --open "$host" 2>/dev/null | sed 's/^/  /'
  fi
}

dsu_security_audit() {
  local input="${1:-}"; shift || true
  [[ -n "$input" && "$input" != --* ]] || { _dsu_audit_usage; return 2; }
  local deep=0 authorized=0 ports=0 path_checks=1 strict=0 port=443 arg host
  while (( $# )); do
    arg="$1"; shift
    case "$arg" in
      --deep) deep=1 ;;
      --authorized|--authorised) authorized=1 ;;
      --ports) ports=1; deep=1 ;;
      --no-paths) path_checks=0 ;;
      --strict) strict=1 ;;
      --port) [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] || { dsu_bad "--port requires a numeric value"; return 2; }; port="$1"; shift ;;
      --help|-h) _dsu_audit_usage; return 0 ;;
      *) dsu_bad "Unknown audit option: $arg"; return 2 ;;
    esac
  done
  if (( deep && ! authorized )); then
    dsu_bad "--deep/--ports require --authorized to reduce accidental active scanning"
    dsu_info "Example: audit $input --deep --authorized"
    return 2
  fi

  dsu_need dig dnsutils || return
  dsu_need curl curl || return
  dsu_need openssl openssl || return
  dsu_need python3 python3 || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
  dsu_find_reset
  dsu_banner
  printf '\n%s%sSecurity exposure audit:%s %s%s%s\n' "$DSU_BOLD" "$DSU_WHITE" "$DSU_RESET" "$DSU_CYAN" "$host:$port" "$DSU_RESET"
  if (( deep )); then dsu_warn "Deep authorized mode enabled: additional DNS and network probes will be sent"; else dsu_dim "Low-impact mode. Use --deep --authorized for additional authorized checks."; fi

  _dsu_audit_dns "$host"
  _dsu_audit_tls "$host" "$port" "$deep"
  _dsu_audit_headers "$host" "$port"
  _dsu_audit_http_behavior "$host" "$port"
  (( path_checks )) && _dsu_audit_paths "$host" "$port" "$deep"
  if (( deep )); then
    _dsu_audit_deep_dns "$host"
    _dsu_audit_nmap "$host" "$port" "$ports"
  fi

  dsu_finding_summary
  dsu_dim "This is an exposure/hardening audit, not proof that a target is vulnerability-free. Validate material findings manually."

  if (( strict )); then
    if (( DSU_FIND_CRITICAL + DSU_FIND_HIGH > 0 )); then return 2
    elif (( DSU_FIND_MEDIUM > 0 )); then return 1
    fi
  fi
  return 0
}
