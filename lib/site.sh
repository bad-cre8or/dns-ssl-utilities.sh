#!/usr/bin/env bash

_dsu_site_usage() {
  cat <<EOF_HELP
${DSU_BOLD}${DSU_CYAN}Site diagnostics${DSU_RESET}

${DSU_BOLD}Usage:${DSU_RESET}
  dns-ssl-utilities.sh site <command> [arguments]
  sitecheck <domain>                          ${DSU_GRAY}# after setup.sh${DSU_RESET}

${DSU_GREEN}check, c${DSU_RESET}        Full domain + hosting + TLS + HTTP health summary
${DSU_GREEN}headers, h${DSU_RESET}      HTTP response/security headers
${DSU_GREEN}redirects, r${DSU_RESET}    Follow and display HTTP/HTTPS redirect chains
${DSU_GREEN}status, s${DSU_RESET}       Compact HTTP + TLS availability status

${DSU_BLUE}Examples${DSU_RESET}
  sitecheck example.com
  dns-ssl-utilities.sh site check example.com
  dns-ssl-utilities.sh site redirects http://example.com
EOF_HELP
}


_dsu_site_leaf_help() {
  case "${1,,}" in
    check|c|full) cat <<EOF
${DSU_BOLD}site check${DSU_RESET} — combined domain/site diagnostics
Usage: site check <domain>
Alias: site c
Includes DNS, DNSSEC, mail policy, hosting/provider, WHOIS, TLS, HTTP headers,
redirects and IPv4/IPv6 PTR results.
EOF
      ;;
    headers|header|h) printf '%b\n' "${DSU_BOLD}site headers${DSU_RESET} — Usage: site headers <domain-or-url>  (alias: site h)" ;;
    redirects|redirect|r) printf '%b\n' "${DSU_BOLD}site redirects${DSU_RESET} — Usage: site redirects <domain-or-url>  (alias: site r)" ;;
    status|s) printf '%b\n' "${DSU_BOLD}site status${DSU_RESET} — Usage: site status <domain>  (alias: site s)" ;;
    *) _dsu_site_usage ;;
  esac
}

dsu_site_check() {
  local input="${1:-}" host a aaaa cname ns mx spf dmarc caa provider http_code https_code http_loc headers server powered hsts csp tmp cert_end days registrar expiry
  [[ -n "$input" ]] || { dsu_bad "Usage: site check <domain>"; return 2; }
  dsu_need dig dnsutils || return
  dsu_need curl curl || return
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }

  dsu_banner
  printf '\n%s%sTarget:%s %s%s%s\n' "$DSU_BOLD" "$DSU_WHITE" "$DSU_RESET" "$DSU_CYAN" "$host" "$DSU_RESET"

  dsu_section "DNS"
  a=$(_dsu_dig_lines A "$host" | paste -sd ', ' -)
  aaaa=$(_dsu_dig_lines AAAA "$host" | paste -sd ', ' -)
  cname=$(_dsu_dig_lines CNAME "$host" | paste -sd ', ' -)
  ns=$(_dsu_dig_lines NS "$host" | paste -sd ', ' -)
  mx=$(_dsu_dig_lines MX "$host" | sort -n | paste -sd ', ' -)
  [[ -n "$a" ]] && dsu_ok "A: $a" || dsu_warn "No A record"
  [[ -n "$aaaa" ]] && dsu_ok "AAAA: $aaaa" || dsu_info "No AAAA record"
  [[ -n "$cname" ]] && dsu_info "CNAME: $cname"
  [[ -n "$ns" ]] && dsu_ok "NS: $ns" || dsu_bad "No NS records returned"
  [[ -n "$mx" ]] && dsu_ok "MX: $mx" || dsu_info "No MX records"
  if dig A "$host" +dnssec 2>/dev/null | grep -q 'flags:.* ad[; ]'; then dsu_ok "DNSSEC validated by resolver (AD flag)"; elif [[ -n "$(_dsu_dig_lines DNSKEY "$host")" ]]; then dsu_warn "DNSKEY present, but AD validation not observed"; else dsu_info "DNSSEC not detected"; fi

  dsu_section "Mail + certificate policy"
  spf=$(_dsu_dig_lines TXT "$host" | tr -d '"' | grep -i '^v=spf1' | head -1)
  dmarc=$(_dsu_dig_lines TXT "_dmarc.$host" | tr -d '"' | grep -i '^v=DMARC1' | head -1)
  caa=$(_dsu_dig_lines CAA "$host" | paste -sd ', ' -)
  [[ -n "$spf" ]] && dsu_ok "SPF: $spf" || dsu_warn "SPF missing"
  [[ -n "$dmarc" ]] && dsu_ok "DMARC: $dmarc" || dsu_warn "DMARC missing"
  [[ -n "$caa" ]] && dsu_ok "CAA: $caa" || dsu_warn "CAA missing"

  dsu_section "Hosting + registration"
  if dsu_has python3; then
    provider=$(python3 "$DSU_HOME/helpers/hosting_provider.py" "$host" --plain 2>/dev/null || true)
    [[ -n "$provider" && "$provider" != "Unknown" ]] && dsu_keyval "Provider guess" "$provider" || dsu_keyval "Provider guess" "Unknown"
  fi
  if dsu_has whois; then
    local whois_data
    whois_data=$(_dsu_whois_best "$host")
    registrar=$(printf '%s\n' "$whois_data" | grep -iE '^(Registrar|registrar-name|Registrar Name):' | head -1 | sed 's/^[^:]*:[[:space:]]*//')
    expiry=$(printf '%s\n' "$whois_data" | grep -iE '^(Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|paid-till):' | head -1 | sed 's/^[^:]*:[[:space:]]*//')
    [[ -n "$registrar" ]] && dsu_keyval "Registrar" "$registrar"
    [[ -n "$expiry" ]] && dsu_keyval "Registration expiry" "$expiry"
  else
    dsu_info "whois not installed; registration summary skipped"
  fi

  dsu_section "TLS"
  tmp=$(dsu_tmpdir) || return 1
  if dsu_fetch_leaf_cert "$host" 443 "$tmp/cert.pem"; then
    cert_end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate | cut -d= -f2-)
    days=$(dsu_days_until "$cert_end" 2>/dev/null || printf '?')
    if openssl x509 -in "$tmp/cert.pem" -noout -checkhost "$host" >/dev/null 2>&1; then dsu_ok "Certificate hostname match"; else dsu_bad "Certificate hostname mismatch"; fi
    if [[ "$days" =~ ^-?[0-9]+$ ]]; then
      if (( days < 0 )); then dsu_bad "Certificate expired: $cert_end"; elif (( days < 30 )); then dsu_warn "Certificate expires in $days days: $cert_end"; else dsu_ok "Certificate expires in $days days: $cert_end"; fi
    else dsu_keyval "Certificate expiry" "$cert_end"; fi
  else
    dsu_bad "No TLS certificate retrieved on port 443"
  fi
  dsu_cleanup_dir "$tmp"

  dsu_section "HTTP / HTTPS"
  http_code=$(dsu_http_status "http://$host/")
  https_code=$(dsu_http_status "https://$host/")
  dsu_keyval "HTTP" "$http_code"
  dsu_keyval "HTTPS" "$https_code"
  http_loc=$(dsu_header_value "$(dsu_http_headers "http://$host/")" location)
  if [[ "$http_loc" == https://* ]]; then dsu_ok "HTTP redirects to HTTPS → $http_loc"; else dsu_warn "HTTP does not clearly redirect to HTTPS${http_loc:+ → $http_loc}"; fi

  headers=$(dsu_http_final_headers "https://$host/")
  server=$(dsu_header_value "$headers" server)
  powered=$(dsu_header_value "$headers" x-powered-by)
  hsts=$(dsu_header_value "$headers" strict-transport-security)
  csp=$(dsu_header_value "$headers" content-security-policy)
  [[ -n "$hsts" ]] && dsu_ok "HSTS: $hsts" || dsu_warn "HSTS missing"
  [[ -n "$csp" ]] && dsu_ok "CSP present" || dsu_warn "Content-Security-Policy missing"
  [[ -n "$server" ]] && dsu_warn "Server header exposed: $server" || dsu_ok "Server header not exposed"
  [[ -n "$powered" ]] && dsu_warn "X-Powered-By exposed: $powered" || dsu_ok "X-Powered-By not exposed"

  dsu_section "Reverse DNS"
  local addresses ptr ip
  addresses="$( { _dsu_dig_lines A "$host"; _dsu_dig_lines AAAA "$host"; } | awk 'NF' | sort -u )"
  if [[ -n "$addresses" ]]; then
    while IFS= read -r ip; do
      ptr=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | paste -sd ', ' -)
      [[ -n "$ptr" ]] && dsu_ok "$ip → $ptr" || dsu_info "$ip → no PTR"
    done <<< "$addresses"
  else
    dsu_info "No address records to reverse-resolve"
  fi

  printf '\n%sTip:%s run %s%saudit %s%s for the web-security exposure audit.\n' "$DSU_GRAY" "$DSU_RESET" "$DSU_CYAN" "" "$host" "$DSU_RESET"
}

dsu_site_headers() {
  dsu_ssl_headers "$@"
}

dsu_site_redirects() {
  local input="${1:-}" url
  [[ -n "$input" ]] || { dsu_bad "Usage: site redirects <url-or-domain>"; return 2; }
  dsu_need curl curl || return
  url="$input"; [[ "$url" == http://* || "$url" == https://* ]] || url="http://$url"
  dsu_section "Redirect chain · $url"
  curl -ksS -o /dev/null -L --max-redirs 12 --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time 25 \
    -A "$DSU_USER_AGENT" -w '  %{http_code}  %{url_effective}\n  redirects: %{num_redirects}\n' "$url" -D - 2>/dev/null \
    | awk 'BEGIN{IGNORECASE=1} /^HTTP\// || /^location:/ || /^  [0-9][0-9][0-9]/ || /^  redirects:/'
}

dsu_site_status() {
  local input="${1:-}" host http https tmp end days
  [[ -n "$input" ]] || { dsu_bad "Usage: site status <domain>"; return 2; }
  host=$(dsu_normalize_host "$input")
  http=$(dsu_http_status "http://$host/")
  https=$(dsu_http_status "https://$host/")
  tmp=$(dsu_tmpdir) || return 1
  if dsu_fetch_leaf_cert "$host" 443 "$tmp/cert.pem"; then end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate | cut -d= -f2-); days=$(dsu_days_until "$end" 2>/dev/null || printf '?'); else days='no-cert'; fi
  dsu_cleanup_dir "$tmp"
  printf '%s%-35s%s HTTP=%s  HTTPS=%s  TLS=%s\n' "$DSU_CYAN" "$host" "$DSU_RESET" "$http" "$https" "$days"
}

dsu_site_dispatch() {
  local cmd="${1:-help}"; shift || true
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then _dsu_site_leaf_help "$cmd"; return 0; fi
  case "${cmd,,}" in
    help|--help|-h) _dsu_site_usage ;;
    check|c|full) dsu_site_check "$@" ;;
    headers|header|h) dsu_site_headers "$@" ;;
    redirects|redirect|r) dsu_site_redirects "$@" ;;
    status|s) dsu_site_status "$@" ;;
    *) dsu_bad "Unknown site command: $cmd"; printf '\n'; _dsu_site_usage; return 2 ;;
  esac
}
