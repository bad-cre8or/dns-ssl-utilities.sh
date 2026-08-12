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

_dsu_site_provider_guess() {
  local ip="${1:-}" cnames="${2,,}" ptrs="${3,,}"
  case "$cnames" in
    *squarespace.com*) printf 'Squarespace'; return ;;
    *shopify.com*) printf 'Shopify'; return ;;
    *wixdns.net*) printf 'Wix'; return ;;
    *hostinger*) printf 'Hostinger'; return ;;
    *webflow*) printf 'Webflow'; return ;;
    *pages.dev*) printf 'Cloudflare Pages'; return ;;
    *github.io*) printf 'GitHub Pages'; return ;;
    *netlify*) printf 'Netlify'; return ;;
    *vercel*) printf 'Vercel'; return ;;
    *azurewebsites.net*) printf 'Microsoft Azure App Service'; return ;;
    *cloudfront.net*) printf 'Amazon CloudFront'; return ;;
    *fastly.net*) printf 'Fastly'; return ;;
  esac
  if [[ "$ip" == "104.37.39.71" ]]; then printf 'SSL Redirect Proxy / default A record'; return; fi
  if [[ "$ip" =~ ^104\.(1[6-9]|2[0-3])\. ]]; then printf 'Cloudflare'; return; fi
  if [[ "$ip" =~ ^172\.(6[4-9]|7[01])\. ]]; then printf 'Cloudflare'; return; fi
  [[ "$ip" == 104.37.39.* ]] && { printf 'Digital Garden'; return; }
  [[ "$ip" == 195.47.247.* ]] && { printf 'One.com'; return; }
  case "$ptrs" in
    *tornado-node.net*|*tornado.no*) printf 'SYSE'; return ;;
    *proisp.no*) printf 'ProISP'; return ;;
    *webpod*) printf 'One.com / ProISP infrastructure'; return ;;
    *domeneshop.no*|*domainname.shop*) printf 'Domeneshop'; return ;;
  esac
  printf 'Unknown'
}

dsu_site_check() {
  local input="${1:-}" host tmp
  [[ -n "$input" ]] || { dsu_bad "Usage: site check <domain>"; return 2; }
  dsu_need dig dnsutils || return
  dsu_need curl curl || return
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }

  tmp=$(dsu_tmpdir) || return 1
  printf '\n%sTarget:%s %s%s%s\n' "$DSU_BOLD" "$DSU_RESET" "$DSU_CYAN" "$host" "$DSU_RESET"

  # Fan out independent network operations immediately. The results are still
  # printed in a stable human-friendly order, but network latency no longer stacks.
  local pid_a pid_aaaa pid_cname pid_www_cname pid_ns pid_mx pid_txt pid_dmarc pid_caa pid_dnskey pid_dnssec
  (_dsu_dig_lines A "$host") >"$tmp/a" & pid_a=$!
  (_dsu_dig_lines AAAA "$host") >"$tmp/aaaa" & pid_aaaa=$!
  (_dsu_dig_lines CNAME "$host") >"$tmp/cname" & pid_cname=$!
  (_dsu_dig_lines CNAME "www.$host") >"$tmp/www_cname" & pid_www_cname=$!
  (_dsu_dig_lines NS "$host") >"$tmp/ns" & pid_ns=$!
  (_dsu_dig_lines MX "$host") >"$tmp/mx" & pid_mx=$!
  (_dsu_dig_lines TXT "$host") >"$tmp/txt" & pid_txt=$!
  (_dsu_dig_lines TXT "_dmarc.$host") >"$tmp/dmarc" & pid_dmarc=$!
  (_dsu_dig_lines CAA "$host") >"$tmp/caa" & pid_caa=$!
  (_dsu_dig_lines DNSKEY "$host") >"$tmp/dnskey" & pid_dnskey=$!
  (dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" A "$host" +dnssec 2>/dev/null || true) >"$tmp/dnssec" & pid_dnssec=$!

  local pid_whois='' pid_tls pid_http pid_https
  if dsu_has whois; then
    (_dsu_whois_best "$host" || true) >"$tmp/whois" & pid_whois=$!
  fi
  (dsu_fetch_leaf_cert "$host" 443 "$tmp/cert.pem" || true) >/dev/null 2>&1 & pid_tls=$!
  (dsu_http_headers "http://$host/" || true) >"$tmp/http.headers" & pid_http=$!
  (dsu_http_final_headers "https://$host/" || true) >"$tmp/https.headers" & pid_https=$!

  local pid
  for pid in "$pid_a" "$pid_aaaa" "$pid_cname" "$pid_www_cname" "$pid_ns" "$pid_mx" "$pid_txt" "$pid_dmarc" "$pid_caa" "$pid_dnskey" "$pid_dnssec"; do
    wait "$pid" 2>/dev/null || true
  done

  local a aaaa cname provider_cnames ns mx spf dmarc caa
  a=$(cat "$tmp/a" 2>/dev/null || true)
  aaaa=$(cat "$tmp/aaaa" 2>/dev/null || true)
  cname=$(cat "$tmp/cname" 2>/dev/null || true)
  provider_cnames=$(cat "$tmp/cname" "$tmp/www_cname" 2>/dev/null | awk 'NF' | sort -u)
  ns=$(cat "$tmp/ns" 2>/dev/null || true)
  mx=$(sort -n "$tmp/mx" 2>/dev/null || true)
  spf=$(tr -d '"' <"$tmp/txt" | grep -i '^v=spf1' | head -1)
  dmarc=$(tr -d '"' <"$tmp/dmarc" | grep -i '^v=DMARC1' | head -1)
  caa=$(cat "$tmp/caa" 2>/dev/null || true)

  # Start PTR lookups as soon as address DNS is available; they run while the
  # human-readable DNS, mail, registration and TLS sections are being rendered.
  local addresses ip i=0
  local -a ptr_ips=() ptr_pids=()
  addresses="$(printf '%s\n%s\n' "$a" "$aaaa" | awk 'NF' | sort -u)"
  if [[ -n "$addresses" ]]; then
    while IFS= read -r ip; do
      [[ -n "$ip" ]] || continue
      ptr_ips+=("$ip"); ((i+=1))
      (_dsu_ptr_probe "$ip") >"$tmp/ptr.$i" &
      ptr_pids+=("$!")
    done <<< "$addresses"
  fi

  local registrar whois_data
  dsu_section "REGISTRAR"
  if [[ -n "$pid_whois" ]]; then
    wait "$pid_whois" 2>/dev/null || true
    whois_data=$(cat "$tmp/whois" 2>/dev/null || true)
    registrar=$(_dsu_whois_registrar "$whois_data" || true)
    if [[ -n "$registrar" ]]; then
      printf '  %s%s%s\n' "$DSU_BOLD" "$registrar" "$DSU_RESET"
    elif [[ -n "$whois_data" ]]; then
      dsu_warn "Registrar not identified in WHOIS response"
    else
      dsu_warn "WHOIS returned no registration data"
    fi
  else
    dsu_warn "Registrar unavailable (install the 'whois' package)"
  fi

  dsu_section "DNS"
  [[ -n "$a" ]] && dsu_ok "A: $(printf '%s\n' "$a" | paste -sd ', ' -)" || dsu_warn "No A record"
  [[ -n "$aaaa" ]] && dsu_ok "AAAA: $(printf '%s\n' "$aaaa" | paste -sd ', ' -)" || dsu_info "No AAAA record"
  [[ -n "$cname" ]] && dsu_info "CNAME: $(printf '%s\n' "$cname" | paste -sd ', ' -)"
  [[ -n "$ns" ]] && dsu_ok "NS: $(printf '%s\n' "$ns" | paste -sd ', ' -)" || dsu_bad "No NS records returned"
  [[ -n "$mx" ]] && dsu_ok "MX: $(printf '%s\n' "$mx" | paste -sd ', ' -)" || dsu_info "No MX records"
  if grep -q 'flags:.* ad[; ]' "$tmp/dnssec" 2>/dev/null; then
    dsu_ok "DNSSEC validated by resolver (AD flag)"
  elif [[ -s "$tmp/dnskey" ]]; then
    dsu_warn "DNSKEY present, but AD validation not observed"
  else
    dsu_bad "DNSSEC not detected"
  fi

  dsu_section "MAIL & SECURITY POLICY"
  [[ -n "$spf" ]] && dsu_ok "SPF: $spf" || dsu_warn "SPF missing"
  [[ -n "$dmarc" ]] && dsu_ok "DMARC: $dmarc" || dsu_warn "DMARC missing"
  [[ -n "$caa" ]] && dsu_ok "CAA: $(printf '%s\n' "$caa" | paste -sd ', ' -)" || dsu_warn "CAA missing"

  dsu_section "HOSTING"
  local provider first_ip ptr_blob
  for pid in "${ptr_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  first_ip=$(printf '%s\n%s\n' "$a" "$aaaa" | awk 'NF {print; exit}')
  ptr_blob=$(cat "$tmp"/ptr.* 2>/dev/null | awk -F '\t' '$1=="OK" {print $2}' | paste -sd ' ' -)
  provider=$(_dsu_site_provider_guess "$first_ip" "$provider_cnames" "$ptr_blob")
  if [[ "$provider" == "Unknown" ]]; then
    dsu_warn "Guessing: Unknown"
  else
    dsu_keyval "Guessing" "$provider"
  fi

  dsu_section "TLS"
  wait "$pid_tls" 2>/dev/null || true
  local cert_end days
  if [[ -s "$tmp/cert.pem" ]]; then
    cert_end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2-)
    days=$(dsu_days_until "$cert_end" 2>/dev/null || printf '?')
    if openssl x509 -in "$tmp/cert.pem" -noout -checkhost "$host" >/dev/null 2>&1; then dsu_ok "Certificate hostname match"; else dsu_bad "Certificate hostname mismatch"; fi
    if [[ "$days" =~ ^-?[0-9]+$ ]]; then
      if (( days < 0 )); then dsu_bad "Certificate expired: $cert_end"; elif (( days < 30 )); then dsu_warn "Certificate expires in $days days: $cert_end"; else dsu_ok "Certificate expires in $days days: $cert_end"; fi
    else
      dsu_keyval "Certificate expiry" "$cert_end"
    fi
  else
    dsu_bad "No TLS certificate retrieved on port 443"
  fi

  dsu_section "HTTP / HTTPS"
  wait "$pid_http" 2>/dev/null || true
  wait "$pid_https" 2>/dev/null || true
  local http_headers https_headers http_code https_code http_loc server powered hsts csp
  http_headers=$(cat "$tmp/http.headers" 2>/dev/null || true)
  https_headers=$(cat "$tmp/https.headers" 2>/dev/null || true)
  http_code=$(dsu_http_code_from_headers "$http_headers")
  https_code=$(dsu_http_code_from_headers "$https_headers")
  dsu_keyval "HTTP" "$http_code"
  dsu_keyval "HTTPS" "$https_code"
  http_loc=$(dsu_header_value "$http_headers" location)
  if [[ "$http_loc" == https://* ]]; then dsu_ok "HTTP redirects to HTTPS → $http_loc"; else dsu_warn "HTTP does not clearly redirect to HTTPS${http_loc:+ → $http_loc}"; fi
  server=$(dsu_header_value "$https_headers" server)
  powered=$(dsu_header_value "$https_headers" x-powered-by)
  hsts=$(dsu_header_value "$https_headers" strict-transport-security)
  csp=$(dsu_header_value "$https_headers" content-security-policy)
  [[ -n "$hsts" ]] && dsu_ok "HSTS: $hsts" || dsu_warn "HSTS missing"
  [[ -n "$csp" ]] && dsu_ok "CSP present" || dsu_warn "Content-Security-Policy missing"
  [[ -n "$server" ]] && dsu_warn "Server header exposed: $server" || dsu_ok "Server header not exposed"
  [[ -n "$powered" ]] && dsu_warn "X-Powered-By exposed: $powered" || dsu_ok "X-Powered-By not exposed"

  dsu_section "REVERSE DNS"
  if (( ${#ptr_ips[@]} )); then
    i=0
    for ip in "${ptr_ips[@]}"; do
      ((i+=1))
      local ptr ptr_state ptr_value
      ptr=$(cat "$tmp/ptr.$i" 2>/dev/null || true)
      ptr_state=${ptr%%$'\t'*}
      ptr_value=${ptr#*$'\t'}
      case "$ptr_state" in
        OK) dsu_ok "$ip → $ptr_value" ;;
        NONE) dsu_info "$ip → no PTR" ;;
        ERROR) dsu_bad "$ip → PTR lookup failed ($ptr_value)" ;;
        *) dsu_bad "$ip → PTR lookup failed (unrecognized resolver response)" ;;
      esac
    done
  else
    dsu_info "No address records to reverse-resolve"
  fi

  printf '\n%sTip:%s run %s%saudit %s%s for the web-security exposure audit.\n' "$DSU_GRAY" "$DSU_RESET" "$DSU_CYAN" "" "$host" "$DSU_RESET"
  dsu_cleanup_dir "$tmp"
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
  local input="${1:-}" host tmp end days pid_http pid_https pid_tls http https
  [[ -n "$input" ]] || { dsu_bad "Usage: site status <domain>"; return 2; }
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
  tmp=$(dsu_tmpdir) || return 1

  (dsu_http_status "http://$host/" || true) >"$tmp/http" & pid_http=$!
  (dsu_http_status "https://$host/" || true) >"$tmp/https" & pid_https=$!
  (dsu_fetch_leaf_cert "$host" 443 "$tmp/cert.pem" || true) >/dev/null 2>&1 & pid_tls=$!
  wait "$pid_http" 2>/dev/null || true
  wait "$pid_https" 2>/dev/null || true
  wait "$pid_tls" 2>/dev/null || true

  http=$(cat "$tmp/http" 2>/dev/null || printf '000')
  https=$(cat "$tmp/https" 2>/dev/null || printf '000')
  if [[ -s "$tmp/cert.pem" ]]; then
    end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2-)
    days=$(dsu_days_until "$end" 2>/dev/null || printf '?')
  else
    days='no-cert'
  fi
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
