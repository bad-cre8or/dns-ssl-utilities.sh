#!/usr/bin/env bash

_dsu_site_usage() {
  cat <<EOF_HELP
${DSU_BOLD}${DSU_CYAN}Website diagnostics${DSU_RESET}

The primary site overview is simply:
  ${DSU_GREEN}check <domain> [--no-rdns]${DSU_RESET}

Additional site commands:
  ${DSU_GREEN}check site headers${DSU_RESET} <domain-or-url>
  ${DSU_GREEN}check site redirects${DSU_RESET} <domain-or-url>
  ${DSU_GREEN}check site status${DSU_RESET} <domain>

Compatibility frontend:
  ${DSU_GREEN}sitecheck${DSU_RESET} <domain>
  ${DSU_GREEN}sitecheck${DSU_RESET} <headers|redirects|status> ...

${DSU_BOLD}Examples${DSU_RESET}
  ${DSU_CYAN}check example.com${DSU_RESET}
  ${DSU_CYAN}check example.com --no-rdns${DSU_RESET}
  ${DSU_CYAN}check site headers example.com${DSU_RESET}
  ${DSU_CYAN}check site redirects http://example.com${DSU_RESET}
EOF_HELP
}

_dsu_site_leaf_help() {
  case "${1,,}" in
    check|c|full) cat <<EOF
${DSU_BOLD}Fast domain overview${DSU_RESET}
Usage: check <domain> [--no-rdns]

Reports registrar, useful DNS records, DNSSEC, SPF/DMARC/CAA, hosting/provider
signals, TLS certificate health, HTTP/HTTPS posture and PTR results.
It does not run the vulnerability audit or heavyweight TLS scans.

Options:
  --no-rdns  Skip PTR lookups for the lowest possible latency
EOF
      ;;
    headers|header|h) printf '%b\n' "${DSU_BOLD}Site headers${DSU_RESET}\nUsage: check site headers <domain-or-url>\nShortcut: sitecheck headers <domain-or-url>" ;;
    redirects|redirect|r) printf '%b\n' "${DSU_BOLD}Redirect chain${DSU_RESET}\nUsage: check site redirects <domain-or-url>\nShortcut: sitecheck redirects <domain-or-url>" ;;
    status|s) printf '%b\n' "${DSU_BOLD}Site status${DSU_RESET}\nUsage: check site status <domain>\nShortcut: sitecheck status <domain>" ;;
    *) _dsu_site_usage ;;
  esac
}

_dsu_site_print_records() {
  local level="$1" label="$2" data="$3" line
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    case "$level" in
      ok) dsu_ok "$label: $line" ;;
      info) dsu_info "$label: $line" ;;
      warn) dsu_warn "$label: $line" ;;
      bad) dsu_bad "$label: $line" ;;
    esac
  done <<<"$data"
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
    *googlehosted.com*|*appspot.com*|*firebaseapp.com*) printf 'Google Cloud'; return ;;
    *wpenginepowered.com*) printf 'WP Engine'; return ;;
    *pantheonsite.io*) printf 'Pantheon'; return ;;
    *herokudns.com*) printf 'Heroku'; return ;;
    *render.com*) printf 'Render'; return ;;
    *fly.dev*) printf 'Fly.io'; return ;;
  esac
  if [[ "$ip" == "104.37.39.71" ]]; then printf 'SSL Redirect Proxy / default A record'; return; fi
  if [[ "$ip" =~ ^104\.(1[6-9]|2[0-3])\. ]]; then printf 'Cloudflare'; return; fi
  if [[ "$ip" =~ ^172\.(6[4-9]|7[01])\. ]]; then printf 'Cloudflare'; return; fi
  [[ "$ip" == 104.37.39.* ]] && { printf 'Digital Garden'; return; }
  [[ "$ip" == 195.47.247.* ]] && { printf 'One.com'; return; }
  case "$ptrs" in
    *1e100.net*|*googleusercontent.com*) printf 'Google'; return ;;
    *amazonaws.com*) printf 'Amazon Web Services'; return ;;
    *azure.com*|*cloudapp.net*) printf 'Microsoft Azure'; return ;;
    *akamai*|*edgekey.net*|*edgesuite.net*) printf 'Akamai'; return ;;
    *digitalocean.com*) printf 'DigitalOcean'; return ;;
    *your-server.de*|*hetzner*) printf 'Hetzner'; return ;;
    *ovh.net*) printf 'OVHcloud'; return ;;
    *vultrusercontent.com*) printf 'Vultr'; return ;;
    *leaseweb*) printf 'Leaseweb'; return ;;
    *tornado-node.net*|*tornado.no*) printf 'SYSE'; return ;;
    *proisp.no*) printf 'ProISP'; return ;;
    *webpod*) printf 'One.com / ProISP infrastructure'; return ;;
    *domeneshop.no*|*domainname.shop*) printf 'Domeneshop'; return ;;
  esac
  printf 'Unknown'
}

_dsu_site_registrar_probe() {
  local host="$1"
  local main_domain whois_cache registrar_result rc

  if ! dsu_has whois; then
    printf 'ERROR\twhois not installed\n'
    return 0
  fi

  # Use the registrar path preserved verbatim from check.zip in lib/dns.sh.
  main_domain=$(_dsu_registrar_whois_domain "$host")
  whois_cache=$(timeout "$DSU_CHECK_WHOIS_TIMEOUT" whois "$main_domain" 2>/dev/null)
  rc=$?
  registrar_result=$(_dsu_registrar_from_whois "$whois_cache" || true)

  if [[ -n "$registrar_result" ]]; then
    printf 'OK\t%s\n' "$registrar_result"
  elif (( rc == 124 )); then
    printf 'ERROR\tWHOIS timed out after %ss\n' "$DSU_CHECK_WHOIS_TIMEOUT"
  elif [[ -z "$whois_cache" ]]; then
    printf 'ERROR\tWHOIS returned no data for %s\n' "$main_domain"
  else
    printf 'NONE\tNo registrar information found for %s\n' "$main_domain"
  fi
}

_dsu_site_curl_probe() {
  local scheme="$1" host="$2" prefix="$3"
  local writeout=$'code=%{http_code}\nurl=%{url_effective}\n'
  if [[ "$scheme" == https ]]; then
    # Reuse the HTTPS transfer for leaf-certificate data. No second TLS handshake
    # is needed on modern curl builds; older builds fall back to OpenSSL below.
    writeout+=$'certs_begin\n%{certs}\ncerts_end\n'
  fi
  curl -ksS -D "$prefix.headers" -o /dev/null \
    --connect-timeout "$DSU_CHECK_CONNECT_TIMEOUT" --max-time "$DSU_CHECK_MAX_TIME" \
    -A "$DSU_USER_AGENT" -w "$writeout" "$scheme://$host/" \
    >"$prefix.meta" 2>"$prefix.err"
}

_dsu_site_meta_value() {
  local file="$1" key="$2"
  sed -n "s/^${key}=//p" "$file" 2>/dev/null | tail -1
}

_dsu_site_extract_leaf_cert() {
  local meta="$1" out="$2"
  awk '
    /^-----BEGIN CERTIFICATE-----$/ { capture=1 }
    capture { print }
    /^-----END CERTIFICATE-----$/ && capture { exit }
  ' "$meta" >"$out" 2>/dev/null || true
  [[ -s "$out" ]]
}

_dsu_site_fetch_leaf_fallback() {
  local host="$1" out="$2"
  timeout "$DSU_CHECK_MAX_TIME" openssl s_client -servername "$host" -connect "$host:443" </dev/null 2>/dev/null \
    | openssl x509 -outform PEM >"$out" 2>/dev/null
  [[ -s "$out" ]]
}

_dsu_site_print_http_code() {
  local label="$1" code="$2"
  if [[ -n "$code" && "$code" != 000 ]]; then
    dsu_keyval "$label" "$code"
  else
    dsu_bad "$label unavailable"
  fi
}

dsu_site_check() {
  local input="${1:-}" host tmp no_rdns=0
  [[ -n "$input" ]] || { dsu_bad "Usage: check <domain> [--no-rdns]"; return 2; }
  shift || true
  while (( $# )); do
    case "$1" in
      --no-rdns|--no-ptr) no_rdns=1 ;;
      --fresh) ;; # accepted for backward compatibility; registrar data is no longer cached
      -h|--help) _dsu_site_leaf_help check; return 0 ;;
      *) dsu_bad "Unknown check option: $1"; return 2 ;;
    esac
    shift
  done

  dsu_need dig dnsutils || return
  dsu_need curl curl || return
  dsu_need openssl openssl || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
  tmp=$(dsu_tmpdir) || return 1

  # Fast path: the independent network probes all launch together. There is no
  # banner, target echo, spinner, redirect crawl or audit work in this command.
  local pid_a pid_aaaa pid_cname pid_www_cname pid_ns pid_mx pid_txt pid_dmarc pid_caa pid_dnskey pid_dnssec
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines A "$host") >"$tmp/a" & pid_a=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines AAAA "$host") >"$tmp/aaaa" & pid_aaaa=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines CNAME "$host") >"$tmp/cname" & pid_cname=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines CNAME "www.$host") >"$tmp/www_cname" & pid_www_cname=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines NS "$host") >"$tmp/ns" & pid_ns=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines MX "$host") >"$tmp/mx" & pid_mx=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines TXT "$host") >"$tmp/txt" & pid_txt=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines TXT "_dmarc.$host") >"$tmp/dmarc" & pid_dmarc=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines CAA "$host") >"$tmp/caa" & pid_caa=$!
  (DSU_DNS_TIMEOUT="$DSU_CHECK_DNS_TIMEOUT" _dsu_dig_lines DNSKEY "$host") >"$tmp/dnskey" & pid_dnskey=$!
  (dig +time="$DSU_CHECK_DNS_TIMEOUT" +tries=1 A "$host" +dnssec 2>/dev/null || true) >"$tmp/dnssec" & pid_dnssec=$!

  local pid_whois pid_http pid_https
  (_dsu_site_registrar_probe "$host") >"$tmp/registrar" & pid_whois=$!
  (_dsu_site_curl_probe http "$host" "$tmp/http" || true) & pid_http=$!
  (_dsu_site_curl_probe https "$host" "$tmp/https" || true) & pid_https=$!

  # A/AAAA finish quickly and immediately unlock parallel PTR work.
  wait "$pid_a" 2>/dev/null || true
  wait "$pid_aaaa" 2>/dev/null || true
  local a aaaa addresses ip i=0
  local -a ptr_ips=() ptr_pids=()
  a=$(cat "$tmp/a" 2>/dev/null || true)
  aaaa=$(cat "$tmp/aaaa" 2>/dev/null || true)
  if (( ! no_rdns )); then
    addresses="$(printf '%s\n%s\n' "$a" "$aaaa" | awk 'NF' | sort -u)"
    if [[ -n "$addresses" ]]; then
      while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        ptr_ips+=("$ip"); ((i+=1))
        (_dsu_ptr_probe "$ip" "$DSU_CHECK_PTR_TIMEOUT" 1) >"$tmp/ptr.$i" &
        ptr_pids+=("$!")
      done <<< "$addresses"
    fi
  fi

  dsu_section "REGISTRAR"
  wait "$pid_whois" 2>/dev/null || true
  local registrar_result registrar_state registrar_value
  registrar_result=$(cat "$tmp/registrar" 2>/dev/null || true)
  registrar_state=${registrar_result%%$'\t'*}
  registrar_value=${registrar_result#*$'\t'}
  case "$registrar_state" in
    OK) printf '  %s%s%s\n' "$DSU_BOLD" "$registrar_value" "$DSU_RESET" ;;
    NONE|ERROR) dsu_warn "$registrar_value" ;;
    *) dsu_warn "Registrar unavailable" ;;
  esac

  local pid
  for pid in "$pid_cname" "$pid_www_cname" "$pid_ns" "$pid_mx" "$pid_txt" "$pid_dmarc" "$pid_caa" "$pid_dnskey" "$pid_dnssec"; do
    wait "$pid" 2>/dev/null || true
  done

  local cname provider_cnames ns mx spf dmarc caa
  cname=$(cat "$tmp/cname" 2>/dev/null || true)
  provider_cnames=$(cat "$tmp/cname" "$tmp/www_cname" 2>/dev/null | awk 'NF' | sort -u)
  ns=$(cat "$tmp/ns" 2>/dev/null || true)
  mx=$(sort -n "$tmp/mx" 2>/dev/null || true)
  spf=$(tr -d '"' <"$tmp/txt" | grep -i '^v=spf1' | head -1)
  dmarc=$(tr -d '"' <"$tmp/dmarc" | grep -i '^v=DMARC1' | head -1)
  caa=$(cat "$tmp/caa" 2>/dev/null || true)

  dsu_section "DNS"
  if [[ -n "$a" ]]; then
    _dsu_site_print_records ok "A" "$a"
  else
    dsu_warn "No A record"
  fi
  if [[ -n "$aaaa" ]]; then
    _dsu_site_print_records ok "AAAA" "$aaaa"
  else
    dsu_info "No AAAA record"
  fi
  [[ -n "$cname" ]] && _dsu_site_print_records info "CNAME" "$cname"
  if [[ -n "$ns" ]]; then
    _dsu_site_print_records ok "NS" "$ns"
  else
    dsu_bad "No NS records returned"
  fi
  if grep -q 'flags:.* ad[; ]' "$tmp/dnssec" 2>/dev/null; then
    dsu_ok "DNSSEC validated"
  elif [[ -s "$tmp/dnskey" ]]; then
    dsu_warn "DNSSEC signed, validation not observed"
  else
    dsu_bad "DNSSEC not detected"
  fi

  dsu_section "MAIL & SECURITY POLICY"
  if [[ -n "$mx" ]]; then
    _dsu_site_print_records ok "MX" "$mx"
  else
    dsu_info "No MX records"
  fi
  [[ -n "$spf" ]] && dsu_ok "SPF: $spf" || dsu_warn "SPF missing"
  [[ -n "$dmarc" ]] && dsu_ok "DMARC: $dmarc" || dsu_warn "DMARC missing"
  if [[ -n "$caa" ]]; then
    _dsu_site_print_records ok "CAA" "$caa"
  else
    dsu_warn "CAA missing"
  fi

  local provider first_ip ptr_blob=''
  first_ip=$(printf '%s\n%s\n' "$a" "$aaaa" | awk 'NF {print; exit}')
  # Do not let a slow/broken reverse resolver hold the whole report hostage.
  # Most CDN/platform guesses resolve from A/CNAME immediately. PTR is consulted
  # only when those cheap signals were insufficient.
  provider=$(_dsu_site_provider_guess "$first_ip" "$provider_cnames" '')
  if [[ "$provider" == Unknown && ${#ptr_pids[@]} -gt 0 ]]; then
    for pid in "${ptr_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    ptr_blob=$(cat "$tmp"/ptr.* 2>/dev/null | awk -F '\t' '$1=="OK" {print $2}' | paste -sd ' ' -)
    provider=$(_dsu_site_provider_guess "$first_ip" "$provider_cnames" "$ptr_blob")
  fi
  dsu_section "HOSTING"
  if [[ "$provider" == Unknown ]]; then
    dsu_warn "Guessing: Unknown"
  else
    printf '  %sGuessing:%s  %s\n' "$DSU_GRAY" "$DSU_RESET" "$provider"
  fi

  wait "$pid_https" 2>/dev/null || true
  local cert_end days
  _dsu_site_extract_leaf_cert "$tmp/https.meta" "$tmp/cert.pem" || true
  if [[ ! -s "$tmp/cert.pem" ]]; then
    _dsu_site_fetch_leaf_fallback "$host" "$tmp/cert.pem" || true
  fi

  dsu_section "TLS"
  if [[ -s "$tmp/cert.pem" ]]; then
    cert_end=$(openssl x509 -in "$tmp/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2-)
    days=$(dsu_days_until "$cert_end" 2>/dev/null || printf '?')
    if openssl x509 -in "$tmp/cert.pem" -noout -checkhost "$host" >/dev/null 2>&1; then
      dsu_ok "Certificate hostname match"
    else
      dsu_bad "Certificate hostname mismatch"
    fi
    if [[ "$days" =~ ^-?[0-9]+$ ]]; then
      if (( days < 0 )); then
        dsu_bad "Certificate expired: $cert_end"
      elif (( days < 30 )); then
        dsu_warn "Certificate expires in $days days: $cert_end"
      else
        dsu_ok "Certificate expires in $days days: $cert_end"
      fi
    elif [[ -n "$cert_end" ]]; then
      dsu_keyval "Certificate expiry" "$cert_end"
    fi
  else
    dsu_bad "No TLS certificate retrieved on port 443"
  fi

  wait "$pid_http" 2>/dev/null || true
  local http_code https_code http_headers https_headers http_loc https_loc server powered hsts csp
  http_code=$(_dsu_site_meta_value "$tmp/http.meta" code)
  https_code=$(_dsu_site_meta_value "$tmp/https.meta" code)
  http_headers=$(cat "$tmp/http.headers" 2>/dev/null || true)
  https_headers=$(cat "$tmp/https.headers" 2>/dev/null || true)

  dsu_section "HTTP / HTTPS"
  _dsu_site_print_http_code "HTTP" "${http_code:-000}"
  _dsu_site_print_http_code "HTTPS" "${https_code:-000}"
  http_loc=$(dsu_header_value "$http_headers" location)
  https_loc=$(dsu_header_value "$https_headers" location)
  if [[ "$http_loc" == https://* ]]; then
    dsu_ok "HTTP redirects to HTTPS → $http_loc"
  elif [[ "$http_code" =~ ^30[12378]$ && -n "$http_loc" ]]; then
    dsu_warn "HTTP redirects, but not clearly to HTTPS → $http_loc"
  elif [[ "$http_code" != 000 ]]; then
    dsu_warn "HTTP does not redirect to HTTPS${http_loc:+ → $http_loc}"
  fi
  [[ "$https_code" =~ ^30[12378]$ && -n "$https_loc" ]] && dsu_info "HTTPS redirect → $https_loc"

  server=$(dsu_header_value "$https_headers" server)
  powered=$(dsu_header_value "$https_headers" x-powered-by)
  hsts=$(dsu_header_value "$https_headers" strict-transport-security)
  csp=$(dsu_header_value "$https_headers" content-security-policy)
  [[ -n "$hsts" ]] && dsu_ok "HSTS: $hsts" || dsu_warn "HSTS missing"
  [[ -n "$csp" ]] && dsu_ok "Content-Security-Policy present" || dsu_warn "Content-Security-Policy missing"
  [[ -n "$server" ]] && dsu_warn "Server header exposed: $server" || dsu_ok "Server header not exposed"
  [[ -n "$powered" ]] && dsu_warn "X-Powered-By exposed: $powered" || dsu_ok "X-Powered-By not exposed"

  if (( ! no_rdns )); then
    for pid in "${ptr_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
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
  fi

  dsu_cleanup_dir "$tmp"
}

dsu_site_headers() {
  dsu_ssl_headers "$@"
}

dsu_site_redirects() {
  local input="${1:-}" url
  [[ -n "$input" ]] || { dsu_bad "Usage: check site redirects <url-or-domain>"; return 2; }
  dsu_need curl curl || return
  url="$input"; [[ "$url" == http://* || "$url" == https://* ]] || url="http://$url"
  dsu_section "Redirect chain · $url"
  curl -ksS -o /dev/null -L --max-redirs 12 --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time 25 \
    -A "$DSU_USER_AGENT" -w '  %{http_code}  %{url_effective}\n  redirects: %{num_redirects}\n' "$url" -D - 2>/dev/null \
    | awk 'BEGIN{IGNORECASE=1} /^HTTP\// || /^location:/ || /^  [0-9][0-9][0-9]/ || /^  redirects:/'
}

dsu_site_status() {
  local input="${1:-}" host tmp end days pid_http pid_https pid_tls http https
  [[ -n "$input" ]] || { dsu_bad "Usage: check site status <domain>"; return 2; }
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
