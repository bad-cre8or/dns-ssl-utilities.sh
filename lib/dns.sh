#!/usr/bin/env bash

# shellcheck source=lib/core.sh

_dsu_dns_usage() {
  cat <<EOF_HELP
${DSU_BOLD}${DSU_CYAN}DNS commands${DSU_RESET}

${DSU_BOLD}Usage:${DSU_RESET}
  dns-ssl-utilities.sh dns <command> [arguments]
  dnsutil <command> [arguments]              ${DSU_GRAY}# after setup.sh${DSU_RESET}

${DSU_GREEN}lookup, l${DSU_RESET}      Show A/AAAA/MX/NS/TXT/CAA/SOA records
${DSU_GREEN}reverse, ptr, r${DSU_RESET} Reverse DNS for a host or IP
${DSU_GREEN}mail, m${DSU_RESET}        SPF, DMARC, DKIM-selector and mail-policy checks
${DSU_GREEN}dnssec, ds${DSU_RESET}     Inspect DNSSEC records and resolver validation
${DSU_GREEN}trace, t${DSU_RESET}       Run a DNS delegation trace
${DSU_GREEN}whois, w${DSU_RESET}       WHOIS summary for a domain
${DSU_GREEN}hosting, host, h${DSU_RESET} Best-effort hosting/provider identification

${DSU_BLUE}Examples${DSU_RESET}
  dns-ssl-utilities.sh dns lookup example.com
  dns-ssl-utilities.sh dns l example.com A
  dnsutil ptr 203.0.113.20
  dnsutil mail example.com selector1
  dnsutil dnssec example.com
EOF_HELP
}


_dsu_dns_leaf_help() {
  case "${1,,}" in
    lookup|look|resolve|records|l) _dsu_dns_lookup_help ;;
    reverse|ptr|rdns|r) cat <<EOF
${DSU_BOLD}dns reverse${DSU_RESET} — PTR lookup
Usage: dns reverse <domain-or-ip>
Aliases: dns ptr, dns rdns, dns r
A domain expands to all A and AAAA addresses before PTR lookup.
EOF
      ;;
    mail|email|m) cat <<EOF
${DSU_BOLD}dns mail${DSU_RESET} — mail/authentication DNS posture
Usage: dns mail <domain> [dkim-selector]
Alias: dns m
Checks SPF, DMARC, CAA, MTA-STS, TLS-RPT and either a supplied DKIM selector
or a curated set of common selectors.
EOF
      ;;
    dnssec|ds) printf '%b\n' "${DSU_BOLD}dns dnssec${DSU_RESET} — Usage: dns dnssec <domain>  (alias: dns ds)" ;;
    trace|t) printf '%b\n' "${DSU_BOLD}dns trace${DSU_RESET} — Usage: dns trace <domain>  (alias: dns t)" ;;
    whois|w) printf '%b\n' "${DSU_BOLD}dns whois${DSU_RESET} — Usage: dns whois <domain>  (alias: dns w)" ;;
    hosting|host|provider|h) printf '%b\n' "${DSU_BOLD}dns hosting${DSU_RESET} — Usage: dns hosting <domain>  (alias: dns h)" ;;
    *) _dsu_dns_usage ;;
  esac
}

_dsu_dns_lookup_help() {
  cat <<EOF_HELP
${DSU_BOLD}dns lookup${DSU_RESET} — resolve useful DNS records

Usage: dns lookup <domain> [TYPE]
Aliases: dns l

TYPE may be A, AAAA, MX, NS, TXT, CAA, SOA, CNAME, SRV, DS, DNSKEY or ALL.
When omitted, a curated multi-record summary is shown.
EOF_HELP
}

_dsu_dig_lines() {
  local type="$1" name="$2"
  dig +short "$type" "$name" 2>/dev/null | sed 's/\.$//'
}

_dsu_print_rr() {
  local type="$1" name="$2" result
  result=$(_dsu_dig_lines "$type" "$name")
  if [[ -n "$result" ]]; then
    while IFS= read -r line; do dsu_keyval "$type" "$line"; done <<< "$result"
  else
    dsu_keyval "$type" "${DSU_GRAY}—${DSU_RESET}"
  fi
}

dsu_dns_lookup() {
  local input="${1:-}" type="${2:-ALL}" host
  [[ "$input" == "--help" || "$input" == "-h" ]] && { _dsu_dns_lookup_help; return 0; }
  [[ -n "$input" ]] || { _dsu_dns_lookup_help; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
  type="${type^^}"
  dsu_section "DNS records · $host"
  if [[ "$type" != "ALL" ]]; then
    case "$type" in A|AAAA|MX|NS|TXT|CAA|SOA|CNAME|SRV|DS|DNSKEY) _dsu_print_rr "$type" "$host" ;; *) dsu_bad "Unsupported record type: $type"; return 2 ;; esac
    return
  fi
  local rr
  for rr in A AAAA CNAME MX NS CAA SOA TXT; do _dsu_print_rr "$rr" "$host"; done
}

dsu_dns_reverse() {
  local input="${1:-}" host addresses line ptr soa
  [[ -n "$input" ]] || { dsu_bad "Usage: dns reverse <domain-or-ip>"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_section "Reverse DNS · $host"
  if dsu_is_ip "$host"; then
    addresses="$host"
  else
    dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; return 2; }
    addresses="$( { _dsu_dig_lines A "$host"; _dsu_dig_lines AAAA "$host"; } | awk 'NF' | sort -u )"
  fi
  [[ -n "$addresses" ]] || { dsu_warn "No A/AAAA addresses found"; return 1; }
  while IFS= read -r line; do
    ptr=$(dig +short -x "$line" 2>/dev/null | sed 's/\.$//' | paste -sd ', ' -)
    if [[ -n "$ptr" ]]; then
      dsu_ok "${DSU_CYAN}$line${DSU_RESET} → $ptr"
    else
      soa=$(dig -x "$line" +noall +authority 2>/dev/null | awk '$4=="SOA" {print $5; exit}' | sed 's/\.$//')
      if [[ -n "$soa" ]]; then dsu_warn "$line → no PTR (authority: $soa)"; else dsu_warn "$line → no PTR"; fi
    fi
  done <<< "$addresses"
}

dsu_dns_mail() {
  local input="${1:-}" selector="${2:-}" host spf dmarc caa mta tlsrpt dkim found=0
  [[ -n "$input" ]] || { dsu_bad "Usage: dns mail <domain> [dkim-selector]"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid domain: $input"; return 2; }
  dsu_section "Mail DNS posture · $host"

  spf=$(_dsu_dig_lines TXT "$host" | tr -d '"' | grep -i '^v=spf1' | head -1)
  if [[ -z "$spf" ]]; then
    dsu_warn "SPF: missing"
  else
    dsu_ok "SPF: $spf"
    case "$spf" in *'+all'*) dsu_bad "SPF ends in +all or permits all senders" ;; *'-all'*) dsu_ok "SPF enforcement: hard fail (-all)" ;; *'~all'*) dsu_warn "SPF enforcement: soft fail (~all)" ;; *'?all'*) dsu_warn "SPF enforcement: neutral (?all)" ;; esac
  fi

  dmarc=$(_dsu_dig_lines TXT "_dmarc.$host" | tr -d '"' | grep -i '^v=DMARC1' | head -1)
  if [[ -z "$dmarc" ]]; then
    dsu_warn "DMARC: missing"
  else
    dsu_ok "DMARC: $dmarc"
    local dmarc_policy
    dmarc_policy=$(printf '%s' "$dmarc" | sed -nE 's/(^|.*;[[:space:]]*)p=([^;[:space:]]+).*/\2/ip' | tr '[:upper:]' '[:lower:]')
    case "$dmarc_policy" in reject) dsu_ok "DMARC policy: reject" ;; quarantine) dsu_warn "DMARC policy: quarantine" ;; none) dsu_warn "DMARC policy: none (monitoring only)" ;; esac
  fi

  caa=$(_dsu_dig_lines CAA "$host")
  [[ -n "$caa" ]] && dsu_ok "CAA present" || dsu_warn "CAA: missing"
  [[ -n "$caa" ]] && while IFS= read -r line; do dsu_dim "CAA $line"; done <<< "$caa"

  mta=$(_dsu_dig_lines TXT "_mta-sts.$host" | tr -d '"' | grep -i '^v=STSv1' | head -1)
  [[ -n "$mta" ]] && dsu_ok "MTA-STS TXT: $mta" || dsu_info "MTA-STS TXT: not found"
  tlsrpt=$(_dsu_dig_lines TXT "_smtp._tls.$host" | tr -d '"' | grep -i '^v=TLSRPTv1' | head -1)
  [[ -n "$tlsrpt" ]] && dsu_ok "SMTP TLS reporting: $tlsrpt" || dsu_info "SMTP TLS reporting: not found"

  local selectors=()
  if [[ -n "$selector" ]]; then
    selectors=("$selector")
  else
    selectors=(default selector1 selector2 google google2 k1 s1 s2 dkim mail smtp zoho)
  fi
  local s
  for s in "${selectors[@]}"; do
    dkim=$(_dsu_dig_lines TXT "${s}._domainkey.$host" | tr -d '"' | grep -i 'v=DKIM1' | head -1)
    if [[ -n "$dkim" ]]; then dsu_ok "DKIM selector ${DSU_BOLD}$s${DSU_RESET}: found"; dsu_dim "$dkim"; found=1; fi
  done
  (( found )) || dsu_info "DKIM: no record found for checked selectors (absence is not definitive)"
}

dsu_dns_dnssec() {
  local input="${1:-}" host dnskey ds ad
  [[ -n "$input" ]] || { dsu_bad "Usage: dns dnssec <domain>"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid domain: $input"; return 2; }
  dsu_section "DNSSEC · $host"
  dnskey=$(_dsu_dig_lines DNSKEY "$host")
  ds=$(_dsu_dig_lines DS "$host")
  if [[ -n "$dnskey" ]]; then dsu_ok "DNSKEY present"; else dsu_warn "DNSKEY not found"; fi
  if [[ -n "$ds" ]]; then dsu_ok "DS present at parent/resolver view"; else dsu_warn "DS not found"; fi
  ad=$(dig A "$host" +dnssec 2>/dev/null | awk -F'flags: ' '/flags:/ {print $2; exit}')
  if [[ "$ad" == *ad* ]]; then dsu_ok "Resolver set AD flag: validation succeeded"; else dsu_warn "AD flag not observed; resolver validation may be disabled or chain may be unsigned"; fi
}

dsu_dns_trace() {
  local input="${1:-}" host
  [[ -n "$input" ]] || { dsu_bad "Usage: dns trace <domain>"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid domain: $input"; return 2; }
  dsu_section "DNS delegation trace · $host"
  dig +trace "$host"
}


_dsu_whois_best() {
  local host="$1" candidate="$1" data labels
  while [[ "$candidate" == *.* ]]; do
    data=$(timeout 15 whois "$candidate" 2>/dev/null || true)
    if printf '%s\n' "$data" | grep -qiE '^(Registrar|Registrar Name|Registry Expiry Date|Domain Name|domain:|Domain Status|nserver:|Name Server:)'; then
      printf '%s' "$data"
      return 0
    fi
    labels="${candidate#*.}"
    [[ "$labels" != "$candidate" && "$labels" == *.* ]] || break
    candidate="$labels"
  done
  printf '%s' "$data"
}

dsu_dns_whois() {
  local input="${1:-}" host data registrar expiry created status nameservers
  [[ -n "$input" ]] || { dsu_bad "Usage: dns whois <domain>"; return 2; }
  dsu_need whois whois || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid domain: $input"; return 2; }
  dsu_section "WHOIS · $host"
  data=$(_dsu_whois_best "$host")
  [[ -n "$data" ]] || { dsu_warn "No WHOIS data returned"; return 1; }
  registrar=$(printf '%s\n' "$data" | grep -iE '^(Registrar|registrar-name|Registrar Name):' | head -1 | sed 's/^[^:]*:[[:space:]]*//')
  expiry=$(printf '%s\n' "$data" | grep -iE '^(Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|paid-till):' | head -1 | sed 's/^[^:]*:[[:space:]]*//')
  created=$(printf '%s\n' "$data" | grep -iE '^(Creation Date|Created On|created):' | head -1 | sed 's/^[^:]*:[[:space:]]*//')
  status=$(printf '%s\n' "$data" | grep -iE '^(Domain Status|Status):' | head -6 | sed 's/^[^:]*:[[:space:]]*//' | paste -sd ', ' -)
  nameservers=$(printf '%s\n' "$data" | grep -iE '^(Name Server|nserver):' | head -8 | sed 's/^[^:]*:[[:space:]]*//' | awk '{print $1}' | paste -sd ', ' -)
  [[ -n "$registrar" ]] && dsu_keyval "Registrar" "$registrar"
  [[ -n "$created" ]] && dsu_keyval "Created" "$created"
  [[ -n "$expiry" ]] && dsu_keyval "Expires" "$expiry"
  [[ -n "$status" ]] && dsu_keyval "Status" "$status"
  [[ -n "$nameservers" ]] && dsu_keyval "Nameservers" "$nameservers"
  if [[ -z "$registrar$created$expiry$status$nameservers" ]]; then printf '%s\n' "$data" | head -80; fi
}

dsu_dns_hosting() {
  local input="${1:-}"
  [[ -n "$input" ]] || { dsu_bad "Usage: dns hosting <domain>"; return 2; }
  dsu_need python3 python3 || return
  dsu_section "Hosting/provider · $(dsu_normalize_host "$input")"
  python3 "$DSU_HOME/helpers/hosting_provider.py" "$input"
}

dsu_dns_dispatch() {
  local cmd="${1:-help}"; shift || true
  if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then _dsu_dns_leaf_help "$cmd"; return 0; fi
  case "${cmd,,}" in
    help|--help|-h) _dsu_dns_usage ;;
    lookup|look|resolve|records|l) dsu_dns_lookup "$@" ;;
    reverse|ptr|rdns|r) dsu_dns_reverse "$@" ;;
    mail|email|m) dsu_dns_mail "$@" ;;
    dnssec|ds) dsu_dns_dnssec "$@" ;;
    trace|t) dsu_dns_trace "$@" ;;
    whois|w) dsu_dns_whois "$@" ;;
    hosting|host|provider|h) dsu_dns_hosting "$@" ;;
    *) dsu_bad "Unknown dns command: $cmd"; printf '\n'; _dsu_dns_usage; return 2 ;;
  esac
}
