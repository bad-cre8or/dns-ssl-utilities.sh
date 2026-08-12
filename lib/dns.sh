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
  case "${type^^}" in
    A)
      dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" +short A "$name" 2>/dev/null \
        | awk '/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {print}'
      ;;
    AAAA)
      dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" +short AAAA "$name" 2>/dev/null \
        | awk 'index($0, ":") {print}'
      ;;
    *)
      dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" +short "$type" "$name" 2>/dev/null | sed 's/\.$//'
      ;;
  esac
}

_dsu_zone_apex_guess() {
  local host="$1" zone
  zone=$(dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" "$host" SOA +noall +answer +authority 2>/dev/null \
    | awk '$4=="SOA" {print $1; exit}' | sed 's/\.$//')
  printf '%s' "${zone:-$host}"
}

_dsu_whois_first_value() {
  local keys="$1"
  awk -v keys="$keys" '
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function norm(s) {
      s=tolower(s)
      gsub(/[._-]+/, " ", s)
      gsub(/[[:space:]]+/, " ", s)
      return trim(s)
    }
    BEGIN {
      count=split(keys, wanted, "|")
      for (i=1; i<=count; i++) wanted_map[norm(wanted[i])]=1
    }
    {
      line=$0
      sub(/\r$/, "", line)
      if (waiting) {
        candidate=trim(line)
        if (candidate != "") { print candidate; exit }
      }
      colon=index(line, ":")
      if (!colon) next
      key=norm(substr(line, 1, colon-1))
      if (!(key in wanted_map)) next
      value=trim(substr(line, colon+1))
      if (value != "") { print value; exit }
      waiting=1
    }
  '
}

_dsu_registrar_pretty() {
  local value
  value=$(dsu_trim "$*")
  # Present the recognizable registrar brand while keeping WHOIS as the source.
  # This strips only common terminal legal-entity suffixes.
  value=$(printf '%s\n' "$value" | sed -E '
    s/[[:space:]]*,?[[:space:]]+(L\.?L\.?C\.?|INC\.?|INCORPORATED|LTD\.?|LIMITED|GMBH|AG|AS|ASA|S\.?A\.?|B\.?V\.?)[[:space:]]*$//I
  ')
  printf '%s' "$value"
}

_dsu_whois_registrar() {
  local data="$1" value handle details
  value=$(printf '%s\n' "$data" | _dsu_whois_first_value 'registrar|registrar name|sponsoring registrar|registrar organization|registrar organisation')
  if [[ -n "$value" ]]; then
    _dsu_registrar_pretty "$value"
    return 0
  fi

  # Handle-based registries (notably NORID-style WHOIS) may return only a
  # registrar object handle in the domain record. Resolve that object lazily,
  # only when the direct registrar name was absent, so common lookups stay fast.
  handle=$(printf '%s\n' "$data" | _dsu_whois_first_value 'registrar handle' || true)
  [[ -n "$handle" ]] || return 1
  if dsu_has whois; then
    details=$(timeout "$DSU_WHOIS_TIMEOUT" whois "$handle" 2>/dev/null || true)
    value=$(printf '%s\n' "$details" | _dsu_whois_first_value 'registrar name|name|organization|organisation' || true)
    if [[ -n "$value" ]]; then
      _dsu_registrar_pretty "$value"
      return 0
    fi
  fi
  printf '%s' "$handle"
}

_dsu_ptr_probe() {
  local ip="$1" output rc status ptr message
  output=$(dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" -x "$ip" +noall +comments +answer 2>&1)
  rc=$?

  # A valid answer wins even if dig logged a transient resolver warning first.
  ptr=$(printf '%s\n' "$output" | awk 'toupper($4)=="PTR" {gsub(/\.$/, "", $5); print $5}' | awk 'NF && !seen[$0]++' | paste -sd ',' -)
  if [[ -n "$ptr" ]]; then
    printf 'OK\t%s\n' "$ptr"
    return 0
  fi

  status=$(printf '%s\n' "$output" | sed -nE 's/.*status:[[:space:]]*([A-Z]+),.*/\1/p' | head -1)
  case "$output" in
    *'communications error'*'timed out'*|*'connection timed out'*) message='resolver timed out' ;;
    *'no servers could be reached'*) message='no DNS servers reachable' ;;
    *'connection refused'*) message='resolver connection refused' ;;
    *'network is unreachable'*|*'Network is unreachable'*) message='network unreachable' ;;
    *) message='' ;;
  esac

  if [[ -n "$message" ]]; then
    printf 'ERROR\t%s\n' "$message"
  elif (( rc != 0 )); then
    printf 'ERROR\tdig failed (exit %d)\n' "$rc"
  elif [[ "$status" == 'NOERROR' || "$status" == 'NXDOMAIN' ]]; then
    printf 'NONE\tno PTR\n'
  elif [[ -n "$status" ]]; then
    printf 'ERROR\tDNS %s\n' "$status"
  else
    printf 'ERROR\tresolver returned no usable response\n'
  fi
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

  local tmp rr pid result
  local -a records=(A AAAA CNAME MX NS CAA SOA TXT) pids=()
  tmp=$(dsu_tmpdir) || return 1
  for rr in "${records[@]}"; do
    (_dsu_dig_lines "$rr" "$host") >"$tmp/$rr" &
    pids+=("$!")
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  for rr in "${records[@]}"; do
    result=$(cat "$tmp/$rr" 2>/dev/null || true)
    if [[ -n "$result" ]]; then
      while IFS= read -r line; do dsu_keyval "$rr" "$line"; done <<< "$result"
    else
      dsu_keyval "$rr" "${DSU_GRAY}—${DSU_RESET}"
    fi
  done
  dsu_cleanup_dir "$tmp"
}

dsu_dns_reverse() {
  local input="${1:-}" host addresses line ptr soa tmp pid
  [[ -n "$input" ]] || { dsu_bad "Usage: dns reverse <domain-or-ip>"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_section "Reverse DNS · $host"
  tmp=$(dsu_tmpdir) || return 1

  if dsu_is_ip "$host"; then
    addresses="$host"
  else
    dsu_valid_host "$host" || { dsu_bad "Invalid host: $input"; dsu_cleanup_dir "$tmp"; return 2; }
    local p1 p2
    (_dsu_dig_lines A "$host") >"$tmp/A" & p1=$!
    (_dsu_dig_lines AAAA "$host") >"$tmp/AAAA" & p2=$!
    wait "$p1" 2>/dev/null || true; wait "$p2" 2>/dev/null || true
    addresses="$(cat "$tmp/A" "$tmp/AAAA" 2>/dev/null | awk 'NF' | sort -u)"
  fi
  [[ -n "$addresses" ]] || { dsu_warn "No A/AAAA addresses found"; dsu_cleanup_dir "$tmp"; return 1; }

  local -a ips=() pids=()
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    ips+=("$line")
    (_dsu_ptr_probe "$line") >"$tmp/ptr.${#ips[@]}" &
    pids+=("$!")
    (
      dig +time="$DSU_DNS_TIMEOUT" +tries="$DSU_DNS_TRIES" -x "$line" +noall +authority 2>/dev/null \
        | awk '$4=="SOA" {print $5; exit}' | sed 's/\.$//'
    ) >"$tmp/soa.${#ips[@]}" &
    pids+=("$!")
  done <<< "$addresses"
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  local i=0
  for line in "${ips[@]}"; do
    ((i+=1))
    ptr=$(cat "$tmp/ptr.$i" 2>/dev/null || true)
    local ptr_state ptr_value
    ptr_state=${ptr%%$'\t'*}
    ptr_value=${ptr#*$'\t'}
    case "$ptr_state" in
      OK) dsu_ok "${DSU_CYAN}$line${DSU_RESET} → $ptr_value" ;;
      NONE)
        soa=$(cat "$tmp/soa.$i" 2>/dev/null || true)
        if [[ -n "$soa" ]]; then dsu_info "$line → no PTR (authority: $soa)"; else dsu_info "$line → no PTR"; fi
        ;;
      ERROR) dsu_bad "$line → PTR lookup failed ($ptr_value)" ;;
      *) dsu_bad "$line → PTR lookup failed (unrecognized resolver response)" ;;
    esac
  done
  dsu_cleanup_dir "$tmp"
}

dsu_dns_mail() {
  local input="${1:-}" selector="${2:-}" host spf dmarc caa mta tlsrpt dkim found=0 tmp pid
  [[ -n "$input" ]] || { dsu_bad "Usage: dns mail <domain> [dkim-selector]"; return 2; }
  dsu_need dig dnsutils || return
  host=$(dsu_normalize_host "$input")
  dsu_valid_host "$host" || { dsu_bad "Invalid domain: $input"; return 2; }
  dsu_section "Mail DNS posture · $host"

  tmp=$(dsu_tmpdir) || return 1
  local -a base_pids=()
  (_dsu_dig_lines TXT "$host") >"$tmp/txt" & base_pids+=("$!")
  (_dsu_dig_lines TXT "_dmarc.$host") >"$tmp/dmarc" & base_pids+=("$!")
  (_dsu_dig_lines CAA "$host") >"$tmp/caa" & base_pids+=("$!")
  (_dsu_dig_lines TXT "_mta-sts.$host") >"$tmp/mta" & base_pids+=("$!")
  (_dsu_dig_lines TXT "_smtp._tls.$host") >"$tmp/tlsrpt" & base_pids+=("$!")
  for pid in "${base_pids[@]}"; do wait "$pid" 2>/dev/null || true; done

  spf=$(tr -d '"' <"$tmp/txt" | grep -i '^v=spf1' | head -1)
  if [[ -z "$spf" ]]; then
    dsu_warn "SPF: missing"
  else
    dsu_ok "SPF: $spf"
    case "$spf" in *'+all'*) dsu_bad "SPF ends in +all or permits all senders" ;; *'-all'*) dsu_ok "SPF enforcement: hard fail (-all)" ;; *'~all'*) dsu_warn "SPF enforcement: soft fail (~all)" ;; *'?all'*) dsu_warn "SPF enforcement: neutral (?all)" ;; esac
  fi

  dmarc=$(tr -d '"' <"$tmp/dmarc" | grep -i '^v=DMARC1' | head -1)
  if [[ -z "$dmarc" ]]; then
    dsu_warn "DMARC: missing"
  else
    dsu_ok "DMARC: $dmarc"
    local dmarc_policy
    dmarc_policy=$(printf '%s' "$dmarc" | sed -nE 's/(^|.*;[[:space:]]*)p=([^;[:space:]]+).*/\2/ip' | tr '[:upper:]' '[:lower:]')
    case "$dmarc_policy" in reject) dsu_ok "DMARC policy: reject" ;; quarantine) dsu_warn "DMARC policy: quarantine" ;; none) dsu_warn "DMARC policy: none (monitoring only)" ;; esac
  fi

  caa=$(cat "$tmp/caa")
  [[ -n "$caa" ]] && dsu_ok "CAA present" || dsu_warn "CAA: missing"
  [[ -n "$caa" ]] && while IFS= read -r line; do dsu_dim "CAA $line"; done <<< "$caa"

  mta=$(tr -d '"' <"$tmp/mta" | grep -i '^v=STSv1' | head -1)
  [[ -n "$mta" ]] && dsu_ok "MTA-STS TXT: $mta" || dsu_info "MTA-STS TXT: not found"
  tlsrpt=$(tr -d '"' <"$tmp/tlsrpt" | grep -i '^v=TLSRPTv1' | head -1)
  [[ -n "$tlsrpt" ]] && dsu_ok "SMTP TLS reporting: $tlsrpt" || dsu_info "SMTP TLS reporting: not found"

  local selectors=()
  if [[ -n "$selector" ]]; then
    selectors=("$selector")
  else
    selectors=(default selector1 selector2 google google2 k1 s1 s2 dkim mail smtp zoho)
  fi
  local s i=0
  local -a dkim_pids=()
  for s in "${selectors[@]}"; do
    ((i+=1))
    (_dsu_dig_lines TXT "${s}._domainkey.$host") >"$tmp/dkim.$i" &
    dkim_pids+=("$!")
  done
  for pid in "${dkim_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
  i=0
  for s in "${selectors[@]}"; do
    ((i+=1))
    dkim=$(tr -d '"' <"$tmp/dkim.$i" | grep -i 'v=DKIM1' | head -1)
    if [[ -n "$dkim" ]]; then dsu_ok "DKIM selector ${DSU_BOLD}$s${DSU_RESET}: found"; dsu_dim "$dkim"; found=1; fi
  done
  (( found )) || dsu_info "DKIM: no record found for checked selectors (absence is not definitive)"
  dsu_cleanup_dir "$tmp"
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
  local host="$1" candidate data
  candidate=$(_dsu_zone_apex_guess "$host")
  data=$(timeout "$DSU_WHOIS_TIMEOUT" whois "$candidate" 2>/dev/null || true)
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
  registrar=$(_dsu_whois_registrar "$data" || true)
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
