#!/usr/bin/env bash
set -o pipefail

DSU_SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
DSU_SCRIPT_DIR="$(cd -- "$(dirname -- "$DSU_SCRIPT_PATH")" && pwd)"
# shellcheck source=lib/core.sh
source "$DSU_SCRIPT_DIR/lib/core.sh"
# shellcheck source=lib/dns.sh
source "$DSU_SCRIPT_DIR/lib/dns.sh"
# shellcheck source=lib/ssl.sh
source "$DSU_SCRIPT_DIR/lib/ssl.sh"
# shellcheck source=lib/site.sh
source "$DSU_SCRIPT_DIR/lib/site.sh"
# shellcheck source=lib/security.sh
source "$DSU_SCRIPT_DIR/lib/security.sh"

_dsu_main_help() {
  dsu_banner
  cat <<EOF_HELP

${DSU_BOLD}Usage${DSU_RESET}
  ${DSU_GREEN}dns-ssl-utilities.sh${DSU_RESET} <command> [subcommand] [arguments]
  ${DSU_GREEN}dsu${DSU_RESET} <command> [subcommand] [arguments]             ${DSU_GRAY}# after setup.sh${DSU_RESET}

${DSU_BOLD}Fast paths${DSU_RESET}
  ${DSU_GREEN}check, c${DSU_RESET} <domain>       Complete domain/site health summary
  ${DSU_GREEN}audit, a${DSU_RESET} <target>       Web security exposure + hardening audit
  ${DSU_GREEN}rdns${DSU_RESET} <domain|ip>         Reverse DNS/PTR shortcut
  ${DSU_GREEN}cert${DSU_RESET} <domain>            TLS certificate shortcut

${DSU_BOLD}${DSU_BLUE}DNS${DSU_RESET}  ${DSU_GRAY}records, mail policy, DNSSEC and ownership${DSU_RESET}
  ${DSU_GREEN}dns lookup, l${DSU_RESET}           A/AAAA/MX/NS/TXT/CAA/SOA/CNAME records
  ${DSU_GREEN}dns reverse, ptr, r${DSU_RESET}     Reverse DNS for every resolved IP
  ${DSU_GREEN}dns mail, m${DSU_RESET}             SPF, DMARC, DKIM selectors, MTA-STS, TLS-RPT
  ${DSU_GREEN}dns dnssec, ds${DSU_RESET}          DNSKEY/DS + resolver-validation status
  ${DSU_GREEN}dns trace, t${DSU_RESET}            Delegation trace from the DNS root
  ${DSU_GREEN}dns whois, w${DSU_RESET}            Registrar/expiry/status summary
  ${DSU_GREEN}dns hosting, h${DSU_RESET}          Best-effort hosting/provider identification

${DSU_BOLD}${DSU_MAGENTA}SSL / TLS${DSU_RESET}  ${DSU_GRAY}live endpoints + certificate files${DSU_RESET}
  ${DSU_GREEN}ssl cert, c${DSU_RESET}             Full certificate identity, SAN, key and validity
  ${DSU_GREEN}ssl quick, q${DSU_RESET}            One-line certificate health
  ${DSU_GREEN}ssl chain, ch${DSU_RESET}           Full served certificate chain
  ${DSU_GREEN}ssl fetch, f${DSU_RESET}            Test SNI/domain against a specific server IP
  ${DSU_GREEN}ssl versions, v${DSU_RESET}         TLS protocol-version support
  ${DSU_GREEN}ssl ciphers, ci${DSU_RESET}         Cipher enumeration via sslscan or nmap
  ${DSU_GREEN}ssl scan, s${DSU_RESET}             Direct sslscan integration
  ${DSU_GREEN}ssl ocsp, o${DSU_RESET}             OCSP revocation query
  ${DSU_GREEN}ssl crl${DSU_RESET}                 CRL distribution/revocation check
  ${DSU_GREEN}ssl ct, ctlogs${DSU_RESET}          Certificate Transparency names
  ${DSU_GREEN}ssl headers, h${DSU_RESET}          HTTPS security headers
  ${DSU_GREEN}ssl performance, perf${DSU_RESET}   TLS handshake benchmark
  ${DSU_GREEN}ssl fingerprint, fp${DSU_RESET}     SHA-256 fingerprint / expected-pin comparison
  ${DSU_GREEN}ssl decode, d${DSU_RESET}           Decode PEM certificate, CSR or private key
  ${DSU_GREEN}ssl match, m${DSU_RESET}            Compare public keys across cert/CSR/key files
  ${DSU_GREEN}ssl new, n${DSU_RESET}              Create private key + CSR + SANs
  ${DSU_GREEN}ssl pack, pk${DSU_RESET}            Create PFX/PKCS#12
  ${DSU_GREEN}ssl extract, x${DSU_RESET}          Extract certificate/chain/key from PFX

${DSU_BOLD}${DSU_CYAN}Site${DSU_RESET}  ${DSU_GRAY}combined operational diagnostics${DSU_RESET}
  ${DSU_GREEN}site check, c${DSU_RESET}           DNS + WHOIS + hosting + TLS + HTTP + mail + PTR
  ${DSU_GREEN}site headers, h${DSU_RESET}         Header-focused review
  ${DSU_GREEN}site redirects, r${DSU_RESET}       Redirect chain inspection
  ${DSU_GREEN}site status, s${DSU_RESET}          Compact HTTP/HTTPS/TLS status

${DSU_BOLD}${DSU_RED}Security audit${DSU_RESET}
  ${DSU_GREEN}audit, a, vuln, security${DSU_RESET} <target> [options]
      Low-impact DNS/TLS/HTTP exposure checks by default.
      ${DSU_YELLOW}--deep --authorized${DSU_RESET} adds authorized DNS/network probes.
      ${DSU_YELLOW}--ports${DSU_RESET} adds a top-100 TCP inventory in deep mode.
      Run ${DSU_CYAN}audit --help${DSU_RESET} for the full scope and severity model.

${DSU_BOLD}Convenience commands installed by setup.sh${DSU_RESET}
  ${DSU_GREEN}ssl cert example.com${DSU_RESET}       = ${DSU_GREEN}ssl c example.com${DSU_RESET}
  ${DSU_GREEN}dnsutil lookup example.com${DSU_RESET} = ${DSU_GREEN}dnsutil l example.com${DSU_RESET}
  ${DSU_GREEN}sitecheck example.com${DSU_RESET}      = full site check
  ${DSU_GREEN}vulncheck example.com${DSU_RESET}      = security audit

${DSU_BOLD}Global options${DSU_RESET}
  ${DSU_GREEN}--help, -h${DSU_RESET}        This help
  ${DSU_GREEN}--version${DSU_RESET}         Print suite version
  ${DSU_GREEN}--no-color${DSU_RESET}        Disable ANSI colors
  ${DSU_GREEN}--color${DSU_RESET}           Force colors even when stdout is not a TTY
  ${DSU_GREEN}--ascii${DSU_RESET}           Use ASCII status markers instead of Unicode
  ${DSU_GREEN}doctor${DSU_RESET}            Check required and optional dependencies

${DSU_BOLD}Command help${DSU_RESET}
  ${DSU_CYAN}dns --help${DSU_RESET}          DNS command reference
  ${DSU_CYAN}ssl --help${DSU_RESET}          SSL/TLS + certificate-file reference
  ${DSU_CYAN}site --help${DSU_RESET}         Site diagnostic reference
  ${DSU_CYAN}audit --help${DSU_RESET}        Audit scope, options and authorization model
  ${DSU_CYAN}ssl cert --help${DSU_RESET}     Leaf-command help (also: dsu help ssl cert)

${DSU_BOLD}Examples${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh check example.com${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh dns mail example.com selector1${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh ssl c example.com${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh ssl fetch 203.0.113.10 example.com${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh audit example.com${DSU_RESET}
  ${DSU_CYAN}dns-ssl-utilities.sh audit example.com --deep --authorized${DSU_RESET}

${DSU_BOLD}Dependencies${DSU_RESET}
  Required: ${DSU_WHITE}bash 4+, curl, openssl, dig (dnsutils), python3, coreutils${DSU_RESET}
  Recommended: ${DSU_WHITE}whois${DSU_RESET}
  Optional: ${DSU_WHITE}sslscan, nmap, file${DSU_RESET}
  Install: ${DSU_CYAN}sudo apt install curl openssl dnsutils python3 coreutils whois sslscan nmap file${DSU_RESET}

${DSU_BOLD}Exit codes${DSU_RESET}
  ${DSU_GREEN}0${DSU_RESET}  Command completed (audit findings may still be present unless --strict)
  ${DSU_YELLOW}1${DSU_RESET}  Operational failure, or MEDIUM finding with audit --strict
  ${DSU_RED}2${DSU_RESET}  Invalid usage, or HIGH/CRITICAL finding with audit --strict
  ${DSU_RED}127${DSU_RESET} Missing command dependency

${DSU_GRAY}Network-derived results can be incomplete behind CDNs, proxies, split-horizon DNS,
WAFs and load balancers. Treat findings as evidence to verify, not as an oracle.${DSU_RESET}
EOF_HELP
}

dsu_doctor() {
  dsu_banner
  dsu_section "Runtime"
  dsu_keyval "Version" "$DSU_VERSION"
  dsu_keyval "Bash" "$BASH_VERSION"
  dsu_keyval "Home" "$DSU_HOME"
  dsu_section "Dependencies"
  local cmd package class
  while IFS=$'\t' read -r cmd package class; do
    if dsu_has "$cmd"; then
      dsu_ok "$cmd ${DSU_GRAY}($class)${DSU_RESET} → $(command -v "$cmd")"
    else
      if [[ "$class" == required ]]; then dsu_bad "$cmd missing ${DSU_GRAY}(install: $package)${DSU_RESET}"; else dsu_warn "$cmd missing ${DSU_GRAY}(optional: $package)${DSU_RESET}"; fi
    fi
  done <<'DEPS'
curl	curl	required
openssl	openssl	required
dig	dnsutils	required
python3	python3	required
timeout	coreutils	required
date	coreutils	required
whois	whois	recommended
sslscan	sslscan	optional
nmap	nmap	optional
file	file	optional
DEPS
}

_dsu_dispatch_normal() {
  local cmd="${1:-help}"; shift || true
  case "${cmd,,}" in
    help|--help|-h) 
      if (( $# )); then
        case "${1,,}" in
          dns) [[ -n "${2:-}" ]] && _dsu_dns_leaf_help "$2" || _dsu_dns_usage ;;
          ssl) [[ -n "${2:-}" ]] && _dsu_ssl_leaf_help "$2" || _dsu_ssl_usage ;;
          site) [[ -n "${2:-}" ]] && _dsu_site_leaf_help "$2" || _dsu_site_usage ;;
          audit|security|vuln) _dsu_audit_usage ;;
          *) _dsu_main_help ;;
        esac
      else _dsu_main_help; fi
      ;;
    version|--version|-v) printf '%s %s\n' "$DSU_NAME" "$DSU_VERSION" ;;
    doctor|diag) dsu_doctor ;;
    dns) dsu_dns_dispatch "$@" ;;
    ssl|tls) dsu_ssl_dispatch "$@" ;;
    site) dsu_site_dispatch "$@" ;;
    check|c) dsu_site_check "$@" ;;
    audit|a|vuln|vulnerability|security|sec) 
      if [[ "${1:-}" == "audit" ]]; then shift; fi
      if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then
        _dsu_audit_usage
        return 0
      else
        dsu_security_audit "$@"
      fi
      ;;
    rdns|ptr) dsu_dns_reverse "$@" ;;
    cert) dsu_ssl_cert "$@" ;;
    *) dsu_bad "Unknown command: $cmd"; printf '\n'; _dsu_main_help; return 2 ;;
  esac
}

main() {
  local args=("$@") cleaned=() arg
  for arg in "${args[@]}"; do
    case "$arg" in
      --no-color) dsu_disable_color ;;
      --color) _dsu_color_enabled=1; _dsu_apply_colors ;;
      --ascii) DSU_ASCII=1 ;;
      *) cleaned+=("$arg") ;;
    esac
  done
  set -- "${cleaned[@]}"

  local invoked
  invoked=$(basename -- "$0")
  case "$invoked" in
    ssl) dsu_ssl_dispatch "$@" ;;
    dnsutil) dsu_dns_dispatch "$@" ;;
    sitecheck)
      case "${1:-}" in check|c|headers|h|redirects|r|status|s|--help|-h|help) dsu_site_dispatch "$@" ;; *) dsu_site_check "$@" ;; esac
      ;;
    vulncheck) 
      if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || -z "${1:-}" ]]; then _dsu_audit_usage; else dsu_security_audit "$@"; fi
      ;;
    *) _dsu_dispatch_normal "$@" ;;
  esac
}

main "$@"
