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
  ${DSU_GREEN}check${DSU_RESET} <domain> [--no-rdns]
  ${DSU_GREEN}check dns${DSU_RESET} <command> [arguments]
  ${DSU_GREEN}check ssl${DSU_RESET} <command> [arguments]
  ${DSU_GREEN}check audit${DSU_RESET} <target> [options]
  ${DSU_GREEN}check doctor${DSU_RESET}

${DSU_BOLD}Fast domain overview${DSU_RESET}
  ${DSU_GREEN}check <domain>${DSU_RESET}              Registrar, DNS, mail policy, hosting, TLS,
                              HTTP/HTTPS posture and reverse DNS in one fast report.
  ${DSU_GREEN}--no-rdns${DSU_RESET}                  Skip PTR lookups for the lowest latency.

${DSU_BOLD}${DSU_BLUE}DNS${DSU_RESET}  ${DSU_GRAY}records, mail policy, DNSSEC, WHOIS and hosting${DSU_RESET}
  ${DSU_GREEN}dns lookup, l${DSU_RESET}              A/AAAA/MX/NS/TXT/CAA/SOA/CNAME records
  ${DSU_GREEN}dns reverse, ptr, r${DSU_RESET}        Reverse DNS / PTR
  ${DSU_GREEN}dns mail, m${DSU_RESET}                SPF, DMARC, DKIM, MTA-STS and TLS-RPT
  ${DSU_GREEN}dns dnssec, ds${DSU_RESET}             DNSSEC records + resolver validation
  ${DSU_GREEN}dns trace, t${DSU_RESET}               Delegation trace
  ${DSU_GREEN}dns whois, w${DSU_RESET}               Registrar, dates and domain status
  ${DSU_GREEN}dns hosting, h${DSU_RESET}             Best-effort hosting/provider identification

${DSU_BOLD}${DSU_MAGENTA}SSL / TLS${DSU_RESET}  ${DSU_GRAY}live endpoints + certificate/key tools${DSU_RESET}
  ${DSU_GREEN}ssl cert, c${DSU_RESET}                Certificate identity, SANs, key and validity
  ${DSU_GREEN}ssl quick, q${DSU_RESET}               Compact certificate health
  ${DSU_GREEN}ssl chain, ch${DSU_RESET}              Served certificate chain
  ${DSU_GREEN}ssl fetch, f${DSU_RESET}               Test SNI/domain against a specific server IP
  ${DSU_GREEN}ssl versions, v${DSU_RESET}            TLS protocol support
  ${DSU_GREEN}ssl ciphers, ci${DSU_RESET}            Cipher enumeration
  ${DSU_GREEN}ssl ocsp, o${DSU_RESET}                OCSP status
  ${DSU_GREEN}ssl crl${DSU_RESET}                    CRL revocation check
  ${DSU_GREEN}ssl ct${DSU_RESET}                     Certificate Transparency names
  ${DSU_GREEN}ssl headers, h${DSU_RESET}             HTTPS security headers
  ${DSU_GREEN}ssl fingerprint, fp${DSU_RESET}        SHA-256 fingerprint / pin comparison
  ${DSU_GREEN}ssl decode, d${DSU_RESET}              Decode certificate, CSR or private key
  ${DSU_GREEN}ssl match, m${DSU_RESET}               Verify cert/CSR/key public-key matching
  ${DSU_GREEN}ssl new, n${DSU_RESET}                 Create private key + CSR + SANs
  ${DSU_GREEN}ssl pack, pk${DSU_RESET}               Create PKCS#12/PFX
  ${DSU_GREEN}ssl extract, x${DSU_RESET}             Extract PKCS#12/PFX
  ${DSU_GREEN}ssl performance, perf${DSU_RESET}      TLS handshake benchmark

${DSU_BOLD}${DSU_RED}Defensive security audit${DSU_RESET}
  ${DSU_GREEN}check audit <target>${DSU_RESET}        Low-impact DNS/TLS/HTTP exposure review
  ${DSU_YELLOW}--deep --authorized${DSU_RESET}        Add authorized DNS/network probes
  ${DSU_YELLOW}--ports${DSU_RESET}                    Add top-100 TCP inventory in deep mode
  ${DSU_GREEN}--strict${DSU_RESET}                   Return non-zero for MEDIUM+ findings
  Run ${DSU_CYAN}check audit --help${DSU_RESET} for scope, options and authorization rules.

${DSU_BOLD}Convenience commands${DSU_RESET}
  ${DSU_GREEN}dnsutil${DSU_RESET} <command> ...       Shortcut for ${DSU_GREEN}check dns${DSU_RESET}
  ${DSU_GREEN}ssl${DSU_RESET} <command> ...           Shortcut for ${DSU_GREEN}check ssl${DSU_RESET}
  ${DSU_GREEN}vulncheck${DSU_RESET} <target> ...      Shortcut for ${DSU_GREEN}check audit${DSU_RESET}
  ${DSU_GREEN}sitecheck${DSU_RESET} <domain>          Compatibility frontend for site diagnostics
  ${DSU_GRAY}dsu is retained only as a compatibility alias for the suite dispatcher.${DSU_RESET}

${DSU_BOLD}Global options${DSU_RESET}
  ${DSU_GREEN}--help, -h${DSU_RESET}                 Show help
  ${DSU_GREEN}--version, -v${DSU_RESET}              Print suite version
  ${DSU_GREEN}--no-color${DSU_RESET}                 Disable ANSI colors ${DSU_GRAY}(NO_COLOR is also supported)${DSU_RESET}
  ${DSU_GREEN}--color${DSU_RESET}                    Force ANSI colors
  ${DSU_GREEN}--ascii${DSU_RESET}                    Use ASCII status markers

${DSU_BOLD}Help${DSU_RESET}
  ${DSU_CYAN}check dns --help${DSU_RESET}            DNS command reference
  ${DSU_CYAN}check ssl --help${DSU_RESET}            SSL/TLS command reference
  ${DSU_CYAN}ssl cert --help${DSU_RESET}             Command-specific help
  ${DSU_CYAN}check audit --help${DSU_RESET}          Audit scope and authorization model

${DSU_BOLD}Examples${DSU_RESET}
  ${DSU_CYAN}check example.com${DSU_RESET}
  ${DSU_CYAN}check example.com --no-rdns${DSU_RESET}
  ${DSU_CYAN}dnsutil m example.com${DSU_RESET}
  ${DSU_CYAN}ssl c example.com${DSU_RESET}
  ${DSU_CYAN}ssl fetch 203.0.113.10 example.com${DSU_RESET}
  ${DSU_CYAN}vulncheck example.com${DSU_RESET}
  ${DSU_CYAN}vulncheck example.com --deep --authorized${DSU_RESET}

${DSU_BOLD}Dependencies${DSU_RESET}
  Required: ${DSU_WHITE}bash 4+, curl, openssl, dig (dnsutils), python3, coreutils${DSU_RESET}
  Recommended: ${DSU_WHITE}whois${DSU_RESET}
  Optional: ${DSU_WHITE}sslscan, nmap, file${DSU_RESET}
  Diagnose: ${DSU_CYAN}check doctor${DSU_RESET}

${DSU_BOLD}Exit codes${DSU_RESET}
  ${DSU_GREEN}0${DSU_RESET}    Command completed ${DSU_GRAY}(audit findings may still exist without --strict)${DSU_RESET}
  ${DSU_YELLOW}1${DSU_RESET}    Operational failure, or MEDIUM finding with audit --strict
  ${DSU_RED}2${DSU_RESET}    Invalid usage, or HIGH/CRITICAL finding with audit --strict
  ${DSU_RED}127${DSU_RESET}  Required command dependency missing
EOF_HELP
}

dsu_doctor() {
  dsu_banner
  dsu_section "Runtime"
  dsu_keyval "Version" "$DSU_VERSION"
  dsu_keyval "Bash" "$BASH_VERSION"
  dsu_keyval "Home" "$DSU_HOME"
  dsu_section "Network tuning"
  dsu_keyval "Fast check DNS" "${DSU_CHECK_DNS_TIMEOUT}s"
  dsu_keyval "Fast check HTTP/TLS" "${DSU_CHECK_MAX_TIME}s max"
  dsu_keyval "Fast check WHOIS" "${DSU_CHECK_WHOIS_TIMEOUT}s"
  dsu_keyval "DNS timeout" "${DSU_DNS_TIMEOUT}s × ${DSU_DNS_TRIES} try/tries"
  dsu_keyval "Connect timeout" "${DSU_CONNECT_TIMEOUT}s"
  dsu_keyval "General max time" "${DSU_MAX_TIME}s"
  dsu_keyval "WHOIS timeout" "${DSU_WHOIS_TIMEOUT}s"
  dsu_keyval "Audit jobs" "${DSU_AUDIT_JOBS:-4}"
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

_dsu_dispatch_check_command() {
  # When invoked as `check`, an ordinary first argument is the target.
  # Known suite commands still route through the normal dispatcher, making
  # `check dns ...`, `check ssl ...`, `check audit ...`, etc. intuitive.
  case "${1:-}" in
    "") _dsu_main_help ;;
    help|--help|-h|version|--version|-v|doctor|diag|dns|ssl|tls|site|check|c|audit|a|vuln|vulnerability|security|sec|rdns|ptr|cert)
      _dsu_dispatch_normal "$@"
      ;;
    *)
      dsu_site_check "$@"
      ;;
  esac
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
    check) _dsu_dispatch_check_command "$@" ;;
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
