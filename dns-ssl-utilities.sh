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
  ${DSU_GREEN}check${DSU_RESET} <domain-or-ip> [flags]
  ${DSU_GREEN}check --doctor${DSU_RESET}
  ${DSU_GREEN}check --version${DSU_RESET}
  ${DSU_GREEN}ssl${DSU_RESET} <command> [flags]

${DSU_BOLD}Domain and DNS flags${DSU_RESET}
  ${DSU_GREEN}--no-rdns${DSU_RESET}                  Skip reverse-DNS lookups in the overview
  ${DSU_GREEN}--dns [TYPE]${DSU_RESET}               Show DNS records; optionally select one TYPE
  ${DSU_GREEN}--reverse${DSU_RESET}                  Show PTR records for a domain or IP
  ${DSU_GREEN}--mail [selector]${DSU_RESET}          Check MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT
  ${DSU_GREEN}--dnssec${DSU_RESET}                   Check DNSSEC records and resolver validation
  ${DSU_GREEN}--trace${DSU_RESET}                    Trace DNS delegation from the root
  ${DSU_GREEN}--whois${DSU_RESET}                    Show registrar, dates and domain status
  ${DSU_GREEN}--hosting${DSU_RESET}                  Identify the likely hosting provider

  Use one utility flag per invocation. Without one, ${DSU_GREEN}check${DSU_RESET} prints the fast overview.

${DSU_BOLD}Fast overview output${DSU_RESET}
  ${DSU_GREEN}SPF${DSU_RESET}                        Full SPF policy contents
  ${DSU_GREEN}DMARC${DSU_RESET}                      Effective DMARC p= policy only
  ${DSU_GREEN}TLS issuer${DSU_RESET}                 Certificate issuer distinguished name
  ${DSU_GREEN}TLS CN${DSU_RESET}                     Certificate subject common name

${DSU_BOLD}Security audit${DSU_RESET}
  ${DSU_GREEN}--audit${DSU_RESET}                    Run the low-impact DNS/TLS/HTTP audit
  ${DSU_GREEN}--strict${DSU_RESET}                   Return non-zero for MEDIUM+ audit findings
  ${DSU_GREEN}--no-paths${DSU_RESET}                 Skip accidental-exposure path probes
  ${DSU_GREEN}--port N${DSU_RESET}                   Set the HTTPS/TLS audit port ${DSU_GRAY}(default: 443)${DSU_RESET}
  ${DSU_YELLOW}--deep --authorized${DSU_RESET}        Add authorized DNS and network probes
  ${DSU_YELLOW}--ports --authorized${DSU_RESET}       Add a top-100 TCP inventory in deep mode

  Audit options must follow ${DSU_GREEN}--audit${DSU_RESET}. Run
  ${DSU_CYAN}check example.com --audit --help${DSU_RESET} for scope and authorization details.

${DSU_BOLD}Output flags${DSU_RESET}
  ${DSU_GREEN}--no-color${DSU_RESET}                 Disable ANSI colors ${DSU_GRAY}(NO_COLOR is also supported)${DSU_RESET}
  ${DSU_GREEN}--color${DSU_RESET}                    Force ANSI colors
  ${DSU_GREEN}--ascii${DSU_RESET}                    Use ASCII status markers
  ${DSU_GREEN}--help, -h${DSU_RESET}                 Show help

${DSU_BOLD}Examples${DSU_RESET}
  ${DSU_CYAN}check example.com${DSU_RESET}
  ${DSU_CYAN}check example.com --no-rdns${DSU_RESET}
  ${DSU_CYAN}check example.com --dns MX${DSU_RESET}
  ${DSU_CYAN}check example.com --mail${DSU_RESET}
  ${DSU_CYAN}ssl c example.com${DSU_RESET}
  ${DSU_CYAN}ssl fetch 203.0.113.10 example.com${DSU_RESET}
  ${DSU_CYAN}check example.com --audit${DSU_RESET}
  ${DSU_CYAN}check example.com --audit --deep --authorized${DSU_RESET}

${DSU_BOLD}Dependencies${DSU_RESET}
  Required: ${DSU_WHITE}bash 4+, curl, openssl, dig (dnsutils), python3, coreutils${DSU_RESET}
  Recommended: ${DSU_WHITE}whois${DSU_RESET}
  Optional: ${DSU_WHITE}sslscan, nmap, file${DSU_RESET}
  Policy DNS fallback: ${DSU_WHITE}1.1.1.1${DSU_RESET} ${DSU_GRAY}(used when the system resolver fails)${DSU_RESET}
  Diagnose: ${DSU_CYAN}check --doctor${DSU_RESET}
  SSL help: ${DSU_CYAN}ssl --help${DSU_RESET}

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
  dsu_keyval "Policy DNS fallback" "${DSU_FALLBACK_RESOLVER:-disabled}"
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
  case "${1:-}" in
    "") _dsu_main_help ;;
    help|--help|-h) _dsu_main_help ;;
    version|--version|-v) printf '%s %s\n' "$DSU_NAME" "$DSU_VERSION" ;;
    doctor|--doctor|diag|--diag) dsu_doctor ;;
    *) dsu_site_check "$@" ;;
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
    *) _dsu_main_help ;;
  esac
}

main "$@"
