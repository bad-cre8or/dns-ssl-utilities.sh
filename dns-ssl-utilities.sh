#!/usr/bin/env bash
set -o pipefail

DSU_SCRIPT_PATH="$(readlink -f -- "${BASH_SOURCE[0]}")"
DSU_SCRIPT_DIR="$(cd -- "$(dirname -- "$DSU_SCRIPT_PATH")" && pwd)"
# shellcheck source=lib/core.sh
source "$DSU_SCRIPT_DIR/lib/core.sh"
# shellcheck source=lib/presentation.sh
source "$DSU_SCRIPT_DIR/lib/presentation.sh"
# shellcheck source=lib/dns.sh
source "$DSU_SCRIPT_DIR/lib/dns.sh"
# shellcheck source=lib/ssl.sh
source "$DSU_SCRIPT_DIR/lib/ssl.sh"
# shellcheck source=lib/site.sh
source "$DSU_SCRIPT_DIR/lib/site.sh"
# shellcheck source=lib/report.sh
source "$DSU_SCRIPT_DIR/lib/report.sh"
# shellcheck source=lib/security.sh
source "$DSU_SCRIPT_DIR/lib/security.sh"

_dsu_main_help() { dsu_help check; }

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
    *) dsu_site_report "$@" ;;
  esac
}

main() {
  DSU_UI_CAPTURE=0
  local args=("$@") cleaned=() arg
  for arg in "${args[@]}"; do
    case "$arg" in
      --no-color) dsu_disable_color ;;
      --color) _dsu_color_enabled=1; _dsu_apply_colors ;;
      --ascii) DSU_ASCII=1 ;;
      --plain) DSU_PLAIN=1 ;;
      *) cleaned+=("$arg") ;;
    esac
  done
  set -- "${cleaned[@]}"

  local invoked
  invoked=$(basename -- "$0")
  if dsu_help_request "$invoked" "$@"; then return 0; fi
  case "$invoked" in
    check) _dsu_present_check "$@" ;;
    ssl) _dsu_present_ssl "$@" ;;
    *) _dsu_main_help ;;
  esac
}

main "$@"
