#!/usr/bin/env bash
# Shared runtime helpers for dns-ssl-utilities.

DSU_VERSION="2.2.0"
DSU_NAME="DNS + SSL Utilities"
DSU_HOME="${DSU_HOME:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
DSU_CONNECT_TIMEOUT="${DSU_CONNECT_TIMEOUT:-4}"
DSU_MAX_TIME="${DSU_MAX_TIME:-8}"
DSU_DNS_TIMEOUT="${DSU_DNS_TIMEOUT:-2}"
DSU_DNS_TRIES="${DSU_DNS_TRIES:-1}"
DSU_WHOIS_TIMEOUT="${DSU_WHOIS_TIMEOUT:-7}"
# The everyday `check` path deliberately uses tighter deadlines than the
# forensic subcommands. A support overview should feel instant; deeper commands
# can afford to wait longer for reluctant remote services.
DSU_CHECK_DNS_TIMEOUT="${DSU_CHECK_DNS_TIMEOUT:-1}"
DSU_CHECK_CONNECT_TIMEOUT="${DSU_CHECK_CONNECT_TIMEOUT:-2}"
DSU_CHECK_MAX_TIME="${DSU_CHECK_MAX_TIME:-4}"
DSU_CHECK_WHOIS_TIMEOUT="${DSU_CHECK_WHOIS_TIMEOUT:-2}"
DSU_CHECK_WHOIS_HANDLE_TIMEOUT="${DSU_CHECK_WHOIS_HANDLE_TIMEOUT:-1}"
DSU_CHECK_PTR_TIMEOUT="${DSU_CHECK_PTR_TIMEOUT:-1}"
DSU_REGISTRAR_CACHE_TTL="${DSU_REGISTRAR_CACHE_TTL:-21600}"
DSU_USER_AGENT="${DSU_USER_AGENT:-dns-ssl-utilities/${DSU_VERSION}}"

_dsu_color_enabled=1
if [[ -n "${NO_COLOR:-}" || "${TERM:-}" == "dumb" || ! -t 1 ]]; then
  _dsu_color_enabled=0
fi
if [[ "${DSU_FORCE_COLOR:-0}" == "1" ]]; then
  _dsu_color_enabled=1
fi

_dsu_apply_colors() {
  if (( _dsu_color_enabled )); then
    DSU_RESET=$'\033[0m'; DSU_BOLD=$'\033[1m'; DSU_DIM=$'\033[2m'
    DSU_RED=$'\033[38;5;203m'; DSU_GREEN=$'\033[38;5;114m'; DSU_YELLOW=$'\033[38;5;220m'
    DSU_BLUE=$'\033[38;5;75m'; DSU_MAGENTA=$'\033[38;5;176m'; DSU_CYAN=$'\033[38;5;81m'
    DSU_GRAY=$'\033[38;5;245m'; DSU_WHITE=$'\033[38;5;255m'
  else
    DSU_RESET=''; DSU_BOLD=''; DSU_DIM=''; DSU_RED=''; DSU_GREEN=''; DSU_YELLOW=''
    DSU_BLUE=''; DSU_MAGENTA=''; DSU_CYAN=''; DSU_GRAY=''; DSU_WHITE=''
  fi
}
_dsu_apply_colors

_dsu_icon() {
  local unicode="$1" ascii="$2"
  if [[ "${DSU_ASCII:-0}" == "1" ]]; then printf '%s' "$ascii"; else printf '%s' "$unicode"; fi
}

dsu_disable_color() { _dsu_color_enabled=0; _dsu_apply_colors; }

dsu_banner() {
  printf '\n%s%s%s%s\n' "$DSU_BOLD" "$DSU_CYAN" "$DSU_NAME" "$DSU_RESET"
  printf '%s%s%s\n' "$DSU_GRAY" 'DNS, TLS, certificate, hosting and web-security diagnostics' "$DSU_RESET"
}

dsu_section() {
  printf '\n%s%s%s %s%s\n' "$DSU_BOLD" "$DSU_BLUE" "$(_dsu_icon '◆' '==')" "$1" "$DSU_RESET"
}

dsu_subsection() {
  printf '\n%s%s%s%s\n' "$DSU_BOLD" "$DSU_MAGENTA" "$1" "$DSU_RESET"
}

dsu_ok()   { printf '  %s%s%s  %s\n' "$DSU_GREEN" "$(_dsu_icon '✔' '[OK]')" "$DSU_RESET" "$*"; }
dsu_warn() { printf '  %s%s%s  %s\n' "$DSU_YELLOW" "$(_dsu_icon '⚠' '[!]')" "$DSU_RESET" "$*"; }
dsu_bad()  { printf '  %s%s%s  %s\n' "$DSU_RED" "$(_dsu_icon '✘' '[X]')" "$DSU_RESET" "$*"; }
dsu_info() { printf '  %s%s%s  %s\n' "$DSU_CYAN" "$(_dsu_icon '•' '[i]')" "$DSU_RESET" "$*"; }
dsu_dim()  { printf '  %s%s%s\n' "$DSU_GRAY" "$*" "$DSU_RESET"; }

dsu_keyval() {
  local key="$1"; shift
  printf '  %s%-18s%s %s\n' "$DSU_GRAY" "$key" "$DSU_RESET" "$*"
}

dsu_die() { dsu_bad "$*" >&2; return 1; }

dsu_has() { command -v "$1" >/dev/null 2>&1; }

dsu_need() {
  local cmd="$1" package="${2:-$1}"
  if ! dsu_has "$cmd"; then
    dsu_bad "Missing dependency: ${DSU_BOLD}${cmd}${DSU_RESET}"
    dsu_info "Ubuntu/WSL: sudo apt install ${package}"
    return 127
  fi
}

dsu_join_by() {
  local sep="$1"; shift
  local first=1 item
  for item in "$@"; do
    if (( first )); then first=0; else printf '%s' "$sep"; fi
    printf '%s' "$item"
  done
}

dsu_trim() {
  local value="$*"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

dsu_normalize_host() {
  local value="${1:-}"
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value#http://}"
  value="${value#https://}"
  value="${value#ftp://}"
  value="${value%%/*}"
  value="${value%%\?*}"
  value="${value%%\#*}"
  if [[ "$value" == \[*\]* ]]; then
    value="${value#[}"
    value="${value%%]*}"
  elif [[ "$value" == *:* && "$value" != *:*:* ]]; then
    value="${value%%:*}"
  fi
  value="${value%.}"
  printf '%s' "${value,,}"
}

dsu_normalize_url() {
  local value="${1:-}"
  if [[ "$value" != http://* && "$value" != https://* ]]; then value="https://$value"; fi
  printf '%s' "$value"
}

dsu_valid_host() {
  local host="$1"
  [[ -n "$host" ]] || return 1
  if [[ "$host" == *:* ]]; then
    python3 - "$host" <<'PY' >/dev/null 2>&1
import ipaddress, sys
ipaddress.ip_address(sys.argv[1])
PY
    return $?
  fi
  [[ ${#host} -le 253 && "$host" != *..* ]] || return 1
  if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    dsu_is_ip "$host"
    return $?
  fi
  [[ "$host" == *.* ]] || return 1
  local label IFS='.'
  read -ra labels <<< "$host"
  for label in "${labels[@]}"; do
    [[ -n "$label" && ${#label} -le 63 && "$label" != -* && "$label" != *- && "$label" =~ ^[A-Za-z0-9-]+$ ]] || return 1
  done
}

dsu_is_ip() {
  local value="${1:-}" octet
  if [[ "$value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local IFS='.'
    local -a _dsu_octets=()
    read -ra _dsu_octets <<< "$value"
    for octet in "${_dsu_octets[@]}"; do
      [[ "$octet" =~ ^[0-9]+$ ]] || return 1
      (( 10#$octet <= 255 )) || return 1
    done
    return 0
  fi
  [[ "$value" == *:* ]] || return 1
  # IPv6 syntax has enough edge cases that the standard library remains the
  # safest validator, but only invoke Python when the input actually looks IPv6.
  python3 - "$value" <<'PYIP' >/dev/null 2>&1
import ipaddress, sys
try:
    ipaddress.IPv6Address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
PYIP
}
dsu_extract_port() {
  local input="$1" default="${2:-443}"
  input="${input#http://}"; input="${input#https://}"; input="${input%%/*}"
  if [[ "$input" =~ :([0-9]+)$ && "$input" != *:*:* ]]; then printf '%s' "${BASH_REMATCH[1]}"; else printf '%s' "$default"; fi
}

dsu_tmpdir() {
  mktemp -d "${TMPDIR:-/tmp}/dns-ssl-utilities.XXXXXX"
}

dsu_cleanup_dir() { [[ -n "${1:-}" && -d "$1" ]] && rm -rf -- "$1"; }

dsu_http_headers() {
  local url="$1"; shift
  curl -ksS -D - -o /dev/null --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" \
    -A "$DSU_USER_AGENT" "$@" "$url" 2>/dev/null
}

dsu_http_status() {
  local url="$1"; shift
  local output rc
  output=$(curl -ksS -o /dev/null -w '%{http_code}' --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" \
    -A "$DSU_USER_AGENT" "$@" "$url" 2>/dev/null)
  rc=$?
  if [[ "$output" =~ ([0-9]{3})$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
  elif (( rc != 0 )); then
    printf '000'
  else
    printf '%s' "${output:-000}"
  fi
}

dsu_http_final_headers() {
  local url="$1"; shift
  curl -ksS -D - -o /dev/null -L --connect-timeout "$DSU_CONNECT_TIMEOUT" --max-time "$DSU_MAX_TIME" \
    -A "$DSU_USER_AGENT" "$@" "$url" 2>/dev/null | awk '''
      /^HTTP\// { block=$0 ORS; next }
      { block=block $0 ORS }
      END { printf "%s", block }
    '''
}

dsu_header_value() {
  local headers="$1" name="$2"
  printf '%s\n' "$headers" | awk -v IGNORECASE=1 -v key="$name" '
    BEGIN { FS=":" }
    tolower($1)==tolower(key) { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit }
  '
}

dsu_header_values() {
  local headers="$1" name="$2"
  printf '%s\n' "$headers" | awk -v IGNORECASE=1 -v key="$name" '
    BEGIN { FS=":" }
    tolower($1)==tolower(key) { sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print }
  '
}

dsu_http_code_from_headers() {
  local headers="$1" code
  code=$(printf '%s\n' "$headers" | awk '/^HTTP\// {gsub(/\r/, "", $2); code=$2} END {if (code ~ /^[0-9][0-9][0-9]$/) print code}')
  printf '%s' "${code:-000}"
}

dsu_fetch_leaf_cert() {
  local host="$1" port="${2:-443}" out="$3"
  timeout "$DSU_MAX_TIME" openssl s_client -servername "$host" -connect "$host:$port" </dev/null 2>/dev/null \
    | openssl x509 -outform PEM >"$out" 2>/dev/null
  [[ -s "$out" ]]
}

dsu_openssl_connection() {
  local host="$1" port="${2:-443}"
  timeout "$DSU_MAX_TIME" openssl s_client -servername "$host" -connect "$host:$port" -showcerts </dev/null 2>&1
}

dsu_days_until() {
  local date_string="$1" expiry now
  expiry=$(date -d "$date_string" +%s 2>/dev/null) || return 1
  now=$(date +%s)
  printf '%d' $(( (expiry - now) / 86400 ))
}

dsu_shell_quote() { printf '%q' "$1"; }

DSU_FIND_INFO=0
DSU_FIND_LOW=0
DSU_FIND_MEDIUM=0
DSU_FIND_HIGH=0
DSU_FIND_CRITICAL=0

dsu_find_reset() { DSU_FIND_INFO=0; DSU_FIND_LOW=0; DSU_FIND_MEDIUM=0; DSU_FIND_HIGH=0; DSU_FIND_CRITICAL=0; }

dsu_finding() {
  local severity="${1^^}"; shift
  local label color icon
  case "$severity" in
    CRITICAL) ((DSU_FIND_CRITICAL+=1)); label="CRITICAL"; color="$DSU_RED"; icon="$(_dsu_icon '‼' '[!!]')" ;;
    HIGH)     ((DSU_FIND_HIGH+=1));     label="HIGH";     color="$DSU_RED"; icon="$(_dsu_icon '✘' '[X]')" ;;
    MEDIUM)   ((DSU_FIND_MEDIUM+=1));   label="MEDIUM";   color="$DSU_YELLOW"; icon="$(_dsu_icon '▲' '[!]')" ;;
    LOW)      ((DSU_FIND_LOW+=1));      label="LOW";      color="$DSU_MAGENTA"; icon="$(_dsu_icon '△' '[-]')" ;;
    *)        ((DSU_FIND_INFO+=1));     label="INFO";     color="$DSU_CYAN"; icon="$(_dsu_icon '•' '[i]')" ;;
  esac
  printf '  %s%s %-8s%s %s\n' "$color" "$icon" "$label" "$DSU_RESET" "$*"
}

dsu_finding_summary() {
  dsu_section "Audit summary"
  printf '  %sCritical%s %d   %sHigh%s %d   %sMedium%s %d   %sLow%s %d   %sInfo%s %d\n' \
    "$DSU_RED" "$DSU_RESET" "$DSU_FIND_CRITICAL" \
    "$DSU_RED" "$DSU_RESET" "$DSU_FIND_HIGH" \
    "$DSU_YELLOW" "$DSU_RESET" "$DSU_FIND_MEDIUM" \
    "$DSU_MAGENTA" "$DSU_RESET" "$DSU_FIND_LOW" \
    "$DSU_CYAN" "$DSU_RESET" "$DSU_FIND_INFO"
}
