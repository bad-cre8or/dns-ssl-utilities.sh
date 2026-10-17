#!/usr/bin/env bash
# Shared runtime helpers for dns-ssl-utilities.

DSU_VERSION="2.2.2"
DSU_NAME="DNS + SSL Utilities"
DSU_HOME="${DSU_HOME:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
DSU_CONNECT_TIMEOUT="${DSU_CONNECT_TIMEOUT:-4}"
DSU_MAX_TIME="${DSU_MAX_TIME:-8}"
DSU_DNS_TIMEOUT="${DSU_DNS_TIMEOUT:-2}"
DSU_DNS_TRIES="${DSU_DNS_TRIES:-1}"
DSU_WHOIS_TIMEOUT="${DSU_WHOIS_TIMEOUT:-10}"
# The everyday `check` path deliberately uses tighter deadlines than the
# forensic subcommands. A support overview should feel instant; deeper commands
# can afford to wait longer for reluctant remote services.
DSU_CHECK_DNS_TIMEOUT="${DSU_CHECK_DNS_TIMEOUT:-1}"
DSU_CHECK_CONNECT_TIMEOUT="${DSU_CHECK_CONNECT_TIMEOUT:-2}"
DSU_CHECK_MAX_TIME="${DSU_CHECK_MAX_TIME:-4}"
DSU_CHECK_WHOIS_TIMEOUT="${DSU_CHECK_WHOIS_TIMEOUT:-10}"
DSU_CHECK_WHOIS_HANDLE_TIMEOUT="${DSU_CHECK_WHOIS_HANDLE_TIMEOUT:-10}"
DSU_CHECK_PTR_TIMEOUT="${DSU_CHECK_PTR_TIMEOUT:-1}"
DSU_CHECK_POLICY_DNS_TIMEOUT="${DSU_CHECK_POLICY_DNS_TIMEOUT:-3}"
DSU_FALLBACK_RESOLVER="${DSU_FALLBACK_RESOLVER:-1.1.1.1}"
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
    # Tokyo Night, with a 256-color fallback for older terminals.
    if [[ "${COLORTERM:-}" == truecolor || "${COLORTERM:-}" == 24bit ]]; then
      DSU_RED=$'\033[38;2;247;118;142m'; DSU_GREEN=$'\033[38;2;158;206;106m'; DSU_YELLOW=$'\033[38;2;224;175;104m'
      DSU_BLUE=$'\033[38;2;122;162;247m'; DSU_MAGENTA=$'\033[38;2;187;154;247m'; DSU_CYAN=$'\033[38;2;125;207;255m'
      DSU_GRAY=$'\033[38;2;145;156;194m'; DSU_WHITE=$'\033[38;2;192;202;245m'; DSU_RULE=$'\033[38;2;59;66;97m'
    else
      DSU_RED=$'\033[38;5;210m'; DSU_GREEN=$'\033[38;5;150m'; DSU_YELLOW=$'\033[38;5;180m'
      DSU_BLUE=$'\033[38;5;111m'; DSU_MAGENTA=$'\033[38;5;147m'; DSU_CYAN=$'\033[38;5;117m'
      DSU_GRAY=$'\033[38;5;103m'; DSU_WHITE=$'\033[38;5;189m'; DSU_RULE=$'\033[38;5;60m'
    fi
  else
    DSU_RESET=''; DSU_BOLD=''; DSU_DIM=''; DSU_RED=''; DSU_GREEN=''; DSU_YELLOW=''
    DSU_BLUE=''; DSU_MAGENTA=''; DSU_CYAN=''; DSU_GRAY=''; DSU_WHITE=''; DSU_RULE=''
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
  printf '%s%s%s\n' "$DSU_GRAY" 'DNS, TLS, domains, mail, hosting and security diagnostics' "$DSU_RESET"
}

dsu_section() {
  # Preserve compact/plain output for logs and ASCII consumers.
  if (( ! _dsu_color_enabled )) || [[ "${DSU_ASCII:-0}" == 1 ]]; then
    printf '\n%s%s%s %s%s\n' "$DSU_BOLD" "$DSU_BLUE" "$(_dsu_icon '◆' '==')" "$1" "$DSU_RESET"
    return 0
  fi

  local width=80 columns="${COLUMNS:-}" size count rule
  # Non-interactive Bash does not always inherit the shell's COLUMNS value.
  if [[ ! "$columns" =~ ^[0-9]{1,3}$ && -t 1 ]] && dsu_has stty; then
    size=$(stty size <&1 2>/dev/null) || size=''
    columns="${size##* }"
  fi
  if [[ "$columns" =~ ^[0-9]{1,3}$ ]]; then width=$((10#$columns)); fi
  (( width > 88 )) && width=88
  (( width < 24 )) && width=24
  count=$((width - ${#1} - 6))
  (( count < 0 )) && count=0
  printf -v rule '%*s' "$count" ''
  rule="${rule// /─}"
  printf '\n%s◆%s %s%s%s %s%s%s\n' \
    "$DSU_BLUE" "$DSU_RESET" "$DSU_BOLD" "$DSU_WHITE" "$1" \
    "$DSU_RULE" "$rule" "$DSU_RESET"
}

dsu_subsection() {
  printf '\n%s%s%s%s\n' "$DSU_BOLD" "$DSU_MAGENTA" "$1" "$DSU_RESET"
}

# Highlight short field labels without changing their text or spacing.
# Never interpret diagnostic text as a printf format or an escape sequence.
_dsu_message() {
  local color="$1" unicode="$2" ascii="$3" text="$4" label
  printf '  %s%s%s  ' "$color" "$(_dsu_icon "$unicode" "$ascii")" "$DSU_RESET"
  label="${text%%: *}"
  if (( _dsu_color_enabled )) && [[ "$text" == *': '* && ${#label} -le 28 && "$label" != *$'\033'* ]]; then
    printf '%s%s%s: %s%s%s\n' "$DSU_CYAN" "$label" "$DSU_RESET" "$DSU_WHITE" "${text#*: }" "$DSU_RESET"
  else
    printf '%s%s%s\n' "$DSU_WHITE" "$text" "$DSU_RESET"
  fi
}

dsu_ok()   { _dsu_message "$DSU_GREEN"  '✔' '[OK]' "$*"; }
dsu_warn() { _dsu_message "$DSU_YELLOW" '⚠' '[!]'  "$*"; }
dsu_bad()  { _dsu_message "$DSU_RED"    '✘' '[X]'  "$*"; }
dsu_info() { _dsu_message "$DSU_CYAN"   '•' '[i]'  "$*"; }
dsu_dim()  { printf '  %s%s%s\n' "$DSU_GRAY" "$*" "$DSU_RESET"; }

dsu_keyval() {
  local key="$1"; shift
  if (( _dsu_color_enabled )) && [[ "${DSU_ASCII:-0}" != 1 ]]; then
    printf '  %s%-18s%s │ %s%s%s\n' "$DSU_GRAY" "$key" "$DSU_RULE" "$DSU_WHITE" "$*" "$DSU_RESET"
  else
    printf '  %s%-18s%s %s\n' "$DSU_GRAY" "$key" "$DSU_RESET" "$*"
  fi
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

dsu_valid_port() {
  local port="${1:-}"
  [[ "$port" =~ ^[0-9]+$ ]] || return 1
  (( 10#$port >= 1 && 10#$port <= 65535 ))
}

dsu_target_parts() {
  local input="${1:-}" explicit_port="${2:-}" default_port="${3:-443}" host port
  host=$(dsu_normalize_host "$input")
  if [[ -n "$explicit_port" ]]; then port="$explicit_port"; else port=$(dsu_extract_port "$input" "$default_port"); fi
  dsu_valid_host "$host" || return 1
  dsu_valid_port "$port" || return 2
  printf '%s\t%s\n' "$host" "$port"
}

dsu_socket_target() {
  local host="$1" port="$2"
  if [[ "$host" == *:* ]]; then printf '[%s]:%s' "$host" "$port"; else printf '%s:%s' "$host" "$port"; fi
}

dsu_url_authority() {
  local host="$1" port="${2:-}" default_port="${3:-}"
  if [[ "$host" == *:* ]]; then host="[$host]"; fi
  if [[ -n "$port" && "$port" != "$default_port" ]]; then printf '%s:%s' "$host" "$port"; else printf '%s' "$host"; fi
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
  local host="$1" port="${2:-443}" out="$3" target
  target=$(dsu_socket_target "$host" "$port")
  timeout "$DSU_MAX_TIME" openssl s_client -servername "$host" -connect "$target" </dev/null 2>/dev/null \
    | openssl x509 -outform PEM >"$out" 2>/dev/null
  [[ -s "$out" ]]
}

dsu_cert_matches_host() {
  local cert="$1" host="$2" flag expected result
  # OpenSSL x509 can return zero even when it prints "does NOT match".
  # Require its explicit positive result, independently of CA/expiry checks.
  if dsu_is_ip "$host"; then
    flag=-checkip
    expected="IP $host does match certificate"
  else
    flag=-checkhost
    expected="Hostname $host does match certificate"
  fi
  result=$(LC_ALL=C openssl x509 -in "$cert" -noout "$flag" "$host" 2>/dev/null) || return 1
  [[ "$result" == "$expected" ]]
}

dsu_openssl_connection() {
  local host="$1" port="${2:-443}" target
  target=$(dsu_socket_target "$host" "$port")
  timeout "$DSU_MAX_TIME" openssl s_client -servername "$host" -connect "$target" -showcerts </dev/null 2>&1
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
