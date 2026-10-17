#!/usr/bin/env bash
# Common presentation only: command arguments and exit codes pass through intact.

_dsu_ui_width() {
  local columns="${COLUMNS:-}" size
  if [[ ! "$columns" =~ ^[0-9]{1,3}$ ]] && dsu_has stty; then
    size=$(stty size 2>/dev/null </dev/tty) || size=''
    columns="${size##* }"
  fi
  [[ "$columns" =~ ^[0-9]{1,3}$ ]] || columns=80
  printf '%s' "$columns"
}

_dsu_ui_wanted() {
  [[ "${DSU_PLAIN:-0}" != 1 && ( -t 1 || "${_dsu_color_enabled:-0}" == 1 ) ]]
}

_dsu_ui_available() {
  dsu_has python3 && [[ -r "${DSU_SCRIPT_DIR:-$DSU_HOME}/helpers/render_ui.py" ]]
}

_dsu_ui_run() {
  python3 "${DSU_SCRIPT_DIR:-$DSU_HOME}/helpers/render_ui.py" "$@" \
    --width "$(_dsu_ui_width)" --color "${_dsu_color_enabled:-0}" --ascii "${DSU_ASCII:-0}"
}

_dsu_help_fallback() {
  # Help must remain usable when Python is the dependency being diagnosed.
  printf '\nDNS + SSL Utilities\n\n'
  if [[ "${1:-check}" == ssl ]]; then
    printf 'Usage: ssl %s\n' "${2:-<command> [arguments]}"
    printf 'Commands: cert quick chain fetch versions ciphers scan ocsp crl ct\n'
    printf '          headers performance fingerprint decode match new pack extract\n'
  elif [[ "${1:-}" == setup ]]; then
    printf 'Usage: ./setup.sh [--force]\nInstalls check and ssl for the current user.\n'
  elif [[ "${1:-}" == update ]]; then
    printf 'Usage: ./update.sh\nRun from a Git checkout to pull and reinstall.\n'
  else
    printf 'Usage: check <domain-or-ip> [flags]\n'
    printf 'Flags: --dns --reverse --mail --dnssec --trace --whois --hosting --audit\n'
  fi
  printf '\nOutput: --no-color --color --ascii --plain --help\n'
  printf 'Python 3 is needed for complete help. Diagnose with: check --doctor\n'
}

dsu_help() {
  local family="${1:-check}" topic="${2:-}"
  local -a extra=()
  _dsu_ui_wanted || extra+=(--plain)
  if _dsu_ui_available && _dsu_ui_run help --family="$family" --topic="$topic" "${extra[@]}"; then
    return 0
  fi
  _dsu_help_fallback "$family" "$topic"
}

dsu_help_request() {
  local family="$1"; shift
  local arg topic='' requested=0
  (( $# == 0 )) && requested=1
  case "${1:-}" in help|--help|-h) requested=1 ;; esac
  for arg in "$@"; do
    [[ "$arg" == --help || "$arg" == -h ]] && requested=1
  done
  (( requested )) || return 1
  if [[ "$family" == ssl ]]; then
    topic="${1:-}"
    case "$topic" in help|--help|-h) topic='' ;; esac
  else
    family=check
    for arg in "$@"; do
      case "$arg" in
        --rdns) topic=reverse; break ;;
        doctor|diag|--diag) topic=doctor; break ;;
        --dns|--reverse|--mail|--dnssec|--trace|--whois|--hosting|--audit|--doctor) topic="${arg#--}"; break ;;
      esac
    done
  fi
  dsu_help "$family" "$topic"
}

_dsu_ui_plain() {
  local line count index
  while IFS= read -r line; do
    if [[ "$line" == $'\036DSU\t'* ]]; then
      count="${line##*$'\t'}"
      [[ "$count" =~ ^[0-9]+$ ]] || continue
      for ((index=0; index<count; index++)); do
        IFS= read -r line || break
        printf '%s\n' "$line"
      done
    else
      printf '%s\n' "$line"
    fi
  done
}

dsu_present() {
  local command="$1" target="$2"; shift 2
  if ! _dsu_ui_wanted || ! _dsu_ui_available; then
    "$@"; return $?
  fi
  if ! _dsu_ui_run header --command="$command" --target="$target"; then
    "$@"; return $?
  fi
  # Vendor tools retain streaming output and their original terminal behavior.
  if [[ "${DSU_UI_NATIVE:-0}" == 1 ]]; then
    "$@"; return $?
  fi
  local output rendered rc=0
  # Only stdout is captured. Stdin and stderr (including password prompts) stay
  # attached to the caller. Presentation never reruns a probe or key operation.
  output=$(dsu_disable_color; DSU_ASCII=1 DSU_UI_CAPTURE=1 "$@") || rc=$?
  if rendered=$(printf '%s\n' "$output" | _dsu_ui_run result --exit-code "$rc"); then
    printf '%s\n' "$rendered"
  else
    _dsu_ui_plain <<<"$output"
  fi
  return "$rc"
}

_dsu_present_check() {
  local arg
  case "${1:-}" in
    doctor|--doctor|diag|--diag) dsu_present 'check --doctor' '' dsu_doctor; return $? ;;
  esac
  for arg in "${@:2}"; do
    case "$arg" in
      --trace) DSU_UI_NATIVE=1 dsu_present "check $arg" "$1" _dsu_dispatch_check_command "$@"; return $? ;;
      --dns|--reverse|--rdns|--mail|--dnssec|--whois|--hosting|--audit)
        dsu_present "check $arg" "$1" _dsu_dispatch_check_command "$@"; return $? ;;
    esac
  done
  _dsu_dispatch_check_command "$@"
}

_dsu_present_ssl() {
  local name="${1:-help}"
  case "${name,,}" in
    chain|ch|decode|d|scan|s|ciphers|cipher|ci|performance|perf|bench)
      DSU_UI_NATIVE=1 dsu_present "ssl $1" "${*:2}" dsu_ssl_dispatch "$@" ;;
    *) dsu_present "ssl ${1:-help}" "${*:2}" dsu_ssl_dispatch "$@" ;;
  esac
}

dsu_maintenance_options() {
  local family="$1" arg; shift
  DSU_MAINT_HELP=0; DSU_MAINT_FORCE=0
  for arg in "$@"; do
    case "$arg" in
      --help|-h) DSU_MAINT_HELP=1 ;;
      --force) [[ "$family" == setup ]] || { printf 'Unknown option: %s\n' "$arg" >&2; return 2; }; DSU_MAINT_FORCE=1 ;;
      --plain) DSU_PLAIN=1 ;;
      --ascii) DSU_ASCII=1 ;;
      --no-color) dsu_disable_color ;;
      --color) _dsu_color_enabled=1; _dsu_apply_colors ;;
      *) printf 'Unknown option: %s\n' "$arg" >&2; return 2 ;;
    esac
  done
}

dsu_maintenance_header() {
  if _dsu_ui_wanted && _dsu_ui_available; then
    _dsu_ui_run header --command="$1" --target="$2" || true
  fi
  return 0
}
