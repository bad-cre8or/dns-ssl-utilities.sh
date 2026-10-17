#!/usr/bin/env bash
# Presentation adapter. The existing check remains the only source of results.

dsu_site_report() {
  local arg helper="${DSU_SCRIPT_DIR:-$DSU_HOME}/helpers/render_report.py"
  local rich=0
  [[ -t 1 ]] && rich=1
  [[ "${_dsu_color_enabled:-0}" == 1 ]] && rich=1

  # Utility modes, errors, pipes, and --plain retain their existing behavior.
  # Only the default overview gets a dashboard; never parse raw WHOIS here.
  if [[ "${DSU_PLAIN:-0}" == 1 ]] || (( ! rich )) || ! dsu_has python3 || [[ ! -r "$helper" ]]; then
    dsu_site_check "$@"
    return $?
  fi
  for arg in "${@:2}"; do
    case "$arg" in
      --no-rdns|--no-ptr|--fresh) ;;
      *) dsu_site_check "$@"; return $? ;;
    esac
  done

  local report rendered rc=0 columns="${COLUMNS:-}" size
  if [[ ! "$columns" =~ ^[0-9]{1,3}$ && -t 1 ]] && dsu_has stty; then
    # Inside $(...), stdout is a pipe; query the controlling terminal instead.
    size=$(stty size 2>/dev/null </dev/tty) || size=''
    columns="${size##* }"
  fi
  [[ "$columns" =~ ^[0-9]{1,3}$ ]] || columns=80

  # Run the original probe once, with its original timeouts and concurrency.
  # A subshell confines the plain transport format to this rendering adapter.
  report=$(dsu_disable_color; DSU_ASCII=1 dsu_site_check "$@") || rc=$?
  if (( rc != 0 )); then
    [[ -z "$report" ]] || printf '%s\n' "$report"
    return "$rc"
  fi

  # Buffer rendering too, so an unavailable/broken renderer can fall back
  # without dropping results or emitting half a dashboard.
  if rendered=$(printf '%s\n' "$report" | python3 "$helper" \
      --host "$(dsu_normalize_host "${1:-}")" --width "$columns" \
      --color "${_dsu_color_enabled:-0}" --ascii "${DSU_ASCII:-0}"); then
    printf '%s\n' "$rendered"
  else
    printf '%s\n' "$report"
  fi
}
