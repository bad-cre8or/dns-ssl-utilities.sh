#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -r "$ROOT/lib/core.sh" && -r "$ROOT/lib/presentation.sh" ]]; then
  DSU_SCRIPT_DIR="$ROOT"
  # shellcheck source=lib/core.sh
  source "$ROOT/lib/core.sh"
  # shellcheck source=lib/presentation.sh
  source "$ROOT/lib/presentation.sh"
  dsu_maintenance_options update "$@"
  if (( DSU_MAINT_HELP )); then dsu_help update; exit 0; fi
  dsu_maintenance_header update.sh "$ROOT"
elif [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
  printf 'Usage: ./update.sh\nRun from a Git checkout to pull and reinstall.\n'
  exit 0
fi
if [[ ! -d "$ROOT/.git" ]]; then
  printf 'This copy is not a Git checkout. Replace it with a newer release/archive instead.\n' >&2
  exit 1
fi
git -C "$ROOT" pull --ff-only
"$ROOT/setup.sh" "$@"
