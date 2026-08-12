#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -d "$ROOT/.git" ]]; then
  printf 'This copy is not a Git checkout. Replace it with a newer release/archive instead.\n' >&2
  exit 1
fi
git -C "$ROOT" pull --ff-only
