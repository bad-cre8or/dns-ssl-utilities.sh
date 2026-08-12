#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${DSU_INSTALL_DIR:-$HOME/.local/share/dns-ssl-utilities}"
BIN_DIR="${DSU_BIN_DIR:-$HOME/.local/bin}"
FORCE=0

case "${1:-}" in
  --force) FORCE=1 ;;
  -h|--help)
    cat <<'HELP'
Usage: ./setup.sh [--force]

Install DNS + SSL Utilities into the current user's home directory.

Options:
  --force      Replace conflicting command links in ~/.local/bin
  -h, --help   Show this help

Environment:
  DSU_INSTALL_DIR   Override installation directory
                    Default: ~/.local/share/dns-ssl-utilities
  DSU_BIN_DIR       Override command-link directory
                    Default: ~/.local/bin

Installed command links:
  check  ssl  dnsutil  vulncheck  sitecheck
  dsu and dns-ssl-utilities are retained for compatibility.
HELP
    exit 0
    ;;
  '') ;;
  *)
    printf 'Unknown setup option: %s\nTry: ./setup.sh --help\n' "$1" >&2
    exit 2
    ;;
esac

# Only these are required to run the suite. Documentation and developer files
# are intentionally optional so a minimal checkout/package can still install.
required_paths=(
  dns-ssl-utilities.sh
  lib
  helpers
)

for rel in "${required_paths[@]}"; do
  if [[ ! -e "$SOURCE_ROOT/$rel" ]]; then
    printf 'error: required suite component is missing: %s\n' "$SOURCE_ROOT/$rel" >&2
    exit 1
  fi
done

mkdir -p "$BIN_DIR"

canonical_path() {
  readlink -f -- "$1" 2>/dev/null || printf '%s\n' "$1"
}

copy_if_present() {
  local rel="$1"
  [[ -e "$SOURCE_ROOT/$rel" ]] || return 0
  cp -a -- "$SOURCE_ROOT/$rel" "$INSTALL_DIR/"
}

if [[ "$(canonical_path "$SOURCE_ROOT")" != "$(canonical_path "$INSTALL_DIR")" ]]; then
  mkdir -p "$INSTALL_DIR"

  # Copy the runnable suite, but never transplant a source checkout's Git
  # metadata. Optional docs/developer files are copied when available.
  for rel in "${required_paths[@]}"; do
    cp -a -- "$SOURCE_ROOT/$rel" "$INSTALL_DIR/"
  done

  optional_paths=(
    setup.sh
    update.sh
    README.md
    .README
    LICENSE
    tests
  )
  for rel in "${optional_paths[@]}"; do
    copy_if_present "$rel"
  done

  TARGET_ROOT="$INSTALL_DIR"
else
  TARGET_ROOT="$SOURCE_ROOT"
fi

chmod +x "$TARGET_ROOT/dns-ssl-utilities.sh"
[[ -f "$TARGET_ROOT/setup.sh" ]] && chmod +x "$TARGET_ROOT/setup.sh"
[[ -f "$TARGET_ROOT/update.sh" ]] && chmod +x "$TARGET_ROOT/update.sh"
if [[ -d "$TARGET_ROOT/helpers" ]]; then
  while IFS= read -r -d '' helper; do
    chmod +x "$helper"
  done < <(find "$TARGET_ROOT/helpers" -maxdepth 1 -type f -name '*.py' -print0)
fi

auto_link() {
  local name="$1"
  local target="$TARGET_ROOT/dns-ssl-utilities.sh"
  local dest="$BIN_DIR/$name"

  if [[ -L "$dest" && "$(canonical_path "$dest")" == "$(canonical_path "$target")" ]]; then
    printf 'ok   %s already points to this suite\n' "$dest"
    return
  fi

  if [[ -e "$dest" || -L "$dest" ]]; then
    if (( FORCE )); then
      rm -f -- "$dest"
    else
      printf 'skip %s already exists (use setup.sh --force to replace)\n' "$dest"
      return
    fi
  fi

  ln -s "$target" "$dest"
  printf 'link %s -> %s\n' "$dest" "$target"
}

for name in check ssl dnsutil vulncheck sitecheck dsu dns-ssl-utilities; do
  auto_link "$name"
done

printf '\nInstalled suite: %s\n' "$TARGET_ROOT"
printf 'Command links:   %s\n' "$BIN_DIR"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  printf '\nAdd this to your shell profile, then restart/source it:\n  export PATH="%s:$PATH"\n' "$BIN_DIR"
fi
printf '\nTry:\n  check example.com\n  check --help\n  ssl c example.com\n'
