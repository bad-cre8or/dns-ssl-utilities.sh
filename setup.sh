#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${DSU_INSTALL_DIR:-$HOME/.local/share/dns-ssl-utilities}"
BIN_DIR="${DSU_BIN_DIR:-$HOME/.local/bin}"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

mkdir -p "$BIN_DIR"

if [[ "$(readlink -f "$SOURCE_ROOT")" != "$(readlink -f "$INSTALL_DIR" 2>/dev/null || printf '%s' "$INSTALL_DIR")" ]]; then
  mkdir -p "$INSTALL_DIR"
  # Copy the runnable suite, but do not transplant a source checkout's Git metadata.
  cp -a "$SOURCE_ROOT/dns-ssl-utilities.sh" "$SOURCE_ROOT/lib" "$SOURCE_ROOT/helpers" \
        "$SOURCE_ROOT/setup.sh" "$SOURCE_ROOT/update.sh" "$SOURCE_ROOT/README.md" \
        "$SOURCE_ROOT/.README" "$SOURCE_ROOT/LICENSE" "$INSTALL_DIR/"
  [[ -d "$SOURCE_ROOT/tests" ]] && cp -a "$SOURCE_ROOT/tests" "$INSTALL_DIR/"
  TARGET_ROOT="$INSTALL_DIR"
else
  TARGET_ROOT="$SOURCE_ROOT"
fi

chmod +x "$TARGET_ROOT/dns-ssl-utilities.sh" "$TARGET_ROOT/helpers/"*.py "$TARGET_ROOT/setup.sh" "$TARGET_ROOT/update.sh"

auto_link() {
  local name="$1" target="$TARGET_ROOT/dns-ssl-utilities.sh" dest="$BIN_DIR/$name"
  if [[ -L "$dest" && "$(readlink -f "$dest" 2>/dev/null || true)" == "$(readlink -f "$target")" ]]; then
    printf 'ok   %s already points to this suite\n' "$dest"
    return
  fi
  if [[ -e "$dest" || -L "$dest" ]]; then
    if (( FORCE )); then rm -f "$dest"; else printf 'skip %s already exists (use setup.sh --force to replace)\n' "$dest"; return; fi
  fi
  ln -s "$target" "$dest"
  printf 'link %s -> %s\n' "$dest" "$target"
}

for name in dns-ssl-utilities dsu ssl dnsutil sitecheck vulncheck; do auto_link "$name"; done

printf '\nInstalled suite: %s\n' "$TARGET_ROOT"
printf 'Command links:   %s\n' "$BIN_DIR"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  printf '\nAdd this to your shell profile, then restart/source it:\n  export PATH="%s:$PATH"\n' "$BIN_DIR"
fi
printf '\nTry:\n  dsu --help\n  ssl c example.com\n  sitecheck example.com\n'
