#!/usr/bin/env bash
set -euo pipefail
# Install only the pinned Xenon language extension into the stock 12.2 tool.
GHIDRA="$(realpath "$1")"
EXT="$(realpath "$2")"
DEST="$GHIDRA/Ghidra/Extensions"
mkdir -p "$DEST"
unzip -q "$EXT" -d "$DEST"
PROPS="$(find "$DEST" -maxdepth 3 -name extension.properties -path '*GhidraXenon*' | head -1)"
test -f "$PROPS"
sed -i 's/^version=.*/version=12.2/' "$PROPS"
LANG="$(dirname "$PROPS")/data/languages/ppc_64_xenon.slaspec"
test -f "$LANG"
# Recompile the extension's original language sources with the host Ghidra
# version, rather than relying on cross-version compiled SLA compatibility.
"$GHIDRA/support/sleigh" "$LANG"
test -s "${LANG%.slaspec}.sla"
