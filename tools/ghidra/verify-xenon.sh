#!/usr/bin/env bash
set -euo pipefail
GHIDRA="$(realpath "$1")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/build/xenon-smoke"
mkdir -p "$OUT/project"
rm -f "$OUT/receipt"
python - "$OUT/words.bin" <<'PY'
import struct,sys
# Exact opcode evidence from the two independently hash-verified images.
open(sys.argv[1],"wb").write(struct.pack(">III",0x18a20f34,0x17fff2f5,0x4e800020))
PY
"$GHIDRA/support/analyzeHeadless" "$OUT/project" smoke \
    -import "$OUT/words.bin" -loader BinaryLoader -loader-baseAddr 0x10000 \
    -processor PowerPC:BE:64:Xenon -cspec default -noanalysis -overwrite \
    -scriptPath "$ROOT/tools/ghidra" -postScript VerifyXenon.java "$OUT/receipt"
test "$(cat "$OUT/receipt")" = ok
