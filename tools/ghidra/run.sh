#!/usr/bin/env bash
set -euo pipefail
# Local analysis: retains project and full output outside Git. Use verified images only.
if [[ $# != 2 ]]; then echo "Usage: $0 GHIDRA_HOME MODULE" >&2; exit 2; fi
GHIDRA="$(realpath "$1")"
MODULE="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python tools/ghidra/prepare.py "$MODULE"
OUT="$ROOT/build/ghidra/$MODULE"
BASE="$(cat "$OUT/base.txt")"
mkdir -p "$OUT/project" "$OUT/export"
rm -f "$OUT/seed_receipt.json" "$OUT/export/summary.json"
"$GHIDRA/support/analyzeHeadless" "$OUT/project" "$MODULE" \
  -import "$ROOT/originals/decoded/$MODULE.image.bin" \
  -loader BinaryLoader -loader-baseAddr "$BASE" \
  -processor PowerPC:BE:64:64-32addr -cspec default \
  -scriptPath "$ROOT/tools/ghidra" \
  -preScript SeedX360.java "$OUT/seeds.tsv" "$OUT/seed_receipt.json" \
  -postScript ExportX360.java "$OUT/export" "$OUT/seeds.tsv" \
  -analysisTimeoutPerFile 1800 -log "$OUT/headless.log" -scriptlog "$OUT/scripts.log" \
  -overwrite
test -s "$OUT/seed_receipt.json"
test -s "$OUT/export/summary.json"
python - "$OUT" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
s=json.loads((p/"export/summary.json").read_text())
assert s["functions"] == s["decompile_success"]+s["decompile_failed"]
assert s["seed_count"] == s["seeds_found"]+s["missing_seeds"]
assert s["functions"]>0
receipt=json.loads((p/"seed_receipt.json").read_text())
assert receipt["attempted"] == s["seed_count"], "seed script did not process every expected function"
assert receipt["retained"] == receipt["attempted"] and receipt["failed"] == 0, receipt
assert not s["analysis_timeout"], "auto-analysis timed out"
assert s["missing_seeds"] == 0, "original seed loss: inspect missing_seeds.tsv"
assert s["empty_disassembly"] == 0 and s["missing_entry_instruction"] == 0, "empty disassembly"
assert s["decompile_failed"] == 0, "decompilation failures: inspect decompile_errors.tsv"
print(json.dumps(s,indent=2))
PY
