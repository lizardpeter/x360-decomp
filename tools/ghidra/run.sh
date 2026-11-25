#!/usr/bin/env bash
set -euo pipefail
# Local analysis retains the full project and full output outside Git.
if [[ $# != 2 ]]; then echo "Usage: $0 GHIDRA_HOME MODULE" >&2; exit 2; fi
GHIDRA="$(realpath "$1")"
MODULE="$2"
PROCESSOR="${X360_GHIDRA_PROCESSOR:-PowerPC:BE:64:Xenon}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
python tools/ghidra/prepare.py "$MODULE"
OUT="$ROOT/build/ghidra/$MODULE"
BASE="$(cat "$OUT/base.txt")"
mkdir -p "$OUT/project" "$OUT/export"
rm -f "$OUT/seed_receipt.json" "$OUT/auto_receipt.json" "$OUT/export/reconcile_receipt.json" "$OUT/export/summary.json"
"$GHIDRA/support/analyzeHeadless" "$OUT/project" "$MODULE" \
  -import "$ROOT/originals/decoded/$MODULE.image.bin" \
  -loader BinaryLoader -loader-baseAddr "$BASE" \
  -processor "$PROCESSOR" -cspec default \
  -scriptPath "$ROOT/tools/ghidra" \
  -preScript SeedX360.java "$OUT/seeds.tsv" "$OUT/seed_receipt.json" \
  -postScript CaptureX360.java "$OUT/auto_receipt.json" "$OUT/export/auto_candidates.tsv" \
  -analysisTimeoutPerFile 1800 -log "$OUT/headless.log" -scriptlog "$OUT/scripts.log" \
  -overwrite
test -s "$OUT/seed_receipt.json"
test -s "$OUT/auto_receipt.json"
# Separate no-analysis session prevents Ghidra from re-merging repaired functions.
"$GHIDRA/support/analyzeHeadless" "$OUT/project" "$MODULE" \
  -process "$MODULE.image.bin" -noanalysis \
  -scriptPath "$ROOT/tools/ghidra" \
  -postScript ReconcileX360.java "$OUT/seeds.tsv" "$OUT/export" \
  -postScript ExportX360.java "$OUT/export" "$OUT/seeds.tsv" \
  -log "$OUT/reconcile.log" -scriptlog "$OUT/reconcile-scripts.log"
test -s "$OUT/export/reconcile_receipt.json"
test -s "$OUT/export/summary.json"
python - "$OUT" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1])
s=json.loads((p/"export/summary.json").read_text())
receipt=json.loads((p/"seed_receipt.json").read_text())
auto=json.loads((p/"auto_receipt.json").read_text())
repair=json.loads((p/"export/reconcile_receipt.json").read_text())
print(json.dumps({"seed":receipt,"auto":auto,"reconcile":repair,"export":s},indent=2))
assert s["functions"] == s["decompile_success"]+s["decompile_failed"]
assert s["seed_count"] == s["seeds_found"]+s["missing_seeds"]
assert s["functions"]>0
assert receipt["attempted"] == s["seed_count"]
assert receipt["retained"] == receipt["attempted"] and receipt["failed"] == 0, receipt
assert not auto["analysis_timeout"]
assert repair["retained"]+repair["restored"]+repair["undecoded_entries"] == s["seed_count"]
assert repair["undecoded_entries"] == 0, "unsupported original entry decoding"
assert s["missing_seeds"] == 0, "original seed loss: inspect missing_seeds.tsv"
assert s["empty_disassembly"] == 0 and s["missing_entry_instruction"] == 0
assert s["decompile_failed"] == 0, "decompilation failures: inspect decompile_errors.tsv"
PY
