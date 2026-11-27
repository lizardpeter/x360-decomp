#!/usr/bin/env python3
"""Prepare only pinned original inputs locally; nothing is uploaded."""
import json
import sys
from pathlib import Path
from fetch_originals import ROOT,config,acquire,check
from prepare_recompilation import original
from pirs import parse as parse_pirs
from stage_dashboard_runtime import stage,put,acquire_font_complements

def main():
    if sys.version_info<(3,11):raise SystemExit("Python 3.11 or newer required")
    cfg=config()
    for item in cfg["source"]:
        if item["id"] in ("pirs","shared_resources"):
            path=acquire(item,ROOT/"originals",cfg["r2_public"])
            check(path,item)
    members=parse_pirs(original("pirs"))
    census=json.loads((ROOT/"analysis/pirs_17559/members.json").read_text())
    fonts=acquire_font_complements(ROOT/"build/metro-font-complements",cfg)
    inputs=ROOT/"inputs"
    result=stage(inputs,members,census,original("shared_resources"),fonts,True,True)
    # Native module loader expects these sibling paths as well as the
    # original system/ and flash/ resource trees.
    for name in ("xam","hud"):
        result["files"].append(put(inputs,name+".xex",members["$flash_"+name+".xex"]["payload"]))
    result["files"].sort(key=lambda r:r["path"])
    result["file_count"]=len(result["files"])
    result["total_bytes"]=sum(r["bytes"] for r in result["files"])
    (ROOT/"local-input-receipt.json").write_text(json.dumps(result,indent=2)+"\n")
    print("Verified local runtime files:",result["file_count"])
if __name__=="__main__":main()
