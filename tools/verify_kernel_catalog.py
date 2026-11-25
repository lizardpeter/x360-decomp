#!/usr/bin/env python3
"""Verify kernel import metadata and direct-call census from the original images."""
import argparse
import collections
import csv
import json
import re
from pathlib import Path
from fetch_originals import ROOT
from verify_xui_resources import source
from pirs import parse as parse_pirs
from decode_image import decode
from analyze_decoded import imports, pe_info, direct_calls
from xex import parse

def rows(path):
    with path.open(encoding="utf-8") as f:
        return list(csv.DictReader(f,delimiter="\t"))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--reference-table",type=Path,help="Optional pinned external symbol table, not runtime code")
    p.add_argument("--report",type=Path,help="Optional local per-ordinal metadata report")
    args=p.parse_args()
    catalog=rows(ROOT/"analysis/modules/kernel-import-catalog.tsv")
    by_ordinal={int(r["ordinal"],16):r for r in catalog}
    assert len(by_ordinal)==len(catalog)==519
    assert all(r["implementation"] in ("missing","host_adapter","reconstructed") for r in catalog)
    assert collections.Counter(r["reference_kind"] for r in catalog)=={"function":498,"variable":21}
    if args.reference_table:
        table=args.reference_table.read_text()
        symbols={int(o,16):(n,"function" if k=="kFunction" else "variable") for o,n,k in re.findall(r"XE_EXPORT\(xboxkrnl,\s*(0x[0-9A-Fa-f]+),\s*(\w+),\s*(kFunction|kVariable)\)",table)}
        for o,r in by_ordinal.items():assert symbols[o]==(r["name"],r["reference_kind"])
    pirs=parse_pirs(source("pirs"))
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    seen=set();counts=collections.Counter();sites={};callers={}
    for short,raw,lzx in [("dash",source("dash_basic"),None),("xam",pirs["$flash_xam.xex"]["payload"],args.lzx.resolve())]:
        ident=short+"_17559";image,info=decode(raw,lzx)
        assert info["sha256"]==summary[ident]["sha256"]
        base=info["image_base"];pe=pe_info(image,base);all_imports=imports(image,base,parse(raw))
        kernel={int(r["ordinal"],16):r for r in all_imports if r["library"]=="xboxkrnl.exe"}
        seen.update(kernel)
        for o,r in by_ordinal.items():
            orig=kernel.get(o)
            value=len(orig["value_slots"]) if orig else 0
            thunk=len(orig["thunk_slots"]) if orig else 0
            assert (value,thunk)==(int(r[short+"_value_slots"]),int(r[short+"_thunks"]))
            assert not(thunk and r["reference_kind"]=="variable")
            counts[short+"_slots"]+=value+thunk
        per=collections.Counter();per_callers=collections.defaultdict(set);all_count=0
        for caller,site,target,kind,lib,ordinal in direct_calls(image,base,pe["functions"],all_imports):
            if kind!="import":continue
            all_count+=1
            if lib=="xboxkrnl.exe":
                o=int(ordinal,16);per[o]+=1;per_callers[o].add(caller)
        assert all_count==summary[ident]["direct_import_call_sites"]
        assert sum(per.values())=={"dash":6271,"xam":8567}[short]
        sites[short]=per;callers[short]=per_callers
    assert seen==set(by_ordinal) and sum(counts.values())==1490
    both=sum(bool(int(r["dash_value_slots"])+int(r["dash_thunks"])) and bool(int(r["xam_value_slots"])+int(r["xam_thunks"])) for r in catalog)
    assert both==244
    combined=sites["dash"]+sites["xam"]
    assert combined[304]==2998 and combined[293]==2690
    report=[]
    for o,r in by_ordinal.items():
        report.append(dict(ordinal=r["ordinal"],name=r["name"],kind=r["reference_kind"],dashboard_direct_sites=sites["dash"][o],
                          xam_direct_sites=sites["xam"][o],dashboard_direct_callers=len(callers["dash"][o]),xam_direct_callers=len(callers["xam"][o]),
                          total_direct_sites=combined[o],startup_dependency=o in (403,21),implementation=r["implementation"]))
    report.sort(key=lambda r:(not r["startup_dependency"],-r["total_direct_sites"],r["ordinal"]))
    if args.report:
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(report,indent=2)+"\n")
    print(f"Kernel catalog: {len(catalog)} ordinals (498 function names, 21 variable names), 1,490 slots, {both} shared, {sum(combined.values()):,} original direct call sites.")
    for r in report[:12]:
        print(f"{r['ordinal']} {r['name']}: {r['total_direct_sites']} direct sites; {'startup dependency' if r['startup_dependency'] else 'frequency priority'}; {r['implementation']}")
if __name__=="__main__":main()
