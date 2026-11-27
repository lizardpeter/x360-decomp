#!/usr/bin/env python3
"""Verified native HUD dependency inventory. No executable or resource bytes emitted."""
import argparse
import collections
import json
from pathlib import Path
from analyze_decoded import pe_info, imports, ordinal_exports, direct_calls
from decode_image import decode
from metro_import_contracts import DIGESTS, sdk_catalog, library, hx
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from xex import parse as parse_xex

HUD_SHA = "37e10612afde211e1d349838704f7cc2648ad5a4d1f8ca459f18ecd2c1f31ac7"

def inventory(members, lzx, catalog, stubs):
    hud=members["$flash_hud.xex"]["payload"]
    xam=members["$flash_xam.xex"]["payload"]
    if sha(hud)!=HUD_SHA or sha(xam)!=EXPECTED["xam_17559"]:
        raise ValueError("HUD or XAM original identity mismatch")
    hi,hm=decode(hud,lzx)
    xi,xm=decode(xam,lzx)
    if xm["sha256"]!=DIGESTS["xam"]:
        raise ValueError("decoded XAM identity mismatch")
    hb,xb=hm["image_base"],xm["image_base"]
    hp,xp=pe_info(hi,hb),pe_info(xi,xb)
    if hb!=0x913e0000 or hm["image_bytes"]!=299008 or hp is None or xp is None:
        raise ValueError("unexpected HUD/XAM layout")
    if not (hb+len(hi)<=xb or xb+len(xi)<=hb):
        raise ValueError("HUD/XAM ranges overlap")
    exports=dict(ordinal_exports(xi,xb,xam))
    rows=imports(hi,hb,parse_xex(hud))
    calls=collections.Counter((lib,ordinal) for _,_,_,kind,lib,ordinal
                              in direct_calls(hi,hb,hp["functions"],rows) if kind=="import")
    bindings=[]
    for row in rows:
        lib=library(row["library"])
        ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("","unknown"))
        target=exports.get(ordinal) if lib=="xam" else None
        section=next((s for s in xp["sections"]
                      if target is not None and xb+s["rva"]<=target<xb+s["rva"]+s["loaded_bytes"]),None)
        native_kind=None if section is None else ("function" if section["flags"]&0x20000000 else "data")
        requested_kind="function" if row["thunk_slots"] else "data"
        bindings.append({"library":lib,"ordinal":row["ordinal"],"name":name,"sdk_kind":kind,
                         "sdk_stub":name in stubs,"requested_kind":requested_kind,
                         "values":[hx(a) for a in row["value_slots"]],
                         "thunks":[hx(a) for a in row["thunk_slots"]],
                         "retail_target":None if target is None else hx(target),
                         "retail_kind":native_kind,
                         "retail_kind_matches":native_kind==requested_kind if lib=="xam" else None,
                         "direct_call_sites":calls[row["library"],row["ordinal"]]})
    xam_rows=[r for r in bindings if r["library"]=="xam"]
    return {"source_sha256":sha(hud),"decoded_sha256":hm["sha256"],
            "base":hx(hb),"entry":hx(hp["entry_point"]),"bytes":len(hi),
            "pdata_functions":len(hp["functions"]),
            "import_counts":dict(collections.Counter(r["library"] for r in bindings)),
            "retail_xam_function_bindings":sum(r["retail_kind_matches"] and r["requested_kind"]=="function" for r in xam_rows),
            "retail_xam_data_bindings":sum(r["retail_kind_matches"] and r["requested_kind"]=="data" for r in xam_rows),
            "retail_xam_unresolved":[r for r in xam_rows if not r["retail_kind_matches"]],
            "other_sdk_unknown_or_stub":[r for r in bindings if r["library"]!="xam" and (r["sdk_kind"]=="unknown" or r["sdk_stub"])],
            "imports":bindings,
            "scope":"original import inventory and exact retail target kinds; not a native HUD execution claim"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):
        p.error("write only under build/")
    catalog,stubs=sdk_catalog(a.sdk)
    report=inventory(parse_pirs(original("pirs")),a.lzx.resolve(),catalog,stubs)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({k:v for k,v in report.items() if k!="imports"},sort_keys=True))
if __name__=="__main__":main()
