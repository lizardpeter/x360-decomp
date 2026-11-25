#!/usr/bin/env python3
"""Validate native mapping and ordinal resolution using both original loaded images."""
import argparse
import csv
import json
import subprocess
import tempfile
from pathlib import Path
from analyze_decoded import pe_info, imports, ordinal_exports
from decode_image import decode
from fetch_originals import ROOT
from pirs import parse as parse_pirs
from verify_xui_resources import source
from xex import parse

def write_module(temp,name,ident,raw,lzx,summary):
    image,info=decode(raw,lzx)
    expected=summary[ident]
    assert info["sha256"]==expected["sha256"] and info["image_base"]==expected["image_base"]
    pe=pe_info(image,info["image_base"])
    assert pe["entry_point"]==expected["pe"]["entry_point"]
    assert pe["sections"]==expected["pe"]["sections"]
    rows=imports(image,info["image_base"],parse(raw))
    recorded=list(csv.DictReader((ROOT/"analysis"/ident/"imports.tsv").open(),delimiter="\t"))
    actual=[dict(library=r["library"],ordinal=r["ordinal"],value_slots=",".join(f"{x:08X}" for x in r["value_slots"]),thunk_slots=",".join(f"{x:08X}" for x in r["thunk_slots"])) for r in rows]
    assert actual==recorded
    output=[f"M {name} {ident} {info['image_base']} {len(image)} {pe['entry_point']}"]
    output.extend(f"S {info['image_base']+r['rva']} {r['loaded_bytes']} {r['flags']}" for r in pe["sections"] if r["loaded_bytes"])
    for r in rows:
        for kind,key in enumerate(("value_slots","thunk_slots")):
            output.extend(f"I {a} {r['library']} {int(r['ordinal'],16)} {kind}" for a in r[key])
    if ident=="xam_17559":
        exports=ordinal_exports(image,info["image_base"],raw)
        recorded=list(csv.DictReader((ROOT/"analysis"/ident/"exports.tsv").open(),delimiter="\t"))
        assert [(f"{o:04X}",f"{a:08X}") for o,a in exports]==[(r["ordinal"],r["address"]) for r in recorded]
        output.extend(f"E {o} {a}" for o,a in exports)
    binary=temp/(ident+".bin");manifest=temp/(ident+".tsv")
    binary.write_bytes(image);manifest.write_text("\n".join(output)+"\n")
    return [str(manifest),str(binary)]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path);p.add_argument("--lzx",required=True,type=Path);a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    pirs=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        temp=Path(d)
        dash=write_module(temp,"dash.xex","dash_17559",source("dash_basic"),None,summary)
        xam=write_module(temp,"xam.xex","xam_17559",pirs["$flash_xam.xex"]["payload"],a.lzx.resolve(),summary)
        output=subprocess.check_output([str(a.probe.resolve()),*dash,*xam],text=True)
    counts=dict((k,int(v)) for k,v in (token.split("=") for token in output.split()))
    assert counts==dict(slots=2534,xam_ordinals=522,resolved_slots=1043,nonexec_thunks=1,kernel_missing_slots=1490,kernel_ordinals=519,xam_exports=1606,exec_exports=1604,data_exports=2),counts
    print("Verified dashboard/XAM native image mapping and ordinal resolution:",output.strip())

if __name__=="__main__":main()
