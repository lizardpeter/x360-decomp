#!/usr/bin/env python3
"""Require real generated mappings for all original profile modules and XAM targets."""
import argparse
import json
from pathlib import Path
from prepare_recompilation import ROOT
from stage_metro_profile_modules import inventory,mapping_coverage
from filter_zero_aot_mappings import filter_text,process

def verify(folder):
    report=inventory()
    xam=folder/"generated_xam/metro_xam_init.cpp"
    coverage=mapping_coverage(xam.read_text(),report)
    result={"retail_xam":coverage,"modules":{}}
    for name,m in report["modules"].items():
        directory=folder/("generated_"+name)
        path=directory/("metro_"+name+"_init.cpp")
        required=(m["entry"],*(b["thunk"] for b in m["xam_bindings"]))
        try:
            record=process(path,required)
            if record["removed_zero_address_mappings"]:
                raise ValueError("unexpected zero-address mappings")
            result["modules"][name]=record|{"valid":True}
        except (OSError,ValueError) as exc:
            result["modules"][name]={"valid":False,"error":str(exc)}
    result["passed"]=all(x["valid"] for x in result["modules"].values()) and all(
        not x["missing"] for x in coverage.values())
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.receipt)):
        p.error("outputs must remain in build/")
    report=verify(a.folder)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))
    if not report["passed"]:raise SystemExit(1)
if __name__=="__main__":main()
