#!/usr/bin/env python3
"""Join live Metro observations to original function metadata."""
import argparse
import bisect
import collections
import json
import re
from pathlib import Path
from prepare_recompilation import ROOT
from stage_metro_xam_aot import rows

STUB=re.compile(r"METRO_STUB name=(\w+) lr=0x([0-9a-fA-F]+) r3=0x([0-9a-fA-F]+) r4=0x([0-9a-fA-F]+) r5=0x([0-9a-fA-F]+) r6=0x([0-9a-fA-F]+)")
PAD=re.compile(r"METRO_PAD user=(\d+) buttons=0x([0-9a-fA-F]+)")
FRAME=re.compile(r"^METRO_BOOT frames (\d+)$")
VAR=re.compile(r"METRO_KERNEL_VAR module=(\w+) ordinal=0x([0-9a-fA-F]+).* state=(\w+)")

def functions(module):
    return [(int(r["address"],16),int(r["size"])) for r in rows(ROOT/"analysis"/module/"functions.tsv")]

def summarize(lines, inventories):
    starts={module:[a for a,_ in funcs] for module,funcs in inventories.items()}
    def locate(lr):
        pc=lr-4
        for module,funcs in inventories.items():
            i=bisect.bisect_right(starts[module],pc)-1
            if i>=0:
                a,size=funcs[i]
                if a<=pc<a+size:return module,f"{a:08X}"
        return "unclassified",None
    gates=[];stubs=collections.Counter();sites={};pad=[];frames=[];variables=[];errors=[];failed_paths=collections.Counter()
    for line in lines:
        if m:=STUB.search(line):
            name=m[1];lr=int(m[2],16);module,caller=locate(lr)
            stubs[name]+=1
            key=(name,lr)
            sites.setdefault(key,{"symbol":name,"lr":f"{lr:08X}","module":module,"pdata_caller":caller,"samples":[]})
            if len(sites[key]["samples"])<4:
                sites[key]["samples"].append([f"{int(x,16):08X}" for x in m.groups()[2:]])
        if m:=PAD.search(line):
            pad.append({"user":int(m[1]),"buttons":int(m[2],16)})
        if m:=FRAME.fullmatch(line):frames.append(int(m[1]))
        if m:=VAR.search(line):
            variables.append({"module":m[1],"ordinal":m[2].upper(),"state":m[3]})
        if line.startswith("METRO_BOOT "):gates.append(line)
        if m:=re.search(r"no mount covers '([^']+)'",line):
            failed_paths[m[1]]+=1
        if any(x in line for x in ("Assertion failed","exception: SIG","unimplemented:","Unresolved import","invalid or unregistered function")):
            if len(errors)<100:errors.append(line[:512])
    return {"boot_markers":gates,"observed_stub_counts":dict(stubs),"stub_call_sites":list(sites.values()),
            "pad_transitions":pad,"frame_counts":frames,"kernel_variables":variables,
            "missing_mount_paths":dict(failed_paths),"errors":errors,
            "menu_visually_verified":False,"navigation_visually_verified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("log",type=Path)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=summarize(a.log.read_text(errors="replace").splitlines(),
                     {m:functions(m) for m in ("dash_17559","xam_17559")})
    a.output.write_text(json.dumps(result,indent=2)+"\n")
    print("Boot evidence:",len(result["stub_call_sites"]),"stub sites,",len(result["pad_transitions"]),
          "pad transitions,",len(result["frame_counts"]),"frame reports")
if __name__=="__main__":main()
