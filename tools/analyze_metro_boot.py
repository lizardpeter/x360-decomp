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
GUEST_PAD=re.compile(r"METRO_GUEST_PAD context=([0-9a-fA-F]+) user=(\d+) packet=(\d+) buttons=0x([0-9a-fA-F]+)")
HEAP=re.compile(r"METRO_HEAP pc=([0-9A-Fa-f]+) stage=(\w+) r3=([0-9A-Fa-f]+) r4=([0-9A-Fa-f]+) r5=([0-9A-Fa-f]+) r6=([0-9A-Fa-f]+) r7=([0-9A-Fa-f]+) r8=([0-9A-Fa-f]+)")
VM=re.compile(r"METRO_VM (\w+) lr=([0-9a-fA-F]+) region=(\d+) base=([0-9a-fA-F]+) size=([0-9a-fA-F]+) flags=([0-9a-fA-F]+) protect=([0-9a-fA-F]+) status=([0-9a-fA-F]+)")
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
    gates=[];stubs=collections.Counter();sites={};pad=[];guest_pad=[];frames=[];variables=[];errors=[];heap=[];vm=[];failed_paths=collections.Counter()
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
        if m:=GUEST_PAD.search(line):
            guest_pad.append({"context":m[1].upper(),"user":int(m[2]),"packet":int(m[3]),"buttons":int(m[4],16)})
        if m:=HEAP.search(line):
            heap.append({"pc":m[1].upper(),"stage":m[2],
                         **{f"r{i}":m[i].upper() for i in range(3,9)}})
        if m:=VM.search(line):
            vm.append({"name":m[1],"lr":m[2].upper(),"region":int(m[3]),
                       **{key:m[i].upper() for i,key in enumerate(("base","size","flags","protect","status"),4)}})
        if m:=FRAME.fullmatch(line):frames.append(int(m[1]))
        if m:=VAR.search(line):
            variables.append({"module":m[1],"ordinal":m[2].upper(),"state":m[3]})
        if line.startswith("METRO_BOOT "):gates.append(line)
        if m:=re.search(r"no mount covers '([^']+)'",line):
            failed_paths[m[1]]+=1
        if any(x in line for x in ("Assertion failed","exception: SIG","unimplemented:","Unresolved import","invalid or unregistered function")):
            if len(errors)<100:errors.append(line[:512])
    return {"boot_markers":gates,"observed_stub_counts":dict(stubs),"stub_call_sites":list(sites.values()),
            "pad_transitions":pad,"guest_pad_transitions":guest_pad,"frame_counts":frames,"kernel_variables":variables,
            "missing_mount_paths":dict(failed_paths),"errors":errors,
            "heap_probes":heap,"virtual_memory_calls":vm,
            "virtual_memory_failures":[v for v in vm if int(v["status"],16)&0x80000000],
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
          "host pad transitions,",len(result["guest_pad_transitions"]),"guest pad transitions,",len(result["frame_counts"]),"frame reports")
if __name__=="__main__":main()
