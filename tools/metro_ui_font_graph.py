#!/usr/bin/env python3
"""Trace exact original font registration, file streams and input clock callers."""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context
from metro_ui_startup_evidence import ancestors
from metro_xam_fault_evidence import bounded_entry
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from xex import parse as parse_xex

ROOTS={
    "dash":[0x922655D8,0x92202490,0x922020C0,0x922023C8,0x92201FA0,
            0x92218670,0x922188F0,0x92218BE8,0x927AD420],
    "xam":[0x81699810,0x81699190,0x81698C98,0x816EA588,0x81699668],
}
INPUT_ROOT=0x816F28A8
def forward(roots,edges,limit=400,depth=3):
    seen={a:0 for a in roots}
    queue=collections.deque(sorted(roots))
    truncated=False
    while queue:
        start=queue.popleft()
        if seen[start]>=depth:continue
        for dest,pc,linked in sorted(edges[start]):
            if dest not in seen:
                if len(seen)>=limit:truncated=True;continue
                seen[dest]=seen[start]+1
                queue.append(dest)
    return seen,truncated

def audit(label,raw,image,meta,catalog,stubs):
    if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong image")
    base=meta["image_base"];pe=pe_info(image,base);thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);o=int(row["ordinal"],16)
        name,kind=catalog.get((lib,o),("", "unknown"))
        for a in row["thunk_slots"]:
            thunks[a]={"library":lib,"name":name,"ordinal":f"{o:04X}","sdk_stub":name in stubs}
    funcs={a:s for a,s,_ in pe["functions"]};inbound=collections.defaultdict(set);edges=collections.defaultdict(set)
    calls=collections.defaultdict(list)
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+4*i;b=branch(pc,w)
            if not b:continue
            target,linked=b
            if target in thunks:
                calls[start].append({"site":hx(pc),"import":thunks[target],"linked":linked,**context(words,i,linked)})
            elif target in funcs and target!=start:
                edges[start].add((target,pc,linked));inbound[target].add((start,pc,linked))
    roots=set(ROOTS[label])&set(funcs)
    nodes,truncated=forward(roots,edges,limit=400,depth=3)
    report={"font_roots":[hx(a) for a in sorted(roots)],
            "unresolved_roots":[hx(a) for a in sorted(set(ROOTS[label])-roots)],
            "font_nodes":[{"entry":hx(a),"depth":d,"imports":calls[a]} for a,d in sorted(nodes.items())],
            "font_edges":[{"caller":hx(a),"site":hx(pc),"callee":hx(t),"linked":linked}
                for a in sorted(nodes) for t,pc,linked in sorted(edges[a]) if t in nodes],
            "font_truncated":truncated,
            "font_root_bodies":{hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(roots)}}
    if label=="xam":
        graph=ancestors({INPUT_ROOT},inbound,max_depth=4,max_nodes=600)
        input_nodes={int(n["entry"],16) for n in graph["nodes"]}
        report["input_clock_graph"]=graph
        report["input_clock_imports"]={hx(a):calls[a] for a in sorted(input_nodes) if calls[a]}
        focus={a for a in input_nodes if any(any(s in c["import"]["name"].lower() for s in ("time","clock","counter","tick")) for c in calls[a])}
        report["input_clock_bodies"]={hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(focus)}
        print("input clock ancestors",len(input_nodes),"clock-related owners",len(focus))
        for a in sorted(focus):print("clock owner",hx(a),[(c["site"],c["import"]["name"]) for c in calls[a] if any(s in c["import"]["name"].lower() for s in ("time","clock","counter","tick"))])
    print(label,"font roots",len(roots),"descendants",len(nodes),"import calls",sum(len(calls[a]) for a in nodes),
          "stub call names",sorted({c["import"]["name"] for a in nodes for c in calls[a] if c["import"]["sdk_stub"]}))
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    xam=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong source")
    catalog,stubs=sdk_catalog(a.sdk)
    result={"source_run":45977440311,"modules":{}}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,meta=decode(raw,a.lzx.resolve())
        result["modules"][label]=audit(label,raw,image,meta,catalog,stubs)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
