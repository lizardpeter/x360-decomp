#!/usr/bin/env python3
"""Trace original text-object and glyph paths after confirmed registration.

Only original addresses, normalized operand metadata and import names are
exported. No font data, localized strings, shaders or original code bytes.
"""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context
from metro_font_evidence import refs
from metro_ui_font_graph import forward
from metro_ui_startup_evidence import ancestors
from metro_xam_fault_evidence import bounded_entry,operand
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from xex import parse as parse_xex
from instrument_metro_ui import TEXT_CALLS,TEXT_ENTRIES

# Independently recovered XuiText/Glyph/StringTable literal xrefs from
# 45978542649. Names describe the evidence, not an invented function ABI.
ROOTS={
    "dash":{0x921D8188:"text_reference_1",0x921D8798:"text_reference_2",
            0x921D9480:"text_reference_3",0x92286980:"text_reference_4",
            0x92287A60:"text_reference_5",0x92287B78:"text_reference_6",
            0x927AD420:"glyph_reference",0x92911340:"text_reference_7",
            0x929115D0:"string_table_reference_1",0x92911670:"string_table_reference_2",
            0x92911870:"string_table_reference_3"},
    "xam":{0x81693880:"text_reference_1",0x816AA280:"text_reference_2",
           0x817B8D30:"text_reference_3",0x817B9340:"text_reference_4",
           0x817B9EB8:"text_reference_5",0x817F0418:"text_reference_6",
           0x817F0480:"text_reference_7"},
}
MAGIC={0x78747466,0x66747478}
def virtual_calls(body):
    ops=body["operands"]
    result=[]
    for i,o in enumerate(ops):
        if o.get("kind")=="indirect_branch" and o.get("linked"):
            # Candidate call setup only; a load near mtctr is not proof of
            # the dynamic callee. Preserve all recognized operands.
            result.append({"site":o["pc"],"window":ops[max(0,i-10):i+1]})
    return result

def verify_trace_plan(label,image,base,funcs):
    module={"dash":"generated","xam":"generated_xam"}[label]
    entries=TEXT_ENTRIES[module]
    if not set(entries)<=funcs.keys():raise ValueError("text entry outside original function inventory")
    calls=[]
    for pc,(name,target,kind) in sorted(TEXT_CALLS[module].items()):
        owners=[a for a,size in funcs.items() if a<=pc and pc+4<a+size]
        if len(owners)!=1 or branch(pc,struct.unpack_from(">I",image,pc-base)[0])!=(target,True):
            raise ValueError(f"original text trace call differs {pc:08X}")
        calls.append({"site":hx(pc),"return":hx(pc+4),"target":hx(target),"owner":hx(owners[0]),"label":name,"kind":kind})
    return {"entries":{hx(a):n for a,n in sorted(entries.items())},"calls":calls}

def audit(label,raw,image,meta,catalog,stubs):
    if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong original identity")
    base=meta["image_base"];pe=pe_info(image,base)
    thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for a in row["thunk_slots"]:
            thunks[a]={"name":name,"library":lib,"ordinal":f"{ordinal:04X}","sdk_stub":name in stubs}
    funcs={a:s for a,s,_ in pe["functions"]}
    outgoing=collections.defaultdict(set);incoming=collections.defaultdict(set)
    calls=collections.defaultdict(list);magic=[]
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for pc,value,kind in refs(words,start,MAGIC):
            if kind=="constructed_address":
                i=(pc-start)//4
                magic.append({"owner":hx(start),"pc":hx(pc),"value":hx(value),
                    "window":[{"pc":hx(start+j*4),**operand(start+j*4,words[j])}
                              for j in range(max(0,i-6),min(len(words),i+12))]})
        for i,w in enumerate(words):
            pc=start+i*4;b=branch(pc,w)
            if not b:continue
            target,linked=b
            if target in thunks:
                calls[start].append({"site":hx(pc),"import":thunks[target],"linked":linked,
                                     **context(words,i,linked)})
            elif target in funcs and target!=start:
                outgoing[start].add((target,pc,linked));incoming[target].add((start,pc,linked))
    roots=set(ROOTS[label])&set(funcs)
    roots.update(int(m["owner"],16) for m in magic)
    nodes,truncated=forward(roots,outgoing,limit=800,depth=3)
    graph=ancestors(roots,incoming,max_depth=3,max_nodes=1500)
    # Keep exact root operands and a bounded set of descendants carrying
    # direct imports. Dynamic call sites within those bodies get windows.
    focus=roots|{a for a,d in nodes.items() if d<=2 and calls[a]}
    bodies={hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(focus)}
    result={"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "verified_live_trace_plan":verify_trace_plan(label,image,base,funcs),
            "literal_reference_roots":{hx(a):ROOTS[label][a] for a in sorted(roots&ROOTS[label].keys())},
            "magic_candidates":magic,"forward_truncated":truncated,
            "forward_nodes":[{"entry":hx(a),"depth":d,"imports":calls[a]} for a,d in sorted(nodes.items())],
            "forward_edges":[{"caller":hx(a),"callee":hx(t),"site":hx(pc),"linked":linked}
                for a in sorted(nodes) for t,pc,linked in sorted(outgoing[a]) if t in nodes],
            "reverse_graph":graph,"bodies":bodies,
            "virtual_call_candidates":{a:v for a,b in bodies.items() if (v:=virtual_calls(b))}}
    print(label,"literal roots",len(roots),"XTTF immediate candidates",len(magic),
          "descendants",len(nodes),"bounded bodies",len(bodies),
          "dynamic call windows",sum(map(len,result["virtual_call_candidates"].values())),
          "SDK stub imports",sorted({c["import"]["name"] for a in nodes for c in calls[a] if c["import"]["sdk_stub"]}))
    return result

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
    report={"source_run":45981038927,"modules":{}}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,meta=decode(raw,a.lzx.resolve())
        report["modules"][label]=audit(label,raw,image,meta,catalog,stubs)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
