#!/usr/bin/env python3
"""Recover exact original non-security console preference and text-idle ABI callers.

Trace only category 3/7 user-facing selectors, and input-idle queries.
Do not inspect secured settings or publish original resource payloads.
"""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context,setup
from metro_xam_fault_evidence import bounded_entry,operand
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from xex import parse as parse_xex

FOCUS={(3,0x22),(7,0x0b)}
def candidate(words,i):
    # Only claim local immediate evidence if the nearest recognized write is
    # a literal, not a copy/load, and there is no intervening control transfer.
    seen={}
    for j in range(i-1,max(-1,i-21),-1):
        w=words[j]
        if w>>26 in (16,17,18,19):break
        s=setup(w)
        if s and s[0] in (3,4,5,6,7) and s[0] not in seen:
            seen[s[0]]=s[1]
    if any(seen.get(r,{}).get("kind")!="immediate" for r in (3,4)):
        return None
    key=(seen[3]["value"],seen[4]["value"])
    if key not in FOCUS:return None
    return {"category":key[0],"selector":key[1],"argument_evidence":seen,
            "confidence":"nearby immediate observations, not complete register dataflow"}

def audit(label,raw,image,meta,catalog):
    if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong decoded image")
    base=meta["image_base"];pe=pe_info(image,base)
    thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for a in row["thunk_slots"]:
            thunks[a]={"library":lib,"name":name,"ordinal":f"{ordinal:04X}"}
    sites=[];roots=set()
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+i*4;dest=branch(pc,w)
            if not dest or not dest[1] or dest[0] not in thunks:continue
            imp=thunks[dest[0]]
            if imp["name"]=="ExGetXConfigSetting":
                selection=candidate(words,i)
                if not selection:continue
            elif imp["name"]=="XInputdGetLastTextInputTime":
                selection={"kind":"text_idle_query"}
            else:continue
            sites.append({"owner":hx(start),"site":hx(pc),"import":imp,**selection,
                          **context(words,i,True),
                          "window":[{"pc":hx(start+j*4),**operand(start+j*4,words[j])}
                                    for j in range(max(0,i-12),min(len(words),i+25))]})
            roots.add(start)
    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "sites":sites,"owners":{hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(roots)}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    xam=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong XAM source")
    catalog,_=sdk_catalog(a.sdk)
    report={"source_run":45975037949,"modules":{}}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,meta=decode(raw,a.lzx.resolve())
        result=audit(label,raw,image,meta,catalog)
        report["modules"][label]=result
        print(label,"non-security preference and text-idle sites",len(result["sites"]))
        for s in result["sites"]:
            print(s["site"],s["import"]["name"],s.get("category"),s.get("selector"),s.get("argument_evidence"))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
