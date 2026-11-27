#!/usr/bin/env python3
"""Recover original UI font and localization call paths, with no asset payload."""
import argparse
import collections
import json
import re
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,signed
from metro_live_slot_and_input_evidence import owner
from metro_ui_startup_evidence import ranges,ancestors
from metro_xam_fault_evidence import bounded_entry
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from xex import parse as parse_xex

TERMS=("XenonJKLatin","XenonCLatin","SegoeXbox-Light",".xtt",".xuis",
       "XuiFont","XuiText","XuiString","FontFace","Glyph","StringTable","GetLocale","GetLanguage")
MASK=0xffffffff
def literals(image,base,pe,intervals):
    # Recover enclosing string starts (not only the matching substring).
    # Report known labels, encoding and lengths, never original text content.
    result=collections.defaultdict(set)
    for lo,hi in ranges(pe,base,False):
        data=image[lo-base:hi-base]
        for encoding,pattern in (
            ("ascii",rb"[\x20-\x7e]{3,240}\x00"),
            ("utf-16-be",rb"(?:\x00[\x20-\x7e]){3,240}\x00\x00"),
            ("utf-16-le",rb"(?:[\x20-\x7e]\x00){3,240}\x00\x00")):
            for m in re.finditer(pattern,data):
                a=lo+m.start()
                if encoding!="ascii" and a%2:continue
                if any(a<end and a+len(m.group())>start for start,end in intervals):continue
                text=m.group()[:-1 if encoding=="ascii" else -2].decode(encoding)
                labels=[t for t in TERMS if t.lower() in text.lower()]
                for label in labels:result[a].add((label,encoding,len(text)))
    return result

def refs(words,start,targets):
    # Conservative within-block constant propagation. Unknown instructions
    # kill all state rather than assuming that they do not write registers.
    reg={}
    for i,w in enumerate(words):
        pc=start+4*i
        op=w>>26;rt=(w>>21)&31;ra=(w>>16)&31;rb=(w>>11)&31
        old=reg.copy();value=None;dest=None
        if op in (14,15):
            dest=rt
            if ra==0 or ra in old:
                value=((0 if ra==0 else old[ra])+ (signed(w&65535,16)<<(16 if op==15 else 0)))&MASK
        elif op in (24,25):
            dest=ra
            if rt in old:value=old[rt] | ((w&65535)<<(16 if op==25 else 0))
        elif op==31 and ((w>>1)&1023)==444 and rt==rb:
            dest=ra;value=old.get(rt)
        elif op in (32,34,40,42,58):
            dest=rt
            if ra in old:
                a=(old[ra]+(signed(w&65535,16)&(~3 if op==58 else -1)))&MASK
                if a in targets:yield (pc,a,"memory_operand")
        elif op in (36,38,44,62) and (op!=62 or (w&3)==0):
            if ra in old:
                a=(old[ra]+(signed(w&65535,16)&(~3 if op==62 else -1)))&MASK
                if a in targets:yield (pc,a,"memory_operand")
            continue
        elif op in (10,11):
            continue
        else:
            reg.clear()
            continue
        if dest is not None:
            reg.pop(dest,None)
            if value is not None:
                reg[dest]=value
                if value in targets:yield (pc,value,"constructed_address")

def audit(label,raw,image,meta,catalog,stubs):
    if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong original image")
    base=meta["image_base"];pe=pe_info(image,base);x=parse_xex(raw)
    intervals=[(int(r["address"],16),int(r["address"],16)+r["bytes"]) for r in x["resources"]]
    lit=literals(image,base,pe,intervals)
    pointers=collections.defaultdict(set)
    for lo,hi in ranges(pe,base,False):
        end=hi-(hi-lo)%4
        for i,(word,) in enumerate(struct.iter_unpack(">I",image[lo-base:end-base])):
            a=lo+i*4
            if word in lit and not any(x<=a<y for x,y in intervals):
                pointers[a].update(lit[word])
    targets=set(lit)|set(pointers)
    thunks={}
    for r in imports(image,base,x):
        lib=library(r["library"]);ordinal=int(r["ordinal"],16)
        name,_=catalog.get((lib,ordinal),("", "unknown"))
        for a in r["thunk_slots"]:thunks[a]={"name":name,"library":lib,"ordinal":f"{ordinal:04X}","sdk_stub":name in stubs}
    funcs={a:s for a,s,_ in pe["functions"]}
    references=[];inbound=collections.defaultdict(set);roots=set()
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for pc,a,kind in refs(words,start,targets):
            references.append({"owner":hx(start),"site":hx(pc),"address":hx(a),"kind":kind,
                               "labels":sorted(t[0] for t in lit.get(a,pointers.get(a,())))})
            roots.add(start)
        for i,w in enumerate(words):
            b=branch(start+i*4,w)
            if b and b[0] in funcs and b[0]!=start:inbound[b[0]].add((start,start+i*4,b[1]))
    # The observed original repeated file-open caller is independent of
    # font references: trace its caller graph even if no font xrefs match.
    if label=="dash":
        roots.add(owner(pe,0x922186D0)[0])
    graph=ancestors(roots,inbound,max_depth=3,max_nodes=3000)
    # Original body operands only for exact root owners, not every ancestor.
    focused={hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(roots)}
    return {"decoded_sha256":meta["sha256"],
            "literal_sites":[{"address":hx(a),"labels":sorted(v)} for a,v in sorted(lit.items())],
            "pointer_sites":[{"address":hx(a),"labels":sorted(v)} for a,v in sorted(pointers.items())],
            "references":references,"focused_functions":focused,"reverse_graph":graph,
            "scope":"Static labels and exact conservative intra-block references; no font renderer execution claim."}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    xam=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong XAM source")
    catalog,stubs=sdk_catalog(a.sdk)
    report={"source_run":45975037949,"modules":{}}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,meta=decode(raw,a.lzx.resolve())
        result=audit(label,raw,image,meta,catalog,stubs)
        report["modules"][label]=result
        print(label,"font/text literals",len(result["literal_sites"]),"pointer slots",len(result["pointer_sites"]),
              "code references",len(result["references"]),"root owners",len(result["focused_functions"]),
              "reverse nodes",len(result["reverse_graph"]["nodes"]))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
