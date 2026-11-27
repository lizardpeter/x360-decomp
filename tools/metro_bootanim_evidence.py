#!/usr/bin/env python3
"""Recover native boot-animation lifecycle, graphics/audio contracts and export roots.

Never execute a guessed entry point. The original boot animation has no XEX
entry-point optional header. Only metadata is written, not original bytes.
"""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path

from analyze_decoded import pe_info, imports, ordinal_exports
from decode_image import decode
from metro_import_contracts import sdk_catalog, library, hx, branch, context, variable_reference
from metro_xam_fault_evidence import bounded_entry
from metro_live_slot_and_input_evidence import executable
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from xex import parse as parse_xex

BOOT_SHA="45eb980c0f841b4807d43c07c766fae5e70b8e2fa4d13fb247a491897cfc6de7"
DECODED_SHA="b2bc842157ea7fbc6fde9adede7d55a5b6b9a4bdb88f73fbdb01f03371b1835b"

def riff_metadata(payload):
    if len(payload)<12 or payload[:4]!=b"RIFF" or payload[8:12]!=b"WAVE":
        raise ValueError("expected embedded RIFF/WAVE")
    extent=8+struct.unpack_from("<I",payload,4)[0]
    if extent>len(payload) or extent<12:raise ValueError("invalid RIFF extent")
    chunks=[];fmt=None;offset=12
    while offset+8<=extent:
        key=payload[offset:offset+4].decode("ascii",errors="replace")
        size=struct.unpack_from("<I",payload,offset+4)[0]
        end=offset+8+size
        if end>extent:raise ValueError("RIFF chunk out of range")
        chunks.append({"id":key,"offset":offset+8,"size":size})
        if key=="fmt ":
            if fmt is not None or size<16:raise ValueError("invalid WAVE format")
            tag,ch,rate,avg,align,bits=struct.unpack_from("<HHIIHH",payload,offset+8)
            fmt={"format_tag":f"{tag:04X}","channels":ch,"sample_rate":rate,
                 "average_bytes_per_second":avg,"block_align":align,"bits_per_sample":bits}
        offset=end+(size&1)
    if fmt is None or not any(c["id"]=="data" for c in chunks):
        raise ValueError("missing WAVE format/data")
    return {"container":"RIFF/WAVE","riff_extent":extent,"resource_bytes":len(payload),
            "format":fmt,"chunks":chunks}

def kernel_imports(raw,image,base,pe,catalog,stubs):
    thunks={};items=[]
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        item={"library":lib,"ordinal":row["ordinal"],"name":name,"sdk_kind":kind,
              "explicit_sdk_stub":name in stubs,"kind":"function" if row["thunk_slots"] else "data",
              "thunks":[hx(a) for a in row["thunk_slots"]],
              "value_slots":[hx(a) for a in row["value_slots"]],"direct_calls":[]}
        items.append(item)
        for a in row["thunk_slots"]:thunks[a]=item
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+4*i;dest=branch(pc,w)
            if dest and dest[0] in thunks:
                thunks[dest[0]]["direct_calls"].append({"owner":hx(start),"site":hx(pc),
                    "linked":dest[1],**context(words,i,dest[1])})
    # bounded_entry receives compact descriptors, not recursive call lists.
    compact={a:{k:v for k,v in item.items() if k!="direct_calls"} for a,item in thunks.items()}
    return items,compact

def loader_references(image,base,pe):
    """Literal and direct static pointer evidence, not assumed invocation."""
    literals=set()
    lower=image.lower()
    for s in pe["sections"]:
        if s["flags"]&0x20000000:continue
        lo=s["rva"];hi=lo+s["loaded_bytes"]
        for enc in ("ascii","utf-16-be","utf-16-le"):
            needle="bootanim".encode(enc);p=lo
            while (p:=lower.find(needle,p,hi))!=-1:
                literals.add(base+p);p+=len(needle)
    pointers=set()
    for s in pe["sections"]:
        if s["flags"]&0x20000000:continue
        lo=s["rva"];hi=lo+s["loaded_bytes"]
        for i,(w,) in enumerate(struct.iter_unpack(">I",image[lo:hi-(hi-lo)%4])):
            if w in literals:pointers.add(base+lo+i*4)
    refs=[]
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i in range(1,len(words)):
            found=variable_reference(words[i-1],words[i])
            if found and found[0] in literals|pointers:
                refs.append({"owner":hx(start),"site":hx(start+4*(i-1)),
                    "target":hx(found[0]),"kind":found[1]})
    return {"literal_addresses":[hx(a) for a in sorted(literals)],
            "pointer_addresses":[hx(a) for a in sorted(pointers)],"code_references":refs}

def audit(raw,image,meta,catalog,stubs):
    if sha(raw)!=BOOT_SHA or meta["sha256"]!=DECODED_SHA:
        raise ValueError("boot animation source identity")
    base=meta["image_base"];pe=pe_info(image,base);parsed=parse_xex(raw)
    if base!=0x98000000 or len(image)!=638976 or parsed["entry_point"] is not None:
        raise ValueError("unexpected boot animation layout")
    pin=json.loads((ROOT/"analysis/bootanim_17559/resource_hashes.json").read_text())[0]
    address=int(pin["address"],16);size=pin["bytes"]
    payload=image[address-base:address-base+size]
    if len(payload)!=size or hashlib.sha256(payload).hexdigest()!=pin["sha256"]:
        raise ValueError("original audio resource identity")
    audio=riff_metadata(payload)
    items,thunks=kernel_imports(raw,image,base,pe,catalog,stubs)
    if len(items)!=114 or sum(r["kind"]=="function" for r in items)!=104:
        raise ValueError("boot animation import census")
    exports=[]
    for ordinal,target in ordinal_exports(image,base,raw) or []:
        code=executable(pe,base,target)
        exports.append({"ordinal":ordinal,"address":hx(target),"kind":"function" if code else "data",
                        "body":bounded_entry(image,base,pe,target,thunks,8192) if code else None})
    focus=collections.defaultdict(set)
    for row in items:
        name=row["name"]
        if name.startswith(("Vd","XAudio","XMA","Xex","ExCreateThread","KeWait")) or row["explicit_sdk_stub"]:
            for c in row["direct_calls"]:focus[int(c["owner"],16)].add(name)
    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "module_flags":hx(int.from_bytes(raw[4:8],"big")),
            "xex_entry":None,"pe_entry":hx(pe["entry_point"]),
            "pe_entry_executable":executable(pe,base,pe["entry_point"]),
            "image_base":hx(base),"image_bytes":len(image),"pdata_functions":len(pe["functions"]),
            "exports":exports,"audio":audio,"imports":items,
            "focused_functions":[{"imports":sorted(names),**bounded_entry(image,base,pe,addr,thunks,8192)}
                                 for addr,names in sorted(focus.items())],
            "missing_or_stub_imports":[{k:v for k,v in item.items() if k!="direct_calls"}
                 for item in items if item["explicit_sdk_stub"] or item["sdk_kind"]=="unknown"],
            "scope":"static module and callback evidence, not native animation execution"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    members=parse_pirs(original("pirs"))
    raw=members["$flash_bootanim.xex"]["payload"];im,meta=decode(raw,a.lzx.resolve())
    catalog,stubs=sdk_catalog(a.sdk)
    report=audit(raw,im,meta,catalog,stubs)
    callers={}
    for label,raw in (("dash",original("dash_basic")),("xam",members["$flash_xam.xex"]["payload"])):
        image,m=decode(raw,a.lzx.resolve())
        from metro_import_contracts import DIGESTS
        if m["sha256"]!=DIGESTS[label]:raise ValueError("caller image identity")
        callers[label]=loader_references(image,m["image_base"],pe_info(image,m["image_base"]))
    report["caller_references"]=callers
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("boot animation:",len(report["exports"]),"exports",len(report["focused_functions"]),
          "focused functions",len(report["missing_or_stub_imports"]),"missing/stub imports")
    print("audio",report["audio"]["format"])
    print("exports",[(r["ordinal"],r["address"],r["kind"]) for r in report["exports"]])
    print("caller references", {k:len(v["code_references"]) for k,v in callers.items()})
if __name__=="__main__":main()
