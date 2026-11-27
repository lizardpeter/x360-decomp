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

def xma1_format(fmt):
    # XMAWAVEFORMAT, not WAVEFORMATEX. FFmpeg n7.1 wmaprodec.c
    # confirms the stream count and per-stream channel offsets.
    if len(fmt)<12:raise ValueError("truncated XMA1 global format")
    tag,bits,options,largest_skip,streams,loops,version=struct.unpack_from("<HHHHHBB",fmt)
    if tag!=0x165 or not 1<=streams<=64 or len(fmt)!=12+20*streams:
        raise ValueError("invalid XMA1 format extent")
    records=[]
    for i in range(streams):
        avg,rate,begin,end,subframe,channels,mask=struct.unpack_from("<IIIIBBH",fmt,12+20*i)
        if channels not in (1,2) or not 8000<=rate<=192000:
            raise ValueError("invalid XMA1 stream format")
        records.append({"average_bytes_per_second":avg,"sample_rate":rate,
                        "loop_start":begin,"loop_end":end,"loop_subframe_data":subframe,
                        "channels":channels,"channel_mask":f"{mask:04X}"})
    return {"format_tag":"0165","codec":"XMA1","bits_per_sample":bits,
            "encode_options":f"{options:04X}","largest_skip":largest_skip,
            "stream_count":streams,"loop_count":loops,"version":version,
            "channels":sum(r["channels"] for r in records),"streams":records,
            "packet_size":2048}

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
            tag=struct.unpack_from("<H",payload,offset+8)[0]
            if tag==0x165:
                fmt=xma1_format(payload[offset+8:end])
            else:
                tag,ch,rate,avg,align,bits=struct.unpack_from("<HHIIHH",payload,offset+8)
                fmt={"format_tag":f"{tag:04X}","channels":ch,"sample_rate":rate,
                     "average_bytes_per_second":avg,"block_align":align,"bits_per_sample":bits}
        offset=end+(size&1)
    if fmt is None or not any(c["id"]=="data" for c in chunks):
        raise ValueError("missing WAVE format/data")
    result={"container":"RIFF/WAVE","riff_extent":extent,"resource_bytes":len(payload),
            "format":fmt,"chunks":chunks}
    if fmt["format_tag"]=="0165":
        data=next(c for c in chunks if c["id"]=="data")
        if data["size"]%fmt["packet_size"]:raise ValueError("partial XMA1 packet")
        result["packet_count"]=data["size"]//fmt["packet_size"]
        seek=[c for c in chunks if c["id"]=="seek"]
        if seek:
            if len(seek)!=1 or seek[0]["size"]%4:raise ValueError("invalid seek chunk extent")
            result["seek_words"]=seek[0]["size"]//4
    return result

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

def shape(word):
    # Preserve register operands, memory offsets and comparison constants.
    primary=word>>26
    if primary==18:return word&0xfc000003
    if primary==16:return word&0xffff0003
    if primary==15:return word&0xffff0000
    return word

def body_words(image,base,start,size):
    if size%4 or not base<=start<=base+len(image)-size:raise ValueError("function range")
    return [w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]

def matching_functions(source,source_base,source_pe,target,target_base,target_pe,roots):
    """Identify exact normalized homologues and bounded near matches."""
    source_sizes={a:s for a,s,_ in source_pe["functions"]}
    targets=[(a,size,tuple(shape(w) for w in body_words(target,target_base,a,size)))
             for a,size,_ in target_pe["functions"]]
    result=[]
    for root in roots:
        if root not in source_sizes:raise ValueError("source root missing")
        size=source_sizes[root]
        needle=tuple(shape(w) for w in body_words(source,source_base,root,size))
        exact=[];near=[]
        for a,ts,words in targets:
            if ts==size and words==needle:exact.append(hx(a))
            elif abs(ts-size)<=16:
                same=sum(x==y for x,y in zip(needle,words))
                ratio=same/max(len(needle),len(words))
                if ratio>=.6:near.append({"address":hx(a),"size":ts,"aligned_similarity":round(ratio,4)})
        near.sort(key=lambda n:(-n["aligned_similarity"],n["address"]))
        result.append({"source":hx(root),"size":size,"exact":exact,"near":near[:8]})
    return result

def direct_audio_contract(registration,callback,register_pc,callback_pc):
    """Validate the actual descriptor writes and direct context access."""
    regs={int(r["pc"],16):r for r in registration["operands"]}
    ops={int(r["pc"],16):r for r in callback["operands"]}
    def check(table,pc,expected):
        row=table.get(pc,{})
        if any(row.get(k)!=v for k,v in expected.items()):
            raise ValueError("original direct audio operand differs: "+hx(pc))
    # All descriptor fields must originate from the actual caller arguments.
    for delta,expected in (
        (-0x44,{"kind":"register_copy","source":4,"writes":29}),
        (-0x14,{"kind":"memory_load","base":30,"offset":12,"writes":11}),
        (-0x0C,{"kind":"memory_store","base":1,"offset":80,"source":29}),
        (-0x08,{"kind":"register_offset","base":1,"value":80,"writes":3}),
        (-0x04,{"kind":"memory_store","base":1,"offset":84,"source":11}),
        (0,{"kind":"branch","linked":True})):
        check(regs,register_pc+delta,expected)
    if regs[register_pc].get("import",{}).get("name")!="XAudioRegisterRenderDriverClient":
        raise ValueError("original audio import differs")
    for delta,expected in (
        (0x10,{"kind":"register_copy","source":3,"writes":31}),
        (0x30,{"kind":"memory_load","base":31,"offset":304,"writes":10}),
        (0x38,{"kind":"memory_store","base":31,"offset":300,"source":11})):
        check(ops,callback_pc+delta,expected)
    return {"callback":hx(callback_pc),"registration_return":hx(register_pc+4),
            "object_argument":"direct r3","object_read_offset":304,
            "object_write_offset":300,"descriptor_words":2}

def control_flag_references(image,base,pe,addresses):
    # Exact consecutive lis + byte access pairs only; extended window
    # candidates are deliberately not promoted to verified references.
    refs=[]
    for start,size,_ in pe["functions"]:
        words=body_words(image,base,start,size)
        for i in range(1,len(words)):
            w=words[i]
            if w>>26 not in (34,38):continue
            found=variable_reference(words[i-1],w)
            if found and found[0] in addresses:
                refs.append({"owner":hx(start),"site":hx(start+4*i),
                             "address":hx(found[0]),"access":"read" if w>>26==34 else "write"})
    return refs

def lifecycle_report(raw,image,meta,thunks):
    base=meta["image_base"];pe=pe_info(image,base)
    roots=(0x98020E60,0x98020EC8,0x98020ED8,0x98020EF0,
           0x980432B8,0x9800FF08,0x98044400,0x980210F8,0x98020FD0,
           0x9800E910,0x9800F380,0x9800F5A8,0x9800FDB0,0x9800E448,
           0x9800E550,0x98045A60,0x98045A58,0x98045A10,
           0x9800EA10,0x9800FCB0,0x9800FB30,0x980123A0,0x980215E0,0x98021620)
    details=[bounded_entry(image,base,pe,addr,thunks,8192) for addr in roots]
    by_pc={r["pc"]:r for f in details for r in f["operands"]}
    def absolute_slot(lis,access):
        hi=by_pc[hx(lis)];lo=by_pc[hx(access)]
        if hi["kind"]!="immediate" or hi["writes"]!=lo["base"]:
            raise ValueError("boot animation module slot construction")
        return (hi["value"]+lo["offset"])&0xffffffff
    store=by_pc["9800FF20"];load=by_pc["9800E47C"]
    if store.get("kind")!="memory_store" or store.get("source")!=3 or load.get("kind")!="memory_load" or load.get("writes")!=3:
        raise ValueError("boot animation handle flow")
    slot=absolute_slot(0x9800FF14,0x9800FF20)
    if slot!=absolute_slot(0x9800E468,0x9800E47C):raise ValueError("handle slot mismatch")
    masks=[]
    for pc in (0x9800FF18,0x9800FF28):
        op=by_pc[hx(pc)]
        if op["kind"]!="rotate_mask" or op["source"]!=4 or op["mask_start"]!=op["mask_end"]:
            raise ValueError("startup flags shape")
        masks.append(f"{1<<(31-op['mask_start']):08X}")
    flags=[]
    for hi_pc,store_pc in ((0x9800E920,0x9800E924),(0x9800E92C,0x9800E930)):
        row=by_pc[hx(store_pc)]
        if row.get("kind")!="memory_store" or row.get("width")!=1 or row.get("source")!=11:
            raise ValueError("original control flag store")
        flags.append(absolute_slot(hi_pc,store_pc))
    if flags!=[0x98077760,0x98077761]:raise ValueError("original control flag identity")
    references=control_flag_references(image,base,pe,set(flags))
    return {"control_export":{"address":"98020EC8","tail":"9800E910",
            "flag_addresses":[hx(a) for a in flags],"exact_adjacent_references":references,
            "scope":"original control branches; retail caller policy not recovered"},
            "first_export_arguments":{"r3":"module handle (verified resource lookup flow)",
            "r4":"flags word (verified masks, caller policy not recovered)"},
            "module_handle_global":hx(slot),"startup_flag_masks":masks,
            "functions":details}

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
    audio_registration=bounded_entry(image,base,pe,0x98051768,thunks,8192)
    audio_callback=bounded_entry(image,base,pe,0x9804BEA0,thunks,8192)
    direct_context=direct_audio_contract(audio_registration,audio_callback,0x980517C4,0x9804BEA0)
    # Run 46027223390 observed a different registered callback. Recover
    # its exact original body and all relevant voice-driver call sites.
    observed=0x9804F308
    if not executable(pe,base,observed):raise ValueError("observed callback is not executable")
    alternate=bounded_entry(image,base,pe,observed,thunks,8192)
    voice_sites=[{"import":row["name"],"calls":row["direct_calls"]}
                 for row in items if row["name"] in (
                     "XAudioGetVoiceCategoryVolumeChangeMask","XAudioSubmitRenderDriverFrame",
                     "XAudioUnregisterRenderDriverClient")]
    roots={int(c["owner"],16) for row in voice_sites for c in row["calls"]}
    for op in alternate["operands"]:
        if op.get("kind")=="branch" and "target" in op:
            dest=int(op["target"],16)
            if executable(pe,base,dest) and dest not in thunks:roots.add(dest)
    alternate_evidence={"source_run":46027223390,"callback":hx(observed),
                        "body":alternate,"registration":audio_registration,
                        "voice_driver_calls":voice_sites,
                        "related_bodies":[bounded_entry(image,base,pe,a,thunks,8192)
                                          for a in sorted(roots)],
                        "scope":"Observed callback and bounded original operand evidence; no guessed ABI."}

    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "direct_audio_context":direct_context,
            "alternate_audio_context":alternate_evidence,
            "module_flags":hx(int.from_bytes(raw[4:8],"big")),
            "xex_entry":None,"pe_entry":hx(pe["entry_point"]),
            "pe_entry_executable":executable(pe,base,pe["entry_point"]),
            "image_base":hx(base),"image_bytes":len(image),"pdata_functions":len(pe["functions"]),
            "exports":exports,"audio":audio,"imports":items,
            "lifecycle":lifecycle_report(raw,image,meta,thunks),
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
        pe=pe_info(image,m["image_base"])
        callers[label]=loader_references(image,m["image_base"],pe)
        if label=="xam":
            report["audio_library_homologues"]=matching_functions(
                image,m["image_base"],pe,im,meta["image_base"],pe_info(im,meta["image_base"]),
                (0x819AC540,0x819A5878,0x819A50B8,0x819A4F00,0x819AFF80,0x819B6FA0))
    report["caller_references"]=callers
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("boot animation:",len(report["exports"]),"exports",len(report["focused_functions"]),
          "focused functions",len(report["missing_or_stub_imports"]),"missing/stub imports")
    print("audio",report["audio"]["format"],"packets",report["audio"].get("packet_count"))
    print("lifecycle",report["lifecycle"]["module_handle_global"],report["lifecycle"]["startup_flag_masks"])
    print("audio library homologues",report["audio_library_homologues"])
    print("exports",[(r["ordinal"],r["address"],r["kind"]) for r in report["exports"]])
    print("caller references", {k:len(v["code_references"]) for k,v in callers.items()})
if __name__=="__main__":main()
