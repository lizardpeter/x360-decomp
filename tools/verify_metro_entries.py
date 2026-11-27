#!/usr/bin/env python3
"""Verify pointer candidates and missing XAM export entries against original images."""
import argparse
import bisect
import collections
import hashlib
import json
import re
import struct
import tomllib
from pathlib import Path
from analyze_decoded import pe_info, ordinal_exports
from decode_image import decode
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from patch_metro_retail_routing import original_inventory
from stage_metro_xam_aot import manifest
from verify_aot_hints import verified_manifest

DASH_JUMPS={"setjmp_address":0x9291C760,"longjmp_address":0x9291C330}
JUMP_CALLS={0x9291C760:0x928E4028,0x9291C330:0x928E4A00}

def branch(pc,word):
    if word>>26!=18:return None
    d=word&0x03fffffc
    if d&0x02000000:d-=0x04000000
    return (d if word&2 else pc+d)&0xffffffff

def terminal(word):
    return word in (0x4e800020,0x4e800420) or (word>>26==18 and not word&1)

def sections(pe,base,executable):
    return [(base+s["rva"],base+s["rva"]+s["loaded_bytes"])
            for s in pe["sections"] if bool(s["flags"]&0x20000000)==executable and
            s["loaded_bytes"]>=4 and (executable or s["name"] in (".rdata",".data"))]

def inside(a,ranges):
    return any(lo<=a and a+4<=hi for lo,hi in ranges)

def in_function(a,funcs,starts):
    i=bisect.bisect_right(starts,a)-1
    return i>=0 and a<funcs[i][0]+funcs[i][1]

def word(image,base,a):
    if a<base or a+4>base+len(image) or a&3:
        raise ValueError("invalid image word")
    return struct.unpack_from(">I",image,a-base)[0]

def pointer_sites(image,base,pe,candidates):
    out=collections.defaultdict(list)
    for lo,hi in sections(pe,base,False):
        for i,(v,) in enumerate(struct.iter_unpack(">I",image[lo-base:hi-base-(hi-lo)%4])):
            if v in candidates:out[v].append(lo+4*i)
    # Independent adjacent lis rN,hi; addi/ori rN,rN,lo evidence.
    # Nonadjacent construction is deliberately not assumed.
    for lo,hi in sections(pe,base,True):
        prev=None
        for i,(v,) in enumerate(struct.iter_unpack(">I",image[lo-base:hi-base-(hi-lo)%4])):
            if prev is not None and prev>>26==15 and (prev>>16)&31==0:
                reg=(prev>>21)&31
                op=v>>26;rt=(v>>21)&31;ra=(v>>16)&31
                if rt==ra==reg and op in (14,24):
                    low=v&65535
                    if op==14 and low&32768:low-=65536
                    target=(((prev&65535)<<16)+low)&0xffffffff
                    if target in candidates:out[target].append(lo+4*(i-1))
            prev=v
    return out

def verify_candidates(image,base,pe,candidates):
    code=sections(pe,base,True)
    funcs=pe["functions"];starts=[a for a,_,_ in funcs]
    sites=pointer_sites(image,base,pe,candidates)
    accepted=[];rejected=[]
    for a in sorted(candidates):
        why=None
        if not inside(a,code) or a&3:why="outside_code"
        elif in_function(a,funcs,starts):why="pdata_covered"
        elif not sites[a]:why="no_independent_pointer"
        elif not inside(a-4,code) or (word(image,base,a-4)!=0 and not terminal(word(image,base,a-4))):
            why="previous_word_not_boundary"
        else:
            boundary=bisect.bisect_right(starts,a)
            next_start=starts[boundary] if boundary<len(starts) else base+len(image)
            end=None
            for pc in range(a,min(a+64*4,next_start),4):
                if not inside(pc,code):break
                v=word(image,base,pc)
                if not v:break
                if terminal(v):
                    end=pc+4;break
            if end is None:why="no_bounded_terminal"
        if why:rejected.append({"address":f"{a:08X}","reason":why})
        else:accepted.append({"address":f"{a:08X}","sites":[f"{v:08X}" for v in sites[a]]})
    return accepted,rejected

def verify_jumps(image,base,pe):
    code=sections(pe,base,True)
    funcs=pe["functions"];starts=[a for a,_,_ in funcs]
    result={}
    for name,target in DASH_JUMPS.items():
        caller=JUMP_CALLS[target]
        if not inside(target,code):raise ValueError("nonexecutable CRT address")
        i=bisect.bisect_right(starts,caller)-1
        lo,hi=caller,caller+0x100
        if i>=0 and in_function(caller,funcs,starts):
            lo=funcs[i][0];hi=lo+funcs[i][1]
        matches=[]
        for pc in range(lo,hi,4):
            if inside(pc,code) and word(image,base,pc)&1 and branch(pc,word(image,base,pc))==target:
                matches.append(pc)
        if not matches:raise ValueError("unverified CRT direct call "+name)
        result[name]={"target":f"{target:08X}","calls":[f"{x:08X}" for x in matches]}
    return result

def xam_hints(image,base,pe,raw):
    exports=dict(ordinal_exports(image,base,raw))
    code=sections(pe,base,True)
    funcs=pe["functions"];starts=[a for a,_,_ in funcs];known=set(starts)
    result=[];interior=[];seen=set()
    for b in original_inventory():
        if b["data"]:continue
        a=b["target"]
        if exports.get(b["ordinal"])!=a or a&3 or not inside(a,code):
            raise ValueError("retail export proof failed")
        if a in seen:continue
        seen.add(a)
        if a in known:continue
        if in_function(a,funcs,starts):
            interior.append(f"{a:08X}");continue
        result.append(f"{a:08X}")
    return sorted(result),sorted(interior)

CUSTOM_OBJECT_DESCRIPTORS = {
    0x81A821E0: (0x81A72B54,0x81A72734,0,0x816A7EE0,0,0xC,0x66746F4E),
    0x81A82574: (0x816E6CE0,0x816E6B10,0,0x816BB030,0,0x81A85484,7),
    0x81A85494: (0x816E6CE0,0x816E6B10,0x816F1200,0,0,0x81A85484,6),
    0x81A93738: (0x81897C50,0x8188B380,0x8188B388,0,0,0x81A85484,0x5370744D),
}
CUSTOM_OBJECT_IMPORT_CALLBACKS = {0x81A72B54:0x000B,0x81A72734:0x000F}

def custom_callback_hints(image,base,pe,descriptors=CUSTOM_OBJECT_DESCRIPTORS,
                          imports=CUSTOM_OBJECT_IMPORT_CALLBACKS):
    code=sections(pe,base,True)
    data=sections(pe,base,False)
    funcs=pe["functions"]; starts=[a for a,_,_ in funcs]
    report={}
    for address,expected in descriptors.items():
        if not all(inside(address+i*4,data) for i in range(7)):
            raise ValueError("custom descriptor outside original data")
        words=tuple(word(image,base,address+i*4) for i in range(7))
        if words!=expected:raise ValueError("original custom descriptor mismatch")
        for i,target in enumerate(words[:5]):
            if not target:continue
            if not inside(target,code) or not word(image,base,target):
                raise ValueError("custom callback not executable")
            if target in imports:
                kind="kernel_import"
            elif target in starts:
                kind="pdata_entry"
            else:
                if in_function(target,funcs,starts):
                    raise ValueError("interior custom callback")
                # A direct descriptor pointer is stronger evidence than a
                # generic data scan. Still require a nonzero bounded leaf
                # ending in an unconditional branch/return/CTR tail call.
                stop=bisect.bisect_right(starts,target)
                bound=starts[stop] if stop<len(starts) else base+len(image)
                for pc in range(target,min(target+64*4,bound),4):
                    if not inside(pc,code) or not word(image,base,pc):
                        raise ValueError("custom callback without bounded terminal")
                    if terminal(word(image,base,pc)):
                        break
                else:raise ValueError("custom callback without bounded terminal")
                kind="descriptor_entry"
            record=report.setdefault(target,{"address":f"{target:08X}","kind":kind,"slots":[]})
            record["slots"].append(f"{address+i*4:08X}")
    return sorted((v for v in report.values()),key=lambda r:r["address"])

def resource_integrity_header(modules):
    """Digest each pinned original resource independently before native loading."""
    out=["#pragma once", "#include <cstdint>",
         "struct MetroResourceProof { const char* name; std::uint32_t address, size; std::uint64_t digest; };"]
    for label,raw,image,meta in modules:
        pin=json.loads((ROOT/"analysis"/f"{label.lower()}_17559"/"resource_hashes.json").read_text())
        if len(pin)!=len({r["id"] for r in pin}):raise ValueError("duplicate resource")
        out.append(f"inline constexpr MetroResourceProof k{label}Resources[] = {{")
        base=meta["image_base"]
        for r in pin:
            name=r["id"];addr=int(r["address"],16);size=r["bytes"]
            if not re.fullmatch(r"[A-Za-z0-9_]{1,8}",name) or not base<=addr<=base+len(image)-size or not size:
                raise ValueError("invalid original resource record")
            payload=image[addr-base:addr-base+size]
            if hashlib.sha256(payload).hexdigest()!=r["sha256"]:
                raise ValueError("original resource digest mismatch "+name)
            # FNV-1a is a fast memory-corruption check, not a security hash.
            # SHA-256 above authenticates the source against the pinned census.
            digest=0xcbf29ce484222325
            for byte in payload:digest=((digest^byte)*0x100000001b3)&0xffffffffffffffff
            out.append(f'    {{"{name}",0x{addr:08X}u,{size}u,0x{digest:016X}ull}},')
        out.append("};")
    return "\n".join(out)+"\n"

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--reference",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    for path in (a.folder,a.receipt):
        if not path.resolve().is_relative_to((ROOT/"build").resolve()):
            p.error("generated hints and receipt must remain under build/")
    image,info=decode(original("dash_basic"))
    base=info["image_base"]
    if info["sha256"]!="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9":
        raise ValueError("dashboard decoded identity differs")
    pe=pe_info(image,base)
    ref=a.reference.read_text()
    candidates={int(x,16) for x in re.findall(r"(?m)^\s*(0x[0-9A-Fa-f]+)\s*=\s*\{\}",ref)}
    if len(candidates)!=515:raise ValueError("unexpected pinned candidate census")
    accepted,rejected=verify_candidates(image,base,pe,candidates)
    if "92394200" not in {x["address"] for x in accepted}:
        raise ValueError("previously demonstrated indirect entry not independently verified")
    jumps=verify_jumps(image,base,pe)
    base_hints,_,_=verified_manifest()
    prior=tomllib.loads(base_hints)["functions"]
    additions={int(x["address"],16) for x in accepted}-{int(x,16) for x in prior}
    dash_text="".join(f"{name} = 0x{addr:08X}\n" for name,addr in DASH_JUMPS.items())
    dash_text+=base_hints+"".join(f"0x{x:08X} = {{}}\n" for x in sorted(additions))
    xam_raw=parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam_raw)!=EXPECTED["xam_17559"]:raise ValueError("XAM source identity differs")
    xi,xm=decode(xam_raw,a.lzx.resolve())
    if xm["sha256"]!="f9e44cd6f4b04875ddc5a3b8fd519785ba2b0488b1c4622f818b740ba4064313":
        raise ValueError("XAM decoded identity differs")
    xpe=pe_info(xi,xm["image_base"])
    exports,interior=xam_hints(xi,xm["image_base"],xpe,xam_raw)
    # 17559 explicitly constructs the callback passed to DrvSetUserBindingCallback.
    # Verify both instructions and its exact import call; do not scan arbitrary pointers.
    xb=xm["image_base"]
    callback=0x816D9060
    hi=word(xi,xb,0x8169690C);lo=word(xi,xb,0x81696910)
    if hi>>26!=15 or (hi>>21)&31!=11 or (hi>>16)&31!=0 or lo>>26!=14 or (lo>>21)&31!=3 or (lo>>16)&31!=11:
        raise ValueError("unexpected binding callback construction")
    low=lo&65535
    if low&0x8000:low-=65536
    if (((hi&65535)<<16)+low)&0xffffffff!=callback or branch(0x81696914,word(xi,xb,0x81696914))!=0x81A72984:
        raise ValueError("original binding callback mismatch")
    if not inside(callback,sections(xpe,xb,True)):
        raise ValueError("callback not executable")
    starts=[a for a,_,_ in xpe["functions"]]
    if in_function(callback,xpe["functions"],starts) and callback not in starts:
        raise ValueError("callback is an interior PDATA address")
    custom_callbacks=custom_callback_hints(xi,xb,xpe)
    # Independently verify both callback import thunk ordinals against the
    # committed original import census, rather than forcing them into codegen.
    from stage_metro_xam_aot import rows
    xam_imports=rows(ROOT/"analysis/xam_17559/imports.tsv")
    for addr,ordinal in CUSTOM_OBJECT_IMPORT_CALLBACKS.items():
        if not any(r["library"]=="xboxkrnl.exe" and int(r["ordinal"],16)==ordinal and
                   f"{addr:08X}" in r["thunk_slots"].split(",") for r in xam_imports):
            raise ValueError("custom allocator/release import proof failed")
    exports=sorted(set(exports)|{f"{callback:08X}"}|
                   {r["address"] for r in custom_callbacks if r["kind"]=="descriptor_entry"})
    hud_raw=parse_pirs(original("pirs"))["$flash_hud.xex"]["payload"]
    from stage_metro_xam_aot import HUD_SHA
    if sha(hud_raw)!=HUD_SHA:raise ValueError("HUD source identity")
    hi,hm=decode(hud_raw,a.lzx.resolve())
    proofs=resource_integrity_header([("Dash",original("dash_basic"),image,info),
                                     ("Xam",xam_raw,xi,xm),("Hud",hud_raw,hi,hm)])
    (a.folder/"src/metro_resource_proofs.hpp").write_text(proofs)
    target=a.folder/"dash_17559_manifest.toml"
    if target.read_text()!=manifest():raise ValueError("unexpected paired manifest")
    updated=target.read_text().replace('out_directory_path = "generated_xam"','out_directory_path = "generated_xam"\nincludes = ["verified-xam-export-entries.toml"]')
    (a.folder/"verified-entries.toml").write_text(dash_text)
    (a.folder/"verified-xam-export-entries.toml").write_text("[functions]\n"+"".join(f"0x{x} = {{}}\n" for x in exports))
    target.write_text(updated)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps({"reference_sha256":hashlib.sha256(ref.encode()).hexdigest(),
        "dashboard_candidates":len(candidates),"accepted":accepted,"rejected":rejected,
        "new_dashboard_entries":len(additions),"crt_calls":jumps,
        "xam_non_pdata_export_entries":exports,"xam_interior_exports_unresolved":interior,
        "custom_object_callbacks":custom_callbacks},indent=2)+"\n")
    print("Verified entries:",len(additions),"dashboard pointer starts,",len(exports),"XAM export starts;",
          len(rejected),"reference candidates rejected,",len(interior),"interior XAM targets")

if __name__=="__main__":main()
