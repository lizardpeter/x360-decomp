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
    exports=sorted(set(exports)|{f"{callback:08X}"})
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
        "xam_non_pdata_export_entries":exports,"xam_interior_exports_unresolved":interior},indent=2)+"\n")
    print("Verified entries:",len(additions),"dashboard pointer starts,",len(exports),"XAM export starts;",
          len(rejected),"reference candidates rejected,",len(interior),"interior XAM targets")

if __name__=="__main__":main()
