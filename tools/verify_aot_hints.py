#!/usr/bin/env python3
"""Validate proposed dashboard function-start hints against exact retail code."""
import argparse
import bisect
import csv
import struct
from pathlib import Path
from collections import defaultdict
from prepare_recompilation import original, ROOT
from decode_image import decode
from analyze_decoded import pe_info

def tail_target(pc, word):
    if word >> 26 != 18 or word & 1:
        return None
    displacement = word & 0x03fffffc
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return (displacement if word & 2 else pc + displacement) & 0xffffffff

def verify(image,base,pe,candidates):
    funcs=pe["functions"]
    starts=[a for a,_,_ in funcs]
    sections=[(base+s["rva"],base+s["rva"]+s["loaded_bytes"]) for s in pe["sections"] if s["flags"]&0x20000000]
    def executable(a):
        return a%4==0 and any(lo<=a and a+4<=hi for lo,hi in sections)
    for a in candidates:
        if not executable(a):
            raise ValueError(f"non-executable candidate {a:08X}")
        i=bisect.bisect_right(starts,a)-1
        if i>=0 and a<funcs[i][0]+funcs[i][1]:
            raise ValueError(f"candidate inside pdata function {a:08X}")
        if not candidates[a]:
            raise ValueError(f"no observed tail branches {a:08X}")
    found=defaultdict(list)
    for lo,hi in sections:
        for off,(word,) in enumerate(struct.iter_unpack(">I",image[lo-base:hi-base])):
            pc=lo+off*4
            dest=tail_target(pc,word)
            if dest in candidates:
                found[dest].append(pc)
    for a,expected in candidates.items():
        if found[a]!=expected:
            raise ValueError(f"branch evidence differs at {a:08X}")
    return sum(map(len,found.values()))

def verified_manifest():
    image,info=decode(original("dash_basic"))
    if info["sha256"]!="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9":
        raise ValueError("dashboard image identity mismatch")
    with (ROOT/"analysis/aot/dashboard-tail-entries.tsv").open() as f:
        rows=list(csv.DictReader(f,delimiter="\t"))
    candidates={int(r["address"],16):[int(x,16) for x in r["tail_branch_sites"].split(",")] for r in rows}
    if len(candidates)!=len(rows) or len(candidates)!=30:
        raise ValueError("candidate inventory mismatch")
    branches=verify(image,info["image_base"],pe_info(image,info["image_base"]),candidates)
    # Only entry locations, not guessed sizes or replacement instructions.
    text="# Verified tail-branch targets outside original pdata ranges.\n[functions]\n"
    text+="".join(f"0x{a:08X} = {{}}\n" for a in sorted(candidates))
    return text, len(candidates), branches

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    output=a.output.resolve()
    if not output.is_relative_to((ROOT/"build").resolve()):p.error("hints output must stay under build/")
    text,count,branches=verified_manifest()
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(text)
    print(f"Verified {count} candidate starts and {branches} direct tail-branch references")
if __name__=="__main__":
    main()
