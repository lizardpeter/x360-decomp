#!/usr/bin/env python3
"""Read-only original boot animation phase probes; no guest state writes."""
import argparse
import collections
import json
import re
from pathlib import Path
from instrument_metro_heap import MARKER
from prepare_recompilation import ROOT

# Verified original 17559 update body 9800EA10, evidence run 46058975976.
POINTS={
    0x9800EA30:"update_entry",
    0x9800EAA8:"phase_advance",
    0x9800EAD4:"phase_wrap",
    0x9800EB08:"phase_enable",
    0x9800EB20:"completion_eligible",
    0x9800EB30:"graceful_flag_test",
    0x9800EB3C:"phase_position_test",
    0x9800EB4C:"nested_activity_test",
    0x9800EB60:"phase_elapsed_test",
    0x9800EB68:"original_exit_publication",
    0x9800EB70:"exit_flag_test",
    0x9800EB90:"original_cleanup",
    0x9800EBC4:"nested_update",
}
TAG="// METRO_INTRO_PHASE_INSERTED"
HEADER=r"""
#include <atomic>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <rex/kernel/guest_memory.h>
namespace {
void metro_intro_phase(unsigned pc,const char* label,unsigned object,unsigned n) {
    auto* mem=REX_GUEST_MEMORY();
    if (!mem || !object || object>0xffffffffu-228u) return;
    auto byte=[&](unsigned a)->int {
        auto v=mem->Load<rex::u8>(a);
        return v?int(*v):-1;
    };
    auto fp=[&](unsigned a)->float {
        auto v=mem->Load<rex::be_u32>(a);
        return v?std::bit_cast<float>(static_cast<unsigned>(*v)):
                 std::numeric_limits<float>::quiet_NaN();
    };
    auto nested=mem->Load<rex::be_u32>(object+224);
    unsigned nested_addr=nested?static_cast<unsigned>(*nested):0;
    int nested_active=nested_addr && nested_addr<=0xffffffffu-196u?byte(nested_addr+196):-1;
    std::fprintf(stderr,"METRO_INTRO_PHASE pc=%08X stage=%s n=%u phase12=%.9g phase36=%.9g field26=%d field27=%d field29=%d field31=%d field40=%d field41=%d nested196=%d flag_a=%d flag_b=%d\n",
        pc,label,n,double(fp(object+12)),double(fp(object+36)),byte(object+26),
        byte(object+27),byte(object+29),byte(object+31),byte(object+40),
        byte(object+41),nested_active,byte(0x98077760u),byte(0x98077761u));
}
}
"""
def insert(source):
    if TAG in source:raise ValueError("already instrumented")
    out=[];hits=collections.Counter();owner=False
    for line in source.splitlines(keepends=True):
        out.append(line)
        if line.lstrip().startswith("DEFINE_REX_FUNC("):
            owner=bool(re.match(r"\s*DEFINE_REX_FUNC\(sub_9800EA10\)\s*\{",line,re.I))
            if owner:out.append("    unsigned metro_intro_object=0;\n")
        m=MARKER.fullmatch(line.rstrip("\r\n"))
        if not m:continue
        pc=int(m[2],16)
        if pc not in POINTS:continue
        if not owner:raise ValueError("phase marker outside original owner")
        hits[pc]+=1
        indent=m[1]
        if pc==0x9800EA30:
            out.append(indent+"metro_intro_object=ctx.r3.u32;\n")
        out.append(indent+'if (std::getenv("X360_METRO_INTRO")) {\n')
        out.append(indent+'  static std::atomic<unsigned> samples{0};\n')
        out.append(indent+'  const unsigned n=samples.fetch_add(1,std::memory_order_relaxed)+1;\n')
        out.append(indent+'  if (n<=4 || (n&(n-1))==0)\n')
        out.append(indent+f'    metro_intro_phase(0x{pc:08X}u,"{POINTS[pc]}",metro_intro_object,n);\n')
        out.append(indent+'}\n')
    return (TAG+"\n"+HEADER+"\n"+"".join(out),hits) if hits else (source,hits)
def instrument(directory):
    if directory.name!="generated_bootanim" or not directory.is_dir():
        raise ValueError("expected generated bootanim directory")
    pending={};hits=collections.Counter()
    for p in sorted(directory.rglob("*.cpp")):
        if p.is_symlink():raise ValueError("generated symlink")
        new,h=insert(p.read_text())
        if h:pending[p]=new;hits.update(h)
    if set(hits)!=set(POINTS) or any(n!=1 for n in hits.values()):
        raise ValueError("original phase probe coverage: "+str(hits))
    if len(pending)!=1:raise ValueError("original update body split across translation units")
    for p,s in pending.items():p.write_text(s)
    return {"points":[{"pc":f"{pc:08X}","stage":name,"occurrences":hits[pc]}
                      for pc,name in POINTS.items()],"scope":"read-only original animation phase fields"}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.directory,a.receipt)):
        p.error("build paths only")
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(instrument(a.directory),indent=2)+"\n")
if __name__=="__main__":main()
