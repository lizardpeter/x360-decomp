#!/usr/bin/env python3
"""Trace the original XAM audio null pointer back through its actual ABI.

The probes read only mapped guest memory and original ABI registers. They
never replace a guest operation, skip a callback, or repair a null field.
"""
import argparse
import collections
import json
from pathlib import Path
from instrument_metro_heap import MARKER

# Original operand evidence: run 45958145203. At the indirect call, r5 is
# the selected buffer value, not the address of its stack slot.
POINTS={
    0x819AC59C:("register_import",1),
    0x819AC5A0:("register_result",0),
    0x819A5878:("render_callback",2),
    0x819A593C:("render_update",2),
    0x819A50B8:("update_entry",2),
    0x819A516C:("voice_queue_call",2),
    0x819A4F00:("voice_queue_entry",2),
    0x819A5040:("voice_virtual_call",0),
    0x819AF968:("voice_render_entry",0),
    0x819AF9F4:("voice_render_virtual",0),
    0x819A7918:("voice_route_entry",0),
    0x819A7978:("buffer_select_call",3),
    0x819AFF80:("buffer_select_entry",3),
    0x819B0088:("selected_buffer_virtual_call",0),
    0x819B6FA0:("selected_buffer_consumer",0),
    0x819B701C:("selected_buffer_header_call",0),
    0x819A4158:("faulting_header_read",0),
}
REQUIRED={0x819AC59C,0x819A5878,0x819AFF80,0x819B0088,0x819B6FA0,0x819A4158}
TAG="// METRO_AUDIO_PROBES_INSERTED"
HEADER=r'''
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
#include <rex/kernel/object/kernel_thread.h>
namespace {
void metro_original_audio_probe(const char* label,unsigned pc,const PPCContext& ctx,unsigned kind,unsigned sample) {
    auto* mem=REX_GUEST_MEMORY();
    if (!mem)return;
    const auto address=[](unsigned a,unsigned offset)->unsigned{
        return a && a<=0xffffffffu-offset?a+offset:0u;
    };
    // Read exactly the mapped fields. An unreadable word prints a separate
    // validity bit; no fabricated zero is conflated with a real zero.
    auto word=[&](const char* name,unsigned a) {
        auto value=a?mem->Load<rex::be_u32>(a):decltype(mem->Load<rex::be_u32>(a)){std::unexpected(rex::Error(rex::ErrorCategory::kRuntime,"null"))};
        if (value)std::fprintf(stderr," %s=%08X",name,static_cast<unsigned>(*value));
        else std::fprintf(stderr," %s=unmapped",name);
    };
    auto byte=[&](const char* name,unsigned a) {
        if (a) {
            auto value=mem->Load<rex::u8>(a);
            if(value){std::fprintf(stderr," %s=%02X",name,static_cast<unsigned>(*value));return;}
        }
        std::fprintf(stderr," %s=unmapped",name);
    };
    auto* thread=rex::kernel::KernelThread::GetCallingThread();
    const auto cpu=thread?static_cast<unsigned>(thread->GetActiveCPU()):0xffu;
    std::fprintf(stderr,"METRO_AUDIO_FLOW pc=%08X stage=%s n=%u cpu=%u r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X r13=%08X lr=%08X",
        pc,label,sample,cpu,ctx.r3.u32,ctx.r4.u32,ctx.r5.u32,ctx.r6.u32,ctx.r7.u32,ctx.r8.u32,
        ctx.r13.u32,static_cast<unsigned>(ctx.lr));
    byte("pcr_cpu",address(ctx.r13.u32,268));
    if (kind==1) {
        word("descriptor_callback",ctx.r3.u32);
        word("descriptor_context",address(ctx.r3.u32,4));
        word("driver_before",ctx.r4.u32);
    }
    if (kind==2) {
        word("object64",address(ctx.r3.u32,64));
        word("object300",address(ctx.r3.u32,300));
        word("object304",address(ctx.r3.u32,304));
    }
    if (kind==3) {
        byte("route5",address(ctx.r4.u32,5));
        byte("route6",address(ctx.r4.u32,6));
        word("incoming_buffer",ctx.r5.u32);
        word("route_object",ctx.r4.u32);
    }
    // Original 819AFF80 selects two pointers at global_object+12+8*CPU
    // and +16+8*CPU. Record actual values, not guessed defaults.
    auto global=mem->Load<rex::be_u32>(0x81B5B5E4u);
    if (global) {
        const unsigned object=*global;
        std::fprintf(stderr," global_object=%08X",object);
        if(cpu<6) {
            word("cpu_buffer_a",address(object,12+8*cpu));
            word("cpu_buffer_b",address(object,16+8*cpu));
        }
    } else std::fprintf(stderr," global_object=unmapped");
    std::fprintf(stderr,"\n");
    std::fflush(stderr);
}
}
'''
# Avoid constructing an artificial error for the null case: the header
# only uses the actual GuestMemory result when the address is nonzero.
HEADER=HEADER.replace('        auto value=a?mem->Load<rex::be_u32>(a):decltype(mem->Load<rex::be_u32>(a)){std::unexpected(rex::Error(rex::ErrorCategory::kRuntime,"null"))};\n        if (value)std::fprintf(stderr," %s=%08X",name,static_cast<unsigned>(*value));\n        else std::fprintf(stderr," %s=unmapped",name);',
'''        if (a) {
            auto value=mem->Load<rex::be_u32>(a);
            if(value){std::fprintf(stderr," %s=%08X",name,static_cast<unsigned>(*value));return;}
        }
        std::fprintf(stderr," %s=unmapped",name);''')

def insert(source):
    if TAG in source:raise ValueError("audio probes already inserted")
    lines=[];hits=collections.Counter()
    for line in source.splitlines(keepends=True):
        lines.append(line)
        marker=MARKER.fullmatch(line.rstrip("\r\n"))
        if not marker:continue
        pc=int(marker[2],16)
        if pc not in POINTS:continue
        name,kind=POINTS[pc];hits[pc]+=1
        indent=marker[1]
        lines.append(indent+'if (std::getenv("X360_METRO_BOOT")) {\n')
        lines.append(indent+'  static std::atomic<unsigned> samples{0};\n')
        lines.append(indent+'  const unsigned n=samples.fetch_add(1,std::memory_order_relaxed)+1;\n')
        lines.append(indent+'  if(n<=8 || (n&(n-1))==0)\n')
        lines.append(indent+f'    metro_original_audio_probe("{name}",0x{pc:08X}u,ctx,{kind}u,n);\n')
        lines.append(indent+'}\n')
    return (TAG+"\n"+HEADER+"\n"+"".join(lines),hits) if hits else (source,hits)

def instrument(directory):
    if directory.name!="generated_xam" or not directory.is_dir():
        raise ValueError("expected generated XAM directory")
    pending={};total=collections.Counter()
    for p in sorted(directory.rglob("*.cpp")):
        if p.is_symlink():raise ValueError("generated symlink")
        source,hits=insert(p.read_text())
        if hits:pending[p]=source;total.update(hits)
    if REQUIRED-total.keys():
        raise ValueError("missing essential audio PC markers: "+
                         ", ".join(f"{a:08X}" for a in sorted(REQUIRED-total.keys())))
    for p,source in pending.items():p.write_text(source)
    return {"covered":len(total),"expected":len(POINTS),
            "points":[{"pc":f"{pc:08X}","label":label,"count":total[pc]}
                       for pc,(label,_) in sorted(POINTS.items())]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    root=Path(__file__).resolve().parents[1]/"build"
    if not all(x.resolve().is_relative_to(root) for x in (a.directory,a.receipt)):
        p.error("generated paths under build only")
    result=instrument(a.directory)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print("Original audio probes:",result["covered"],"/",result["expected"])

if __name__=="__main__":main()
