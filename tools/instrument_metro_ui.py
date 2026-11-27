#!/usr/bin/env python3
"""Bounded read-only probes at original UI initialization and resource calls."""
import argparse
import collections
import json
from pathlib import Path
from instrument_metro_heap import MARKER

# Recovered by run 45956523616. Calls/returns are adjacent exact original PCs.
# Functions with several returns use entry probes; caller post-call PCs record
# their genuine results. Only r3..r8 are observed, not localized registers.
CALLS = {
    "generated": {
        0x922198D0:"dash_section_lookup",0x927C6200:"dash_xui_section",
        0x927CDDE4:"dash_xui_section2",0x92181B10:"dash_shared_locator",
        0x927492DC:"dash_locator",0x927DB6C0:"dash_locator2",
        # Original font setup and resolver calls from 45978542649.
        0x922186D0:"dash_file_open",
        0x922655FC:"dash_font_typeface_1",0x92265604:"dash_font_patch_1",
        0x92265624:"dash_font_typeface_2",0x9226562C:"dash_font_patch_2",
        0x92265654:"dash_font_typeface_3",0x9226565C:"dash_font_patch_3",
        0x92265690:"dash_font_typeface_4",0x92265698:"dash_font_patch_4",
        0x922656AC:"dash_font_typeface_5",0x922656B4:"dash_font_patch_5",
        0x922656EC:"dash_font_enumerate",0x9226570C:"dash_font_release",
        0x92265754:"dash_font_register_1",0x92265778:"dash_font_register_2",
        0x922657B8:"dash_font_register_3",
    },
    "generated_xam": {
        0x817DD348:"xam_section_lookup",0x81903F94:"xam_section_lookup2",
        0x8190CD60:"xam_section_lookup3",0x81945474:"xam_section_lookup4",
        0x81699858:"xam_font_probe_path",0x81699890:"xam_font_copy_path_1",
        0x816998A8:"xam_font_append_path",0x816998F8:"xam_font_copy_path_2",
    },
    "generated_hud": {
        0x913E9960:"hud_xui_init",0x913E827C:"hud_scene_create",
        0x913EA630:"hud_scene_create2",0x913EA650:"hud_scene_forward",
        0x913EAA9C:"hud_scene_create3",0x913EAAB8:"hud_scene_first",
        0x913EB8DC:"hud_scene_create4",0x913EB8F8:"hud_scene_first2",
        0x913F0EBC:"hud_scene_create5",0x913E9BA8:"hud_render_begin",
        0x913E9C20:"hud_render_present",
    },
}
ENTRIES = {
    "generated": {0x92285890:"dash_common_setup",0x922FDFA0:"dash_user_path",
                  0x92775048:"dash_controlpack_setup",0x927A4AC0:"dash_controlpack_uri",
                  0x927A65B8:"dash_controlpack_uri2",0x922655D8:"dash_font_setup",
                  0x92202490:"dash_font_register",0x929115D0:"dash_string_table_load",
                  0x92911670:"dash_string_table_load2",0x92911870:"dash_string_table_lookup"},
    "generated_xam": {0x816C8A48:"retail_resource_locator",
                      0x816C8BF0:"retail_shared_locator",0x817BC088:"retail_xui_init",
                      0x817C4A58:"retail_scene_create",0x817C5390:"retail_scene_first",
                      0x817C54D0:"retail_scene_forward",0x8177DA10:"retail_render_begin",
                      0x8177DAA0:"retail_render_present",0x817FE5C0:"xam_controlpack_setup",
                      0x81807DB8:"xam_controlpack_uri",0x81699190:"xam_font_patch_resolver",
                      0x81699810:"xam_font_typeface_resolver",0x81699244:"xam_font_patch_result",
                      0x81699910:"xam_font_typeface_result"},
    "generated_hud": {0x913E98F8:"hud_initialize",0x913E9B88:"hud_render_loop"},
}
MARK="/* METRO_UI_PROBES_INSERTED */"
FONT_PATH_RETURNS={
    0x92265600:656,0x92265628:128,0x92265658:128,
    0x92265694:656,0x922656B0:128,
}
FONT_DESCRIPTORS={0x92265754,0x92265778,0x922657B8,0x92202490}
FONT_PATCH_RETURNS={0x92265608,0x92265630,0x92265660,0x9226569C,0x922656B8,0x81699244}
FONT_HEADER=r"""
#include <string>
#include <string_view>
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
namespace {
struct MetroFontPath {const char* tag;unsigned units;};
MetroFontPath metro_font_path(rex::kernel::GuestMemory& mem,unsigned addr) {
    if(!addr)return {"null",0};
    std::string ascii;
    for(unsigned i=0;i<260;++i) {
        if(addr>0xffffffffu-2*i)return {"unmapped",i};
        const auto value=mem.Load<rex::be_u16>(addr+2*i);
        if(!value)return {"unmapped",i};
        const unsigned ch=*value;
        if(!ch) {
            const auto slash=ascii.find_last_of("/\\");
            const auto name=std::string_view(ascii).substr(slash==std::string::npos?0:slash+1);
            if(name=="segoexbox-light.xtt")return {"segoe",i};
            if(name=="xenonclatin.xtt")return {"clatin",i};
            if(name=="xenonjklatin.xtt")return {"jklatin",i};
            return {i?"other":"empty",i};
        }
        ascii.push_back(ch>=65&&ch<=90?static_cast<char>(ch+32):
                        ch<128?static_cast<char>(ch):'?');
    }
    return {"unterminated",260};
}
void metro_font_observe(unsigned pc,const char* label,const PPCContext& ctx,unsigned kind,unsigned offset) {
    auto* mem=REX_GUEST_MEMORY();
    if(!mem)return;
    unsigned address=0,detail=0;
    const char* category="path";
    if(kind==0) {
        const unsigned sp=ctx.r1.u32;
        if(sp && sp<=0xffffffffu-offset)address=sp+offset;
    } else if(kind==1) {
        category="descriptor";
        const unsigned descriptor=ctx.r3.u32;
        if(!descriptor || descriptor>0xffffffffu-20u) {
            std::fprintf(stderr,"METRO_FONT pc=%08X label=%s kind=descriptor status=%08X path=unmapped units=0 detail=unmapped\n",pc,label,ctx.r3.u32);
            return;
        }
        auto path=mem->Load<rex::be_u32>(descriptor+4);
        auto patch=mem->Load<rex::be_u32>(descriptor+8);
        if(!path || !patch) {
            std::fprintf(stderr,"METRO_FONT pc=%08X label=%s kind=descriptor status=%08X path=unmapped units=0 detail=unmapped\n",pc,label,ctx.r3.u32);
            return;
        }
        address=*path;detail=*patch;
    } else {
        category="patch";address=ctx.r3.u32;
    }
    const auto path=metro_font_path(*mem,address);
    std::fprintf(stderr,"METRO_FONT pc=%08X label=%s kind=%s status=%08X path=%s units=%u detail=%08X\n",
                 pc,label,category,ctx.r3.u32,path.tag,path.units,detail);
}
}
"""

def probes(module):
    result={pc:(name,"entry") for pc,name in ENTRIES[module].items()}
    for pc,name in CALLS[module].items():
        result[pc]=(name,"call")
        result[pc+4]=(name,"return")
    return result

def insert(source,points):
    if MARK in source:raise ValueError("UI probes already inserted")
    result=[];hits=collections.Counter()
    for line in source.splitlines(keepends=True):
        result.append(line)
        m=MARKER.fullmatch(line.rstrip("\r\n"))
        if not m:continue
        pc=int(m[2],16)
        if pc not in points:continue
        name,phase=points[pc];hits[pc]+=1
        prefix=m[1]
        args=", ".join(f"static_cast<unsigned>(ctx.r{i}.u32)" for i in range(3,9))
        result.append(prefix+'if (std::getenv("X360_METRO_BOOT")) {\n')
        result.append(prefix+'  static std::atomic<unsigned> metro_ui_samples{0};\n')
        result.append(prefix+'  const auto metro_ui_n=metro_ui_samples.fetch_add(1,std::memory_order_relaxed)+1;\n')
        result.append(prefix+'  if (metro_ui_n<=8 || (metro_ui_n & (metro_ui_n-1))==0) {\n')
        result.append(prefix+f'    std::fprintf(stderr,"METRO_UI pc={pc:08X} label={name} phase={phase} count=%u r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X\\n",metro_ui_n,{args});\n')
        if pc in FONT_PATH_RETURNS or pc in FONT_DESCRIPTORS or pc in FONT_PATCH_RETURNS:
            kind=0 if pc in FONT_PATH_RETURNS else 1 if pc in FONT_DESCRIPTORS else 2
            offset=FONT_PATH_RETURNS.get(pc,0)
            result.append(prefix+f'    metro_font_observe(0x{pc:08X}u,"{name}",ctx,{kind}u,{offset}u);\n')
        result.append(prefix+'  }\n'+prefix+'}\n')
    if not hits:return source,hits
    font=FONT_HEADER if set(hits)&(set(FONT_PATH_RETURNS)|FONT_DESCRIPTORS|FONT_PATCH_RETURNS) else ""
    return MARK+"\n#include <atomic>\n#include <cstdio>\n#include <cstdlib>\n"+font+"".join(result),hits

def instrument(folder):
    report={}
    pending={}
    for module in CALLS:
        directory=folder/module
        if not directory.is_dir():raise ValueError("missing "+module)
        points=probes(module);total=collections.Counter()
        for path in sorted(directory.rglob("*.cpp")):
            if path.is_symlink():raise ValueError("generated symlink")
            patched,hits=insert(path.read_text(),points)
            if hits:
                pending[path]=patched;total.update(hits)
        # Some compiler-generated blocks can omit or duplicate entry markers.
        # Report actual coverage separately; never mistake missing probes for
        # functions that did not execute.
        report[module]={"points":[{"pc":f"{pc:08X}","label":name,"phase":phase,
                                   "occurrences":total[pc]} for pc,(name,phase) in sorted(points.items())],
                        "covered":len(total),"expected":len(points)}
        if not total:raise ValueError("no original UI markers in "+module)
    for path,source in pending.items():path.write_text(source)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    root=Path(__file__).resolve().parents[1]/"build"
    if not all(x.resolve().is_relative_to(root) for x in (a.folder,a.receipt)):
        p.error("generated paths must be under build")
    result=instrument(a.folder)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print("UI probes:",{k:(v["covered"],v["expected"]) for k,v in result.items()})
if __name__=="__main__":main()
