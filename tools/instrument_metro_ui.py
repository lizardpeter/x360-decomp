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
        0x92202514:"dash_font_validate_base",0x92202544:"dash_font_validate_patch",
        0x922025A8:"dash_font_construct",0x922025D4:"dash_font_insert",
        0x92218A1C:"dash_stream_open1",0x92218C74:"dash_stream_open2",
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

# Original call sites independently recovered by 46018853868.
# Status-only telemetry; never emit arguments, memory, strings, key material.
TEXT_CALLS = {
    "generated": {
        0x9222FA44:("text_container_open",0x92230460,"status"),
        0x9222FA6C:("text_container_header_read",0x92230670,"status"),
        0x9222FAAC:("text_container_parser",0x9222F7E0,"category"),
        0x9222FADC:("text_container_other_parser",0x9222E328,"category"),
        0x9222F304:("text_verification_provider",0x9293BE3C,"status"),
        0x9222F344:("text_signature_result",0x9293BE2C,"boolean"),
        0x921D81F0:("text_descriptor_create_1",0x921D4580,"category"),
        0x921D8800:("text_descriptor_create_2",0x921D51E0,"category"),
        0x921D94E8:("text_descriptor_create_3",0x921D6ED8,"category"),
        0x927AD454:("text_glyph_prepare_1",0x921DF760,"status"),
        0x927AD468:("text_glyph_operation_1",0x921E3A58,"status"),
        0x927AD484:("text_glyph_prepare_2",0x921DF760,"status"),
        0x927AD498:("text_glyph_operation_2",0x921E3B60,"status"),
        0x92911600:("text_table_object_1",0x928F2618,"category"),
        0x92911610:("text_table_argument_1",0x928E1BB8,"category"),
        0x9291161C:("text_table_value_1",0x921E03E8,"category"),
        0x929116A0:("text_table_object_2",0x928F2618,"category"),
        0x929116BC:("text_table_value_2",0x921E0428,"category"),
        0x9291189C:("text_table_lookup_value",0x921E4180,"category"),
    },
    "generated_xam": {
        0x8179630C:("text_xam_container_open",0x817A2E88,"status"),
        0x81796334:("text_xam_container_header_read",0x817A3098,"status"),
        0x81796374:("text_xam_container_parser",0x817960A8,"category"),
        0x817963A4:("text_xam_container_other_parser",0x81794BF0,"category"),
        0x81795BCC:("text_xam_verification_provider",0x81A72264,"status"),
        0x81795C0C:("text_xam_signature_result",0x81A735D4,"boolean"),
        0x817B8D98:("text_xam_descriptor_create_1",0x817B52D8,"category"),
        0x817B93A8:("text_xam_descriptor_create_2",0x817B5F38,"category"),
        0x817B9F20:("text_xam_descriptor_create_3",0x817B7A80,"category"),
        0x81693948:("text_xam_reference_operation",0x817BCE00,"category"),
        0x816AA2EC:("text_xam_reference_operation_2",0x817C0720,"category"),
    },
    "generated_hud": {},
}
TEXT_ENTRIES = {
    "generated": {0x921D8188:"text_reference_1",0x921D8798:"text_reference_2",
                  0x921D9480:"text_reference_3",0x92286980:"text_reference_4",
                  0x92287A60:"text_reference_5",0x92287B78:"text_reference_6",
                  0x927AD420:"text_glyph_reference",0x92911340:"text_reference_7",
                  0x9222FA20:"text_container_entry",0x9222F2A0:"text_verification_entry"},
    "generated_xam": {0x81693880:"text_xam_reference_1",0x816AA280:"text_xam_reference_2",
                  0x817B8D30:"text_xam_reference_3",0x817B9340:"text_xam_reference_4",
                  0x817B9EB8:"text_xam_reference_5",0x817F0418:"text_xam_reference_6",
                  0x817F0480:"text_xam_reference_7",0x817962E8:"text_xam_container_entry",
                  0x81795B68:"text_xam_verification_entry"},
    "generated_hud": {},
}
TEXT_RESULTS={pc+4:kind for entries in TEXT_CALLS.values()
              for pc,(_,_,kind) in entries.items()}

# Verified original XUI text twins, run 46068603654. At the post-copy
# instruction the original next store is the UTF-16 length at object +44.
# Only recognize public tab labels; never log any other text or object data.
HEADER_POINTS={
 "generated":{0x921CB758:("text_header_copy","entry",4),
              0x921F27A0:("text_header_set","entry",4),
              0x921F2800:("text_header_length","return",0),
              0x921E3AE0:("text_header_get","return",3),
              0x921E3AF8:("text_header_measure","entry",4),
              0x921E3B48:("text_header_measure","return",29)},
 "generated_xam":{0x817ACA98:("text_header_copy","entry",4),
                  0x817CCA28:("text_header_set","entry",4),
                  0x817CCA88:("text_header_length","return",0),
                  0x817C12C8:("text_header_get","return",3),
                  0x817C12E0:("text_header_measure","entry",4),
                  0x817C1330:("text_header_measure","return",29)},
 "generated_hud":{}
}
HEADER_KIND={pc:reg for rows in HEADER_POINTS.values() for pc,(_,_,reg) in rows.items()}
# Exact paired measurement epilogues, before stack/register restoration.
METRIC_POINTS={
 "generated":{0x92228EBC:("text_metric_integer","return",1),
              0x92229250:("text_metric_converted","return",2)},
 "generated_xam":{0x81794664:("text_metric_integer","return",1),
                  0x817949F8:("text_metric_converted","return",2)},
 "generated_hud":{}
}
METRIC_KIND={pc:kind for rows in METRIC_POINTS.values() for pc,(_,_,kind) in rows.items()}
HEADER_PROBE=r"""
#include <rex/kernel/title_runtime.h>
#include <rex/kernel/guest_memory.h>
namespace {
struct MetroHeaderTag {const char* name; unsigned units; unsigned index=0;};
MetroHeaderTag metro_header_tag(rex::kernel::GuestMemory& mem,unsigned addr) {
    // A bounded full-match classifier: arbitrary strings are never printed.
    if(!addr || addr>0xffffffe0u || (addr&1))return {nullptr,0};
    char text[16]={};
    for(unsigned i=0;i<15;++i) {
        const auto value=mem.Load<rex::be_u16>(addr+2*i);
        if(!value)return {nullptr,0};
        unsigned ch=*value;
        if(!ch) {
            struct Known {const char* value; const char* tag;};
            constexpr Known known[]={{"home","home"},{"hom","home_short"},{"movies & tv","movies"},
              {"movies & t","movies_short"},{"social","social"},{"games","games"},
              {"apps","apps"},{"settings","settings"}};
            for(unsigned index=0;index<sizeof(known)/sizeof(known[0]);++index) {
                const auto& k=known[index];
                unsigned n=0;while(k.value[n]&&k.value[n]==text[n])++n;
                if(n==i && !k.value[n])return {k.tag,i,index};
            }
            return {nullptr,0};
        }
        if(ch>=65&&ch<=90)ch+=32;
        if(ch<32||ch>126)return {nullptr,0};
        text[i]=static_cast<char>(ch);
    }
    return {nullptr,0};
}
void metro_header_observe(unsigned pc,const char* phase,const PPCContext& ctx,unsigned reg) {
    auto* mem=REX_GUEST_MEMORY();
    if(!mem)return;
    unsigned address=0;
    if(reg==0) {
        // The original saved pointer-to-string is r29; at the post-wcslen
        // instruction r3 contains the length just before its object store.
        if(!ctx.r29.u32)return;
        const auto ptr=mem->Load<rex::be_u32>(ctx.r29.u32);
        if(!ptr)return;
        address=*ptr;
    } else if(reg==3)address=ctx.r3.u32;
    else if(reg==4)address=ctx.r4.u32;
    else if(reg==29)address=ctx.r29.u32;
    else return;
    const auto tag=metro_header_tag(*mem,address);
    if(!tag.name)return;
    static std::atomic<unsigned> count{0};
    if(count.fetch_add(1,std::memory_order_relaxed)>=256)return;
    if(reg==0) {
        std::fprintf(stderr,"METRO_HEADER pc=%08X phase=%s label=%s units=%u stored_length=%u\n",
                     pc,phase,tag.name,tag.units,ctx.r3.u32);
    } else if(reg==29) {
        std::fprintf(stderr,"METRO_HEADER pc=%08X phase=%s label=%s units=%u status=%08X\n",
                     pc,phase,tag.name,tag.units,ctx.r3.u32);
    } else {
        std::fprintf(stderr,"METRO_HEADER pc=%08X phase=%s label=%s units=%u\n",
                     pc,phase,tag.name,tag.units);
    }
}
void metro_metric_observe(unsigned pc,const PPCContext& ctx,unsigned kind) {
    auto* mem=REX_GUEST_MEMORY();
    if(!mem || (kind!=1 && kind!=2))return;
    // Verified original callee: r27/r28 holds the text in the two stages.
    const auto tag=metro_header_tag(*mem,kind==1?ctx.r27.u32:ctx.r28.u32);
    if(!tag.name)return;
    static std::atomic<unsigned> counts[2][8]{};
    if(counts[kind-1][tag.index].fetch_add(1,std::memory_order_relaxed)>=16)return;
    const unsigned status=ctx.r3.u32;
    const unsigned rect=ctx.r31.u32;
    if(status || !rect || rect>0xfffffff0u || (rect&3)) {
        std::fprintf(stderr,"METRO_HEADER_METRIC pc=%08X kind=%u label=%s units=%u status=%08X rectangle=unavailable\n",
                     pc,kind,tag.name,tag.units,status);
        return;
    }
    unsigned values[4]{};
    for(unsigned i=0;i<4;++i) {
        const auto value=mem->Load<rex::be_u32>(rect+4*i);
        if(!value)return;
        values[i]=*value;
    }
    // Only the original four rectangle fields for known public tab labels.
    // No addresses, arbitrary text, font payloads or object data.
    if(kind==1) {
        std::fprintf(stderr,"METRO_HEADER_METRIC pc=%08X kind=1 label=%s units=%u requested=%d status=%08X rectangle=%08X,%08X,%08X,%08X\n",
                     pc,tag.name,tag.units,static_cast<int>(ctx.r28.s32),status,values[0],values[1],values[2],values[3]);
    } else {
        std::fprintf(stderr,"METRO_HEADER_METRIC pc=%08X kind=2 label=%s units=%u status=%08X rectangle=%08X,%08X,%08X,%08X\n",
                     pc,tag.name,tag.units,status,values[0],values[1],values[2],values[3]);
    }
}
}
"""

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
    for pc,name in TEXT_ENTRIES[module].items():
        if pc in result:raise ValueError("duplicate text entry probe")
        result[pc]=(name,"entry")
    for pc,(name,target,kind) in TEXT_CALLS[module].items():
        if pc in result or pc+4 in result:raise ValueError("duplicate text call probe")
        result[pc]=(name,"call")
        result[pc+4]=(name,"return")
    for pc,(name,phase,_) in HEADER_POINTS[module].items():
        if pc in result:raise ValueError("duplicate header point")
        result[pc]=(name,phase)
    for pc,(name,phase,_) in METRIC_POINTS[module].items():
        if pc in result:raise ValueError("duplicate metric point")
        result[pc]=(name,phase)
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
        if pc in METRIC_KIND:
            result.append(prefix+f'if (std::getenv("X360_METRO_BOOT")) metro_metric_observe(0x{pc:08X}u,ctx,{METRIC_KIND[pc]}u);\n')
            continue
        if pc in HEADER_KIND:
            result.append(prefix+f'if (std::getenv("X360_METRO_BOOT")) metro_header_observe(0x{pc:08X}u,"{phase}",ctx,{HEADER_KIND[pc]}u);\n')
            continue
        result.append(prefix+'if (std::getenv("X360_METRO_BOOT")) {\n')
        result.append(prefix+'  static std::atomic<unsigned> metro_ui_samples{0};\n')
        result.append(prefix+'  const auto metro_ui_n=metro_ui_samples.fetch_add(1,std::memory_order_relaxed)+1;\n')
        result.append(prefix+'  if (metro_ui_n<=8 || (metro_ui_n & (metro_ui_n-1))==0) {\n')
        if name.startswith("text_"):
            kind=TEXT_RESULTS.get(pc,"none") if phase=="return" else "none"
            expression='"observed"'
            if kind=="status":
                expression='ctx.r3.u32==0?"zero":(ctx.r3.u32&0x80000000u?"negative":"positive")'
            elif kind in ("boolean","category"):
                expression='ctx.r3.u32==0?"zero":"nonzero"'
            result.append(prefix+f'    std::fprintf(stderr,"METRO_TEXT pc={pc:08X} label={name} phase={phase} count=%u kind={kind} result=%s\\n",metro_ui_n,{expression});\n')
        else:
            result.append(prefix+f'    std::fprintf(stderr,"METRO_UI pc={pc:08X} label={name} phase={phase} count=%u r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X\\n",metro_ui_n,{args});\n')
        if pc in FONT_PATH_RETURNS or pc in FONT_DESCRIPTORS or pc in FONT_PATCH_RETURNS:
            kind=0 if pc in FONT_PATH_RETURNS else 1 if pc in FONT_DESCRIPTORS else 2
            offset=FONT_PATH_RETURNS.get(pc,0)
            result.append(prefix+f'    metro_font_observe(0x{pc:08X}u,"{name}",ctx,{kind}u,{offset}u);\n')
        result.append(prefix+'  }\n'+prefix+'}\n')
    if not hits:return source,hits
    font=FONT_HEADER if set(hits)&(set(FONT_PATH_RETURNS)|FONT_DESCRIPTORS|FONT_PATCH_RETURNS) else ""
    header=HEADER_PROBE if set(hits)&(HEADER_KIND.keys()|METRIC_KIND.keys()) else ""
    return MARK+"\n#include <atomic>\n#include <cstdio>\n#include <cstdlib>\n"+font+header+"".join(result),hits

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
