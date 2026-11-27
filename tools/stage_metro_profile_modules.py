#!/usr/bin/env python3
"""Isolated native compilation of five original Metro profile UI modules.

All module identities and retail XAM imports must match independently decoded
firmware. Shared guest addresses are deliberately not co-registered. This trial
never executes guest code and does not create, sign in, or modify an account.
"""
import argparse
import collections
import itertools
import json
import re
import subprocess
from pathlib import Path
from analyze_decoded import imports, pe_info, ordinal_exports
from decode_image import decode
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from patch_rexglue_imports import REVISION
from patch_metro_retail_routing import OLD, one_address, section
from stage_metro_xam_aot import rows
from stage_aot_host import write_exact
from xex import parse as parse_xex

# name: source hash, decoded hash, base, size, entry, PDATA, XAM, kernel
SPECS={
    "signin":("86695c6c36250cc4b4addb7ccc07d15d54492b352c979cf5c0934804109a6130",
              "9aa0bead2c38f0d3882b352d0ead30df39707875549c659a33d757519e929689",
              0x90100000,274432,0x901054E0,456,232,18),
    "deviceselector":("2334c6772fd54201e60792c70a54e4714aaf74d45f657013ebe5da3737e06c0c",
              "1e30e6eee8b5e2c0414faafa128f55ef24c961ede4d947d4815acbde2c83e63c",
              0x916D0000,94208,0x916D7230,129,87,3),
    "vk":("876ddbb333d83f408ab7c69267703e623daef6da5b1eb3302bd94d246155724e",
              "73f7d79e3929c212bf9c9f3122d4962f480dc78063dbafdfe4904aec467864d5",
              0x917D0000,114688,0x917DFBA8,177,89,7),
    "gamerprofile":("a99fb2ae20c4b3ffab9fa5f6a73e5766b49fbed5716e8b4d3752d1b97b83aad4",
              "25975c0c2fad9bb3ee66ca89f0a7bd5ab64b32b3051ccce1fa0a762ec697c3b7",
              0x90100000,319488,0x9011C6C0,715,189,23),
    "createprofile":("c5dae66e2e7b408ef6d84d659a2232ad89f01d78fa38c365d8732f2e0a221bbd",
              "caafb8f9056fa2b16ba5711325b975da06f5965ec2105c3a5f8202e67f59b9d3",
              0x90100000,114688,0x901094A8,222,113,13),
}

def metadata(name):
    return json.loads((ROOT/"analysis"/(name+"_17559")/"decoded.json").read_text())

def records(name):
    out=[]
    for r in rows(ROOT/"analysis"/(name+"_17559")/"imports.tsv"):
        out.append((r["library"],int(r["ordinal"],16),
                    one_address(r["value_slots"]),one_address(r["thunk_slots"])))
    return sorted(out)

def validate_metadata(name,meta):
    src,digest,base,size,entry,pdata,xam,kernel=SPECS[name]
    if (meta["state"],meta["source_sha256"],meta["sha256"],meta["image_base"],
        meta["image_bytes"],meta["pe"]["entry_point"],meta["pdata_functions"],
        meta["function_imports"],meta["value_only_imports"])!=(
        "verified",src,digest,base,size,entry,pdata,xam+kernel,0):
        raise ValueError("unexpected original module identity "+name)
    if not section(meta,entry)&0x20000000:
        raise ValueError("nonexecutable module entry "+name)

def inventory():
    xam=metadata("xam")
    if xam["state"]!="verified" or xam["source_sha256"]!=EXPECTED["xam_17559"]:
        raise ValueError("wrong XAM source")
    targets={}
    for r in rows(ROOT/"analysis/xam_17559/exports.tsv"):
        o=int(r["ordinal"],16)
        if o in targets:raise ValueError("duplicate XAM ordinal")
        targets[o]=one_address(r["address"])
    modules={}
    for name,spec in SPECS.items():
        meta=metadata(name);validate_metadata(name,meta)
        bindings=[];kernel=[];slots=set();thunks=set();ordinals=set()
        for lib,o,v,t in records(name):
            if lib not in ("xam.xex","xboxkrnl.exe") or (lib,o) in ordinals or v in slots or t in thunks:
                raise ValueError("ambiguous or foreign module import "+name)
            if not section(meta,t,16)&0x20000000 or section(meta,v)&0x20000000:
                raise ValueError("invalid import section "+name)
            item={"ordinal":o,"slot":v,"thunk":t}
            if lib=="xam.xex":
                target=targets[o]
                if not section(xam,target)&0x20000000:raise ValueError("noncallable XAM export")
                bindings.append(dict(item,target=target))
            else:kernel.append(item)
            slots.add(v);thunks.add(t);ordinals.add((lib,o))
        if (len(bindings),len(kernel))!=spec[-2:]:raise ValueError("wrong import census "+name)
        modules[name]={"source_sha256":spec[0],"decoded_sha256":spec[1],"base":spec[2],
                       "size":spec[3],"entry":spec[4],"pdata_functions":spec[5],
                       "xam_bindings":bindings,"kernel_bindings":kernel}
    tuples={(m["base"],b["ordinal"],b["thunk"]) for m in modules.values() for b in m["xam_bindings"]}
    distinct={b["ordinal"] for m in modules.values() for b in m["xam_bindings"]}
    if len(tuples)!=710 or len(distinct)!=366:raise ValueError("unexpected aggregate import census")
    overlaps=[]
    for (a,m),(b,n) in itertools.combinations(modules.items(),2):
        if max(m["base"],n["base"])<min(m["base"]+m["size"],n["base"]+n["size"]):
            overlaps.append([a,b])
    return {"modules":modules,"xam_binding_count":710,"distinct_xam_ordinals":366,
            "pdata_functions":sum(m["pdata_functions"] for m in modules.values()),
            "overlapping_guest_images":overlaps,"guest_executed":False}

def patch_codegen(source,report):
    if source.count(OLD)!=1 or "metro_profile_module_import" in source:
        raise ValueError("unexpected SDK register phase")
    by_base=collections.defaultdict(dict)
    for m in report["modules"].values():
        for b in m["xam_bindings"]:
            if b["thunk"] in by_base[m["base"]]:raise ValueError("ambiguous native thunk address")
            by_base[m["base"]][b["thunk"]]=b["ordinal"]
    bases=" || ".join(f"binary.GetBaseAddress()==0x{a:08X}u" for a in sorted(by_base))
    code=""
    for base,items in sorted(by_base.items()):
        code+=f"          case 0x{base:08X}u:\n            switch (sym.address) {{\n"
        code+="".join(f"              case 0x{t:08X}u: return ordinal==0x{o:04X}u;\n" for t,o in sorted(items.items()))
        code+="              default: return false;\n            }\n"
    replacement='''      // Profile UI modules are isolated compile trials, not hosted XAM shims.
      const bool metro_profile_module_import=lib_name=="xam" && ('''+bases+''');
      if (metro_profile_module_import) {
        const bool exact=[&]() {
          switch (binary.GetBaseAddress()) {
'''+code+'''            default: return false;
          }
        }();
        if (!exact)
          return Err(ErrorCategory::kValidation, "Unverified Metro profile XAM import");
        resolved_name=std::format("sub_{:X}", sym.address);
        state.module_imports[sym.address]={lib_name,ordinal};
        module_import_count++;
      } else if (exp) {
        if (exp->type == kernel::ExportType::kFunction) {'''
    return source.replace(OLD,replacement,1)

def scaffold(folder,name,m):
    project="metro_"+name
    manifest=f'''[project]
name = "{project}"
sdk_version = "0.11.0"
game_root = "inputs"

[entrypoint]
file_path = "inputs/{name}.xex"
out_directory_path = "generated"
is_dll = true
'''
    cmake='''cmake_minimum_required(VERSION 3.25)
project(@PROJECT@ LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(rexglue 0.11.0 REQUIRED CONFIG)
rexglue_project(@PROJECT@)
add_library(@PROJECT@_module SHARED ${REXGLUE_ENTRYPOINT_GENERATED_SOURCES})
target_include_directories(@PROJECT@_module PRIVATE "${REXGLUE_ENTRYPOINT_INCLUDE_DIR}")
target_link_libraries(@PROJECT@_module PRIVATE rex::sdk)
rexglue_apply_recomp_settings(@PROJECT@_module "${REXGLUE_ENTRYPOINT_INCLUDE_DIR}/@PROJECT@_pch.h")
add_dependencies(@PROJECT@_module @PROJECT@_codegen)
set_target_properties(@PROJECT@_module PROPERTIES CXX_VISIBILITY_PRESET hidden)
rexglue_configure_module_target(@PROJECT@_module)
add_executable(metro_profile_probe src/metro_profile_module_probe.cpp)
target_link_libraries(metro_profile_probe PRIVATE rex::sdk @PROJECT@_module)
rexglue_configure_target(metro_profile_probe)
'''.replace("@PROJECT@",project)
    header=("#pragma once\n#include <cstdint>\n"
            f'inline constexpr char kName[]="{name}";\n'
            f"inline constexpr std::uint32_t kBase=0x{m['base']:08X}u,kSize={m['size']}u,kEntry=0x{m['entry']:08X}u;\n"
            "inline constexpr std::uint32_t kXamThunks[]={\n"+
            "".join(f"  0x{b['thunk']:08X}u,\n" for b in m["xam_bindings"])+"};\n")
    write_exact(folder/(project+"_manifest.toml"),manifest)
    write_exact(folder/"CMakeLists.txt",cmake)
    write_exact(folder/"src/metro_profile_module_probe.cpp",(ROOT/"tools/native/metro_profile_module_probe.cpp").read_text())
    write_exact(folder/"src/profile_module_identity.hpp",header)

def decoded_records(raw,image,base):
    result=[]
    for r in imports(image,base,parse_xex(raw)):
        if len(r["value_slots"])!=1 or len(r["thunk_slots"])!=1:
            raise ValueError("unexpected decoded import multiplicity")
        result.append((r["library"],int(r["ordinal"],16),r["value_slots"][0],r["thunk_slots"][0]))
    return sorted(result)

def stage(folder,lzx,report):
    members=parse_pirs(original("pirs"))
    xam=members["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("XAM original hash mismatch")
    image,meta=decode(xam,lzx)
    if meta["sha256"]!=metadata("xam")["sha256"]:raise ValueError("decoded XAM mismatch")
    exports=dict(ordinal_exports(image,meta["image_base"],xam))
    for name,m in report["modules"].items():
        raw=members[f"$flash_{name}.xex"]["payload"]
        if sha(raw)!=m["source_sha256"]:raise ValueError("original module hash mismatch "+name)
        image,meta=decode(raw,lzx)
        pe=pe_info(image,meta["image_base"])
        if (meta["sha256"],meta["image_base"],len(image),pe["entry_point"],len(pe["functions"]))!=(
             m["decoded_sha256"],m["base"],m["size"],m["entry"],m["pdata_functions"]):
            raise ValueError("decoded module mismatch "+name)
        if decoded_records(raw,image,m["base"])!=records(name):
            raise ValueError("decoded import mismatch "+name)
        if any(exports.get(b["ordinal"])!=b["target"] for b in m["xam_bindings"]):
            raise ValueError("original export mismatch "+name)
        directory=folder/name
        (directory/"inputs").mkdir(parents=True,exist_ok=True)
        (directory/"src").mkdir(exist_ok=True)
        path=directory/"inputs"/(name+".xex")
        if path.exists() and sha(path.read_bytes())!=m["source_sha256"]:raise ValueError("staged module differs")
        if not path.exists():path.write_bytes(raw)
        scaffold(directory,name,m)
    report["original_bytes_reverified"]=True

def mapping_coverage(source,report):
    from filter_zero_aot_mappings import TABLE,ROW
    if source.count(TABLE)!=1:raise ValueError("ambiguous XAM mapping table")
    start=source.index(TABLE);end=source.find("\n};",start)
    if end<0:raise ValueError("unterminated XAM mapping table")
    addresses=set()
    for line in source[start:end].splitlines():
        match=ROW.match(line)
        if match:
            a=int(match.group(2),16)
            if a and match.group(3).strip()!="nullptr":addresses.add(a)
    if not addresses:raise ValueError("empty XAM mapping table")
    result={}
    for name,m in report["modules"].items():
        missing=[b for b in m["xam_bindings"] if b["target"] not in addresses]
        result[name]={"required_bindings":len(m["xam_bindings"]),
                      "mapped_bindings":len(m["xam_bindings"])-len(missing),
                      "missing":missing}
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--folder",type=Path)
    p.add_argument("--lzx",type=Path)
    p.add_argument("--sdk",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if any(not x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.receipt) if x):
        p.error("generated outputs must remain under build/")
    report=inventory()
    if a.folder:
        if not a.lzx:p.error("--folder requires --lzx")
        stage(a.folder,a.lzx.resolve(),report)
    if a.sdk:
        if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
            raise ValueError("unexpected SDK revision")
        file=a.sdk/"src/codegen/phase_register.cpp"
        file.write_text(patch_codegen(file.read_text(),report))
        subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(report,indent=2)+"\n")
    print("Profile module census:",report["pdata_functions"],"PDATA functions,",
          report["xam_binding_count"],"original XAM bindings,",report["distinct_xam_ordinals"],
          "unique ordinals; overlapping modules",report["overlapping_guest_images"])

if __name__=="__main__":main()
