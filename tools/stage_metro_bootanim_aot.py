#!/usr/bin/env python3
"""Stage original bootanim as an entryless native module, without launching it."""
import argparse
import json
import hashlib
import re
from pathlib import Path
from prepare_recompilation import ROOT, original, sha
from pirs import parse as parse_pirs
from decode_image import decode
from analyze_decoded import pe_info, ordinal_exports
from metro_bootanim_evidence import BOOT_SHA, DECODED_SHA
from metro_live_slot_and_input_evidence import executable
from stage_aot_host import write_exact
from stage_metro_xam_aot import rows
from xex import parse as parse_xex

EXPORTS={1:0x98020E60,2:0x98020EC8,3:0x98020ED8}
MANIFEST='''[project]
name = "metro_bootanim"
sdk_version = "0.11.0"
game_root = "inputs"

[entrypoint]
file_path = "inputs/bootanim.xex"
out_directory_path = "generated"
is_dll = true
includes = ["verified-exports.toml"]
'''
CMAKE='''cmake_minimum_required(VERSION 3.25)
project(metro_bootanim LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(rexglue 0.11.0 REQUIRED CONFIG)
rexglue_project(metro_bootanim)
add_library(metro_bootanim_module SHARED ${REXGLUE_ENTRYPOINT_GENERATED_SOURCES})
target_include_directories(metro_bootanim_module PRIVATE "${REXGLUE_ENTRYPOINT_INCLUDE_DIR}")
target_link_libraries(metro_bootanim_module PRIVATE rex::sdk)
rexglue_apply_recomp_settings(metro_bootanim_module "${REXGLUE_ENTRYPOINT_INCLUDE_DIR}/metro_bootanim_pch.h")
target_compile_options(metro_bootanim_module PRIVATE
  $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:-O2>)
add_dependencies(metro_bootanim_module metro_bootanim_codegen)
set_target_properties(metro_bootanim_module PROPERTIES CXX_VISIBILITY_PRESET hidden)
rexglue_configure_module_target(metro_bootanim_module)
add_executable(metro_bootanim_probe src/metro_bootanim_module_probe.cpp)
target_link_libraries(metro_bootanim_probe PRIVATE rex::sdk metro_bootanim_module)
rexglue_configure_target(metro_bootanim_probe)
add_executable(metro_bootanim_live src/metro_bootanim_live.cpp)
target_link_libraries(metro_bootanim_live PRIVATE rex::sdk metro_bootanim_module)
rexglue_configure_target(metro_bootanim_live)
'''

def verified_roots(raw,image,meta):
    if sha(raw)!=BOOT_SHA or meta["sha256"]!=DECODED_SHA:
        raise ValueError("original bootanim identity mismatch")
    pe=pe_info(image,meta["image_base"])
    if parse_xex(raw)["entry_point"] is not None or len(image)!=638976:
        raise ValueError("unexpected bootanim entry/layout")
    actual=dict(ordinal_exports(image,meta["image_base"],raw) or [])
    if actual!=EXPORTS:raise ValueError("original bootanim exports differ")
    for target in actual.values():
        if not executable(pe,meta["image_base"],target):
            raise ValueError("nonexecutable export")
    # Ordinal 3 is an original interior callable tail wrapper in the PDATA
    # span beginning at ordinal 2. Preserve a distinct callable root rather
    # than treating its address as a guessed alternate entry of that body.
    return pe

def hints(pe):
    starts={a:s for a,s,_ in pe["functions"]}
    # The two short wrappers are separate entries. Original export evidence
    # and unconditional tails bound them (the intervening words are padding).
    # Do not supply conflicting PDATA sizes; let codegen discover graph bounds.
    return "[functions]\n"+"".join(f"0x{a:08X} = {{}}\n" for a in EXPORTS.values())

def live_proofs(image,meta):
    pin=json.loads((ROOT/"analysis/bootanim_17559/resource_hashes.json").read_text())[0]
    address=int(pin["address"],16);size=pin["bytes"]
    start=address-meta["image_base"];audio=image[start:start+size]
    if len(audio)!=size or sha(audio)!=pin["sha256"]:raise ValueError("audio resource identity")
    fingerprint=0xcbf29ce484222325
    for byte in audio:fingerprint=((fingerprint^byte)*0x100000001b3)&0xffffffffffffffff
    imports=rows(ROOT/"analysis/bootanim_17559/imports.tsv")
    values=[]
    for row in imports:
        if row["library"]!="xboxkrnl.exe":raise ValueError("unexpected bootanim dependency")
        slots=row["value_slots"].split(",")
        thunks=row["thunk_slots"].split(",") if row["thunk_slots"] else []
        if len(slots)!=1 or len(thunks)>1:raise ValueError("unexpected import record")
        values.append((int(row["ordinal"],16),int(slots[0],16),int(thunks[0],16) if thunks else 0))
    if len(values)!=114 or sum(bool(x[2]) for x in values)!=104:raise ValueError("import census")
    return ("#pragma once\n#include <cstdint>\n"
            "struct BootanimImport {std::uint16_t ordinal; std::uint32_t slot,thunk;};\n"
            "inline constexpr BootanimImport kBootanimImports[] = {\n"+
            "".join(f"    {{0x{o:04X}u,0x{s:08X}u,0x{t:08X}u}},\n" for o,s,t in values)+
            "};\n"+f"inline constexpr std::uint32_t kAudioAddress=0x{address:08X}u,kAudioBytes={size}u;\n"+
            f"inline constexpr std::uint64_t kAudioDigest=0x{fingerprint:016X}ull;\n")

def stage(folder,lzx):
    raw=parse_pirs(original("pirs"))["$flash_bootanim.xex"]["payload"]
    image,meta=decode(raw,lzx)
    pe=verified_roots(raw,image,meta)
    (folder/"inputs").mkdir(parents=True,exist_ok=True)
    (folder/"src").mkdir(exist_ok=True)
    binary=folder/"inputs/bootanim.xex"
    if binary.exists() and sha(binary.read_bytes())!=BOOT_SHA:
        raise ValueError("staged boot animation differs")
    if not binary.exists():binary.write_bytes(raw)
    write_exact(folder/"metro_bootanim_manifest.toml",MANIFEST)
    write_exact(folder/"verified-exports.toml",hints(pe))
    write_exact(folder/"CMakeLists.txt",CMAKE)
    write_exact(folder/"src/metro_bootanim_module_probe.cpp",
                (ROOT/"tools/native/metro_bootanim_module_probe.cpp").read_text())
    write_exact(folder/"src/metro_bootanim_live.cpp",
                (ROOT/"tools/native/metro_bootanim_live.cpp").read_text())
    write_exact(folder/"src/metro_bootanim_live_proofs.hpp",live_proofs(image,meta))
    return {"source_sha256":BOOT_SHA,"decoded_sha256":DECODED_SHA,
            "exports":{str(k):f"{v:08X}" for k,v in EXPORTS.items()},
            "pdata_functions":len(pe["functions"]),"entrypoint":None,
            "scope":"native module code generation and callable registration only"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.receipt)):
        p.error("generated files must remain under build/")
    result=stage(a.folder,a.lzx.resolve())
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))
if __name__=="__main__":main()
