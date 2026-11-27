#!/usr/bin/env python3
"""Add verified entryless bootanim to the already-staged Metro module graph."""
import argparse
import json
import tomllib
from pathlib import Path
from prepare_recompilation import ROOT,original,sha
from pirs import parse as parse_pirs
from decode_image import decode
from stage_aot_host import write_exact
from stage_metro_bootanim_aot import BOOT_SHA,DECODED_SHA,EXPORTS,verified_roots,hints,live_proofs

MODULE='''
[[modules]]
project_name = "metro_bootanim"
file_path = "inputs/bootanim.xex"
guest_path = "bootanim.xex"
out_directory_path = "generated_bootanim"
is_dll = true
includes = ["verified-bootanim-entries.toml"]
'''

# Match the actual generated module source ownership, never assume a target
# name or change the optimization level of the dashboard and XAM.
INTRO_OPTIMIZATION_CMAKE=r"""
get_property(_metro_targets DIRECTORY PROPERTY BUILDSYSTEM_TARGETS)
set(_metro_bootanim_targets "")
foreach(_metro_target IN LISTS _metro_targets)
  get_target_property(_metro_type ${_metro_target} TYPE)
  if(_metro_type STREQUAL "SHARED_LIBRARY")
    get_target_property(_metro_sources ${_metro_target} SOURCES)
    foreach(_metro_source IN LISTS _metro_sources)
      file(TO_CMAKE_PATH "${_metro_source}" _metro_source_path)
      if(_metro_source_path MATCHES "(^|/)generated_bootanim/")
        list(APPEND _metro_bootanim_targets ${_metro_target})
        break()
      endif()
    endforeach()
  endif()
endforeach()
list(LENGTH _metro_bootanim_targets _metro_count)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/generated_bootanim/sources.cmake")
  if(NOT _metro_count EQUAL 1)
    message(FATAL_ERROR "Metro original animation target ownership is ambiguous")
  endif()
  target_compile_options(${_metro_bootanim_targets} PRIVATE
    $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:-O2>)
endif()
unset(_metro_targets)
unset(_metro_bootanim_targets)
unset(_metro_count)
unset(_metro_target)
unset(_metro_type)
unset(_metro_sources)
unset(_metro_source)
unset(_metro_source_path)
"""

def optimized_scaffold(text):
    if INTRO_OPTIMIZATION_CMAKE.strip() in text:
        return text
    if text.count("rexglue_setup_target(dash_17559)")!=1:
        raise ValueError("unexpected dashboard CMake scaffold")
    return text.rstrip()+"\n"+INTRO_OPTIMIZATION_CMAKE

def append_module(text):
    parsed=tomllib.loads(text)
    modules=parsed.get("modules",[])
    if [m["project_name"] for m in modules]!=["metro_xam","metro_hud"]:
        raise ValueError("expected exact verified Metro module graph")
    updated=text.rstrip()+"\n"+MODULE
    out=tomllib.loads(updated)
    if out["entrypoint"]!=parsed["entrypoint"] or out["modules"][:2]!=modules:
        raise ValueError("intro must not alter original dashboard/XAM/HUD declarations")
    return updated

def stage(folder,lzx):
    path=folder/"dash_17559_manifest.toml"
    updated=append_module(path.read_text())
    raw=parse_pirs(original("pirs"))["$flash_bootanim.xex"]["payload"]
    image,meta=decode(raw,lzx)
    pe=verified_roots(raw,image,meta)
    binary=folder/"inputs/bootanim.xex"
    if binary.exists() and sha(binary.read_bytes())!=BOOT_SHA:
        raise ValueError("staged bootanim differs")
    if not binary.exists():binary.write_bytes(raw)
    write_exact(folder/"verified-bootanim-entries.toml",hints(pe))
    write_exact(folder/"src/metro_bootanim_live_proofs.hpp",live_proofs(image,meta))
    write_exact(folder/"src/metro_bootanim_mapping.hpp",
                (ROOT/"tools/native/metro_bootanim_mapping.hpp").read_text())
    cmake=folder/"CMakeLists.txt"
    cmake.write_text(optimized_scaffold(cmake.read_text()))
    path.write_text(updated)
    return {"original_sha256":BOOT_SHA,"decoded_sha256":DECODED_SHA,
            "entrypoint":None,"exports":{str(k):f"{v:08X}" for k,v in EXPORTS.items()},
            "mode":"entryless native user module in original dashboard runtime"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.receipt)):
        p.error("staging under build only")
    result=stage(a.folder,a.lzx.resolve())
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))
if __name__=="__main__":main()
