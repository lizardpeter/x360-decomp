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
import tomllib
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

def codegen_profile_guard(report):
    # Three modules share the base address. The exact image size AND entry
    # distinguish them, so no union of same-base ordinal/thunk allowlists.
    candidates=[]
    for m in report["modules"].values():
        identity=(f"binary.GetBaseAddress()==0x{m['base']:08X}u && "
                  f"binary.GetImageSize()=={m['size']}u && "
                  f"binary.GetEntryPoint()==0x{m['entry']:08X}u")
        candidates.append((identity,m))
    candidates_expr=" || ".join("("+identity+")" for identity,_ in candidates)
    lines=[]
    for identity,m in candidates:
        lines.append("          if ("+identity+") {")
        lines.append("            switch (sym.address) {")
        lines.extend(f"              case 0x{b['thunk']:08X}u: return ordinal==0x{b['ordinal']:04X}u;"
                     for b in m["xam_bindings"])
        lines+=["              default: return false;","            }","          }"]
    return ('''      // Exact original profile module identity and callable XAM slots.
      const bool metro_profile_module_import=lib_name=="xam" && ('''+candidates_expr+''');
''',
'''      if (metro_profile_module_import) {
        const bool exact=[&]() {
'''+ "\n".join(lines)+'''
          return false;
        }();
        if (!exact)
          return Err(ErrorCategory::kValidation, "Unverified Metro profile XAM import");
        resolved_name=std::format("sub_{:X}", sym.address);
        state.module_imports[sym.address]={lib_name,ordinal};
        module_import_count++;
      }''')

def patch_codegen(source,report,integrated=False):
    if "metro_profile_module_import" in source:
        raise ValueError("unexpected SDK register phase")
    selection,branch=codegen_profile_guard(report)
    if integrated:
        anchor="      // Explicit original dashboard-to-XAM forwarding."
        branch_anchor="      if (metro_retail_function_import) {"
        if source.count(anchor)!=1 or source.count(branch_anchor)!=1:
            raise ValueError("missing integrated retail routing anchor")
        return (source.replace(anchor,selection+anchor,1)
                .replace(branch_anchor,branch+" else if (metro_retail_function_import) {",1))
    if source.count(OLD)!=1:raise ValueError("unexpected SDK register phase")
    return source.replace(OLD,selection+branch+" else if (exp) {\n        if (exp->type == kernel::ExportType::kFunction) {",1)

def cpp_string(value):
    # All names are pinned ASCII firmware members. Use JSON string escaping
    # to express literal guest path separators in generated C++.
    return json.dumps(value)

def patch_profile_loader(source,report):
    """Only original modules, only selected retail XAM, no hosted fallback."""
    path_anchor="  std::string path(raw_name);\n  const bool retail_hud="
    resolve_anchor="    if (rex::kernel::ModuleFromName(library.name) || IsKernelModule(library.name)) {"
    recomp_anchor="  auto recomp = FindRecompiledModule(path);"
    if any(source.count(a)!=1 for a in (path_anchor,resolve_anchor,recomp_anchor)):
        raise ValueError("unexpected retail profile registry anchors")
    if "metro_profile_name" in source:raise ValueError("already patched profile loader")
    names=[]
    identify=[]
    path_checks=[]
    for name,m in report["modules"].items():
        leaf=name+".xex";flash="flash:\\"+leaf
        aliases=[leaf,flash,"\\Device\\Flash\\"+leaf,"\\SystemRoot\\"+leaf]
        tests=" || ".join("rex::string::utf8_equal_case(raw_name,"+cpp_string(a)+")" for a in aliases)
        names.append(f"    if ({tests}) return {cpp_string(leaf)};")
        path_checks.append(f"    if (rex::string::utf8_equal_case(path,{cpp_string(flash)})) return {cpp_string(leaf)};")
        identity=f"xex->GetBaseAddress()==0x{m['base']:08X}u && xex->GetImageSize()=={m['size']}u && module.user.entry_point==0x{m['entry']:08X}u"
        cases="\n".join(f"            case 0x{b['ordinal']:04X}u: return import.value_address==0x{b['slot']:08X}u && import.thunk_address==0x{b['thunk']:08X}u && target==0x{b['target']:08X}u;" for b in m["xam_bindings"])
        identify.append(f'''        if (metro_profile_name=={cpp_string(leaf)}) {{
          if (!({identity}) || library.imports.size()!={len(m['xam_bindings'])}u) return false;
          switch (import.ordinal) {{
{cases}
            default: return false;
          }}
        }}''')
    # Normalize aliases to the immutable flash tree before the registry's
    # loading marker. The same requested file cannot acquire separate refs
    # simply by spelling its guest path differently.
    body='''  std::string path(raw_name);
  const std::string_view metro_profile_name=[&]()->std::string_view {
    if (!StateOf(runtime_).retail_xam_hmodule) return {};
'''+ "\n".join(names)+'''
    return {};
  }();
  if (!metro_profile_name.empty()) {
    path="flash:\\\\"+std::string(metro_profile_name);
    if (auto existing=GetModule(path,true)) {
      AcquireReference(*table_.Get<ModuleObject>(*existing));
      return *existing;
    }
    // Refuse raw XEX attach if the native DLL is absent. This also keeps
    // existing dashboard builds without the opt-in module set safe.
    if (!FindRecompiledModule(path))
      return Err<X_HANDLE>(StatusError(X_STATUS_DLL_NOT_FOUND));
  }
  const bool retail_hud='''
    source=source.replace(path_anchor,body,1)
    # Existing HUD branch is followed by a basename redirect. Do not let that
    # branch replace our previously normalized profile path.
    anchor="  } else if (name == raw_name) {"
    if source.count(anchor)!=1:raise ValueError("unexpected retail basename redirect")
    source=source.replace(anchor,"  } else if (metro_profile_name.empty() && name == raw_name) {",1)
    # Match path + actual loaded original metadata. Validate all imports
    # before mutating any slot or acquiring the retail dependency reference.
    resolve='''    const std::string_view metro_profile_name=[&]()->std::string_view {
      if (!StateOf(runtime_).retail_xam_hmodule) return {};
'''+ "\n".join(path_checks)+'''
      return {};
    }();
    if (!metro_profile_name.empty() && library.name=="xam") {
      const auto handle=runtime_.FindGuestModule("xam.xex");
      auto dep=table_.Get<ModuleObject>(handle);
      if (!dep || dep->hmodule_ptr!=StateOf(runtime_).retail_xam_hmodule || !dep->GetXEX())
        return X_STATUS_DLL_NOT_FOUND;
      if (library.imports.empty()) return X_STATUS_DRIVER_ORDINAL_NOT_FOUND;
      std::size_t verified=0;
      for (const auto& import:library.imports) {
        const auto target=dep->GetXEX()->GetExportAddress(static_cast<u16>(import.ordinal));
        const bool exact=[&]() {
'''+ "\n".join(identify)+'''
          return false;
        }();
        if (!exact || !runtime_.FindFunction(target)) return X_STATUS_DRIVER_ORDINAL_NOT_FOUND;
        ++verified;
      }
      AcquireReference(*dep);
      module.user.dependencies.push_back(handle);
      for (const auto& import:library.imports)
        PatchImportSlot(import.value_address,import.thunk_address);
      REXSYS_INFO("METRO_PROFILE module={} retail_xam_bindings={}",metro_profile_name,verified);
      continue;
    }
'''
    source=source.replace(resolve_anchor,resolve+resolve_anchor,1)
    checks=[]
    for name,m in report["modules"].items():
        checks.append(f'''    if (metro_profile_name=={cpp_string(name+".xex")})
      return module->GetXEX()->GetBaseAddress()==0x{m['base']:08X}u &&
             module->GetXEX()->GetImageSize()=={m['size']}u &&
             module->user.entry_point==0x{m['entry']:08X}u;''')
    registration='''
  if (!metro_profile_name.empty()) {
    const bool exact=recomp && module->GetXEX() && module->user.is_dll_module && [&]() {
'''+ "\n".join(checks)+'''
      return false;
    }();
    if (!exact) {
      ReleaseDependencies(*module,call_entry);
      CloseOwned(table_,created);
      return Err<X_HANDLE>(StatusError(X_STATUS_DLL_NOT_FOUND));
    }
  }
'''
    source=source.replace(recomp_anchor,recomp_anchor+registration,1)
    return source

def preflight_header(report):
    parts=["#pragma once\n#include <cstdint>\n#include <cstddef>\n",
           "namespace metro_profile {\n",
           "struct OriginalBinding {std::uint16_t ordinal; std::uint32_t slot,thunk,target;};\n",
           "struct ModuleProof {const char* name; std::uint32_t base,size,entry; const OriginalBinding* xam; std::size_t xam_count; const OriginalBinding* kernel; std::size_t kernel_count;};\n"]
    for name,m in report["modules"].items():
        for kind in ("xam","kernel"):
            parts.append(f"inline constexpr OriginalBinding k_{name}_{kind}[]={{\n")
            parts.extend(f"  {{0x{b['ordinal']:04X}u,0x{b['slot']:08X}u,0x{b['thunk']:08X}u,0x{b.get('target',0):08X}u}},\n"
                         for b in m[kind+"_bindings"])
            parts.append("};\n")
    parts.append("inline constexpr ModuleProof kModules[]={\n")
    for name,m in report["modules"].items():
        parts.append(f'  {{"{name}.xex",0x{m["base"]:08X}u,{m["size"]}u,0x{m["entry"]:08X}u,k_{name}_xam,{len(m["xam_bindings"])}u,k_{name}_kernel,{len(m["kernel_bindings"])}u}},\n')
    parts.append("};\n}\n")
    return "".join(parts)

def integrated_manifest(text,report):
    parsed=tomllib.loads(text)
    previous=parsed.get("modules",[])
    if [m["project_name"] for m in previous]!=["metro_xam","metro_hud","metro_bootanim"]:
        raise ValueError("expected verified dashboard, XAM, HUD, bootanim manifest")
    blocks=[]
    for name in report["modules"]:
        blocks.append(f'''
[[modules]]
project_name = "metro_{name}"
file_path = "inputs/flash/{name}.xex"
guest_path = "{name}.xex"
out_directory_path = "generated_{name}"
is_dll = true
''')
    result=text.rstrip()+"\n"+"".join(blocks)
    check=tomllib.loads(result)
    if check["project"]!=parsed["project"] or check["entrypoint"]!=parsed["entrypoint"] or check["modules"][:len(previous)]!=previous:
        raise ValueError("profile stage changed existing module graph")
    if len({m["out_directory_path"] for m in check["modules"]})!=len(check["modules"]):
        raise ValueError("shared native module output directory")
    return result

def stage_integrated(folder,report):
    # The normal runtime staging already copies original flash members.
    # Check the exact bytes and refuse to fetch or write new account data.
    for name,m in report["modules"].items():
        raw=folder/"inputs/flash"/(name+".xex")
        if not raw.is_file() or raw.is_symlink() or sha(raw.read_bytes())!=m["source_sha256"]:
            raise ValueError("unverified integrated profile module "+name)
    manifest=folder/"dash_17559_manifest.toml"
    updated=integrated_manifest(manifest.read_text(),report)
    manifest.write_text(updated)
    report["integrated_manifest_staged"]=True

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
    p.add_argument("--integrated",type=Path)
    p.add_argument("--lzx",type=Path)
    p.add_argument("--sdk",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if any(not x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.integrated,a.receipt) if x):
        p.error("generated outputs must remain under build/")
    report=inventory()
    if a.folder:
        if not a.lzx:p.error("--folder requires --lzx")
        stage(a.folder,a.lzx.resolve(),report)
    if a.integrated:
        stage_integrated(a.integrated,report)
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
