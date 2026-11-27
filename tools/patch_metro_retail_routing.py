#!/usr/bin/env python3
"""Route the exact original 17559 dashboard XAM import set to retail XAM.

The five previously verified bindings remain a separate baseline. This trial
must not silently fall back to the SDK XAM for any of the 521 callable imports.
"""
import argparse
import collections
import json
import re
import subprocess
from pathlib import Path
from prepare_recompilation import ROOT, EXPECTED
from patch_rexglue_imports import REVISION
from stage_metro_xam_aot import rows, HUD_SHA

OLD = """      if (exp) {
        if (exp->type == kernel::ExportType::kFunction) {"""
MATCH = re.compile(r"REX_EXPORT\(xam,\s*0x([0-9a-fA-F]+),\s*(\w+),\s*(kFunction|kVariable)\)")
DATA_ORDINAL = 0x03DB

def one_address(s):
    if not re.fullmatch(r"[0-9A-Fa-f]{8}",s):
        raise ValueError("expected one original address: "+s)
    n=int(s,16)
    if not n or n&3:raise ValueError("unaligned or null address")
    return n

def section(meta, a, size=4):
    sections=[s for s in meta["pe"]["sections"]
              if meta["image_base"]+s["rva"]<=a and
              a+size<=meta["image_base"]+s["rva"]+s["loaded_bytes"]]
    if len(sections)!=1:raise ValueError(f"address not uniquely in original section {a:08X}")
    return sections[0]["flags"]

def catalog(source):
    result={}
    for ordinal,name,kind in MATCH.findall(source):
        n=int(ordinal,16)
        if n in result:raise ValueError("duplicate SDK ordinal")
        result[n]=(name,kind)
    if len(result)<100:raise ValueError("incomplete SDK export catalog")
    return result

def inventory(imports,exports,dash,xam,sdk=None):
    for name,meta in (("dash_17559",dash),("xam_17559",xam)):
        if meta["state"]!="verified" or meta["source_sha256"]!=EXPECTED[name]:
            raise ValueError("unverified image "+name)
    targets={}
    for e in exports:
        o=int(e["ordinal"],16)
        if o in targets:raise ValueError("duplicate retail export ordinal")
        targets[o]=e["address"]
    out=[]
    slots=set();thunks=set();ordinals=set()
    for r in imports:
        if r["library"]!="xam.xex":continue
        o=int(r["ordinal"],16)
        v=one_address(r["value_slots"])
        t=one_address(r["thunk_slots"])
        if o in ordinals or t in thunks or v in slots:
            raise ValueError("ambiguous original import")
        if o not in targets:raise ValueError(f"missing retail export {o:04X}")
        a=one_address(targets[o])
        flags=section(xam,a)
        data=not bool(flags&0x20000000)
        if data!=(o==DATA_ORDINAL) or (data and not flags&0x80000000):
            raise ValueError(f"unexpected original export kind {o:04X}")
        if not section(dash,t,16)&0x20000000 or section(dash,v)&0x20000000:
            raise ValueError(f"unexpected import slot/thunk section {o:04X}")
        item={"ordinal":o,"slot":v,"thunk":t,"target":a,"data":data}
        if sdk is not None:
            name,kind=sdk.get(o,("", "missing"))
            if kind!="missing" and (kind=="kVariable")!=data:
                raise ValueError(f"SDK/retail export type mismatch {o:04X}")
            item.update(sdk_symbol=name,sdk_kind=kind)
        out.append(item);slots.add(v);thunks.add(t);ordinals.add(o)
    if len(out)!=522 or sum(x["data"] for x in out)!=1:
        raise ValueError("unexpected import census")
    return sorted(out,key=lambda x:x["ordinal"])

def original_inventory(sdk=None):
    return inventory(rows(ROOT/"analysis/dash_17559/imports.tsv"),
                     rows(ROOT/"analysis/xam_17559/exports.tsv"),
                     json.loads((ROOT/"analysis/dash_17559/decoded.json").read_text()),
                     json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text()),sdk)

def hud_inventory():
    hud=json.loads((ROOT/"analysis/hud_17559/decoded.json").read_text())
    xam=json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text())
    if hud["state"]!="verified" or hud["source_sha256"]!=HUD_SHA or hud["image_base"]!=0x913E0000:
        raise ValueError("unverified HUD identity")
    if xam["state"]!="verified" or xam["source_sha256"]!=EXPECTED["xam_17559"]:
        raise ValueError("unverified XAM identity")
    exports={int(r["ordinal"],16):one_address(r["address"]) for r in rows(ROOT/"analysis/xam_17559/exports.tsv")}
    out=[]
    for r in rows(ROOT/"analysis/hud_17559/imports.tsv"):
        if r["library"]!="xam.xex":continue
        o=int(r["ordinal"],16)
        v,t=one_address(r["value_slots"]),one_address(r["thunk_slots"])
        a=exports[o]
        if not section(hud,t,16)&0x20000000 or section(hud,v)&0x20000000 or not section(xam,a)&0x20000000:
            raise ValueError("HUD import section mismatch")
        out.append({"ordinal":o,"slot":v,"thunk":t,"target":a,"data":False})
    if len(out)!=233 or any(len({r[k] for r in out})!=233 for k in ("ordinal","slot","thunk")):
        raise ValueError("HUD import census mismatch")
    return sorted(out,key=lambda r:r["ordinal"])

def patched(source,bindings,hud=()):
    if source.count(OLD)!=1 or "metro_retail_function_import" in source:
        raise ValueError("unexpected register phase")
    cases="".join(f"            case 0x{x['ordinal']:04X}: return sym.address == 0x{x['thunk']:08X};\n"
                  for x in bindings if not x["data"])
    replacement="""      // Explicit original dashboard-to-XAM forwarding. Both ordinal and
      // thunk address are checked against the independently joined inventory.
      const bool metro_retail_function_import =
          binary.GetBaseAddress() == 0x92000000 && lib_name == "xam" && [&]() {
          switch (ordinal) {
"""+cases+"""            default: return false;
          }
        }();
      if (metro_retail_function_import) {
        resolved_name = std::format("sub_{:X}", sym.address);
        state.module_imports[sym.address] = {lib_name, ordinal};
        module_import_count++;
      } else if (exp) {
        if (exp->type == kernel::ExportType::kFunction) {"""
    if hud:
        hud_cases="".join(f"            case 0x{x['ordinal']:04X}: return sym.address == 0x{x['thunk']:08X};\n" for x in hud)
        replacement=replacement.replace("        }();\n      if (metro_retail_function_import)",
          "        }() || (binary.GetBaseAddress() == 0x913E0000 && lib_name == \"xam\" && [&]() {\n"
          "          switch (ordinal) {\n"+hud_cases+"            default: return false;\n"
          "          }\n        }());\n      if (metro_retail_function_import)")
    return source.replace(OLD,replacement,1)

def patch_hud_loader(source,hud):
    # Only the verified retail HUD in a session that selected retail XAM.
    # Keep all ordinary titles and SDK XAM loading unchanged.
    anchor="    if (rex::kernel::ModuleFromName(library.name) || IsKernelModule(library.name)) {"
    if source.count(anchor)!=1:raise ValueError("HUD import resolver anchor")
    cases="".join(f"          case 0x{x['ordinal']:04X}: return import.value_address == 0x{x['slot']:08X} && import.thunk_address == 0x{x['thunk']:08X} && target == 0x{x['target']:08X};\n" for x in hud)
    body=r"""
    if (xex->GetBaseAddress()==0x913E0000 && xex->GetImageSize()==299008 &&
        StateOf(runtime_).retail_xam_hmodule && library.name=="xam") {
      const auto handle=runtime_.FindGuestModule("xam.xex");
      auto dep=table_.Get<ModuleObject>(handle);
      if (!dep || dep->hmodule_ptr!=StateOf(runtime_).retail_xam_hmodule ||
          !dep->GetXEX() || library.imports.size()!=233)
        return X_STATUS_DLL_NOT_FOUND;
      std::size_t verified=0;
      for (const auto& import:library.imports) {
        const auto target=dep->GetXEX()->GetExportAddress(static_cast<u16>(import.ordinal));
        const bool exact=[&]() {
          switch (import.ordinal) {
"""+cases+r"""            default: return false;
          }
        }();
        if (!exact || !runtime_.FindFunction(target)) return X_STATUS_DRIVER_ORDINAL_NOT_FOUND;
        ++verified;
      }
      AcquireReference(*dep);
      module.user.dependencies.push_back(handle);
      for (const auto& import:library.imports)
        PatchImportSlot(import.value_address,import.thunk_address);
      REXSYS_INFO("METRO_HUD retail_xam_bindings={}",verified);
      continue;
    }
"""
    source=source.replace(anchor,body+anchor,1)
    anchor="  std::string path(raw_name);\n  if (name == raw_name) {"
    if source.count(anchor)!=1:raise ValueError("HUD load path anchor")
    body=r"""  std::string path(raw_name);
  const bool retail_hud=StateOf(runtime_).retail_xam_hmodule &&
      (rex::string::utf8_equal_case(raw_name,"hud.xex") ||
       rex::string::utf8_equal_case(raw_name,"flash:\\hud.xex") ||
       rex::string::utf8_equal_case(raw_name,"\\Device\\Flash\\hud.xex") ||
       rex::string::utf8_equal_case(raw_name,"\\SystemRoot\\hud.xex"));
  if (retail_hud) {
    path="flash:\\hud.xex";
    if (auto existing=GetModule(path,true)) {
      AcquireReference(*table_.Get<ModuleObject>(*existing));
      return *existing;
    }
  } else if (name == raw_name) {"""
    source=source.replace(anchor,body,1)
    anchor="  auto recomp = FindRecompiledModule(path);"
    if source.count(anchor)!=1:raise ValueError("HUD registration anchor")
    source=source.replace(anchor,anchor+r"""
  if (retail_hud && (!recomp || !module->GetXEX() ||
      module->GetXEX()->GetBaseAddress()!=0x913E0000 ||
      module->GetXEX()->GetImageSize()!=299008 ||
      module->user.entry_point!=0x913F8D00)) {
    ReleaseDependencies(*module,call_entry);
    CloseOwned(table_,created);
    return Err<X_HANDLE>(StatusError(X_STATUS_DLL_NOT_FOUND));
  }
""",1)
    return source

def header(bindings):
    code=[x for x in bindings if not x["data"]]
    return ("#pragma once\n#include <array>\n"
            "inline constexpr std::array<Binding, 521> kRetailFunctionBindings{{\n"+
            "".join(f"    {{0x{x['ordinal']:04X}u, 0x{x['thunk']:08X}u, 0x{x['target']:08X}u, 0x{x['slot']:08X}u}},\n" for x in code)+"}};\n")

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not a.receipt.resolve().is_relative_to((ROOT/"build").resolve()):
        p.error("receipt must be under build/")
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    sdk=catalog((a.sdk/"src/kernel/xam/export_table.inc").read_text())
    bindings=original_inventory(sdk)
    file=a.sdk/"src/codegen/phase_register.cpp"
    hud=hud_inventory()
    file.write_text(patched(file.read_text(),bindings,hud))
    loader=a.sdk/"src/kernel/module_registry.cpp"
    loader.write_text(patch_hud_loader(loader.read_text(),hud))
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps({"functions":521,"variables":1,
         "sdk_kinds":dict(collections.Counter(x["sdk_kind"] for x in bindings)),
         "bindings":bindings,"hud_bindings":hud},indent=2)+"\n")
    print("Original XAM routing: 521 callable imports and one data import; no hosted XAM substitution")

if __name__=="__main__":main()
