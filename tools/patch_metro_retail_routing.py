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
from stage_metro_xam_aot import rows

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

def patched(source,bindings):
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
    return source.replace(OLD,replacement,1)

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
    file.write_text(patched(file.read_text(),bindings))
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps({"functions":521,"variables":1,
         "sdk_kinds":dict(collections.Counter(x["sdk_kind"] for x in bindings)),
         "bindings":bindings},indent=2)+"\n")
    print("Original XAM routing: 521 callable imports and one data import; no hosted XAM substitution")

if __name__=="__main__":main()
