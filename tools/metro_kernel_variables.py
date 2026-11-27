#!/usr/bin/env python3
"""Generate the exact original kernel data-slot census for both images."""
import json
from prepare_recompilation import ROOT, EXPECTED
from stage_metro_xam_aot import rows

def entries(module):
    meta=json.loads((ROOT/"analysis"/module/"decoded.json").read_text())
    if meta["state"]!="verified" or meta["source_sha256"]!=EXPECTED[module]:
        raise ValueError("wrong original identity")
    result=[]
    for row in rows(ROOT/"analysis"/module/"imports.tsv"):
        if row["library"]!="xboxkrnl.exe" or row["thunk_slots"]:continue
        a=int(row["value_slots"],16);o=int(row["ordinal"],16)
        if not meta["image_base"]<=a<=meta["image_base"]+meta["image_bytes"]-4 or a&3:
            raise ValueError("invalid variable slot")
        result.append((o,a))
    if len(result)!={"dash_17559":16,"xam_17559":20}[module] or len(set(result))!=len(result):
        raise ValueError("unexpected variable import census")
    return result

def header():
    out="#pragma once\n#include <array>\n#include <cstdint>\nstruct KernelVariableBinding {std::uint16_t ordinal; std::uint32_t slot;};\n"
    for name,module in (("Dash","dash_17559"),("Xam","xam_17559")):
        values=entries(module)
        out+=f"inline constexpr std::array<KernelVariableBinding,{len(values)}> k{name}KernelVariables{{{{\n"
        out+="".join(f"    {{0x{o:04X}u, 0x{a:08X}u}},\n" for o,a in values)+"}};\n"
    return out
