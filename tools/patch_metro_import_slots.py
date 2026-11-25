#!/usr/bin/env python3
"""Patch five verified Metro function imports and one XAM data import during XEX loading.

The five code imports are forwarded to the native XAM exports. The data
import is bound directly to the original writable XAM image address.
"""
import argparse
import subprocess
from pathlib import Path
import json
import re
from prepare_recompilation import ROOT, EXPECTED
from patch_rexglue_imports import REVISION
from stage_metro_xam_aot import BINDINGS, rows, verify_bindings

VALUE_SLOTS = {
    0x0546: 0x92000BC4,
    0x0547: 0x92000BCC,
    0x0548: 0x92000BC8,
    0x0549: 0x92000BD0,
    0x054B: 0x920005D0,
}
VARIABLE_ORDINAL = 0x03DB
VARIABLE_SLOT = 0x92000550
VARIABLE_TARGET = 0x81A87F20
VARIABLE_OLD = '''          } else {
            *record_slot = 0xD000BEEF | (kernel_export->ordinal & 0xFFF) << 16;
            REXSYS_WARN("Variable import {}:{:#x} ({}) not implemented", base_name, ordinal,
                        kernel_export->name);
          }'''
VARIABLE_NEW = '''          } else if (base_address_ == 0x92000000 && base_name == "xam" &&
                     ordinal == 0x03DB && record_addr == 0x92000550 &&
                     kernel_export->name == "g_XuiAutomation") {
            *record_slot = 0x81A87F20;
            REXSYS_DEBUG("Patched verified Metro XAM variable import {}:{:#x} ({}) -> {:#x}",
                         base_name, ordinal, kernel_export->name, 0x81A87F20);
          } else {
            *record_slot = 0xD000BEEF | (kernel_export->ordinal & 0xFFF) << 16;
            REXSYS_WARN("Variable import {}:{:#x} ({}) not implemented", base_name,
                        ordinal, kernel_export->name);
          }'''

OLD = '''      REXSYS_DEBUG("Patched function import {}:{:#x} ({}) -> {:#x}", base_name, ordinal,
                   kernel_export->name, import_info.thunk_address);
    }'''
CONDITIONS = " ||\n         ".join(
    f"(ordinal == 0x{o:04X} && import_info.value_address == 0x{v:08X} && "
    f"import_info.thunk_address == 0x{BINDINGS[o][0]:08X})"
    for o, v in sorted(VALUE_SLOTS.items()))
NEW = OLD + ''' else if (!kernel_export && base_address_ == 0x92000000 &&
               base_name == "xam" &&
        (''' + CONDITIONS + ''')) {
      *GetAddressSpace()->TranslateVirtual<be_u32*>(import_info.value_address) =
          import_info.thunk_address;
      REXSYS_DEBUG("Patched verified Metro XAM function import {:#x} -> {:#x}",
                   ordinal, import_info.thunk_address);
    }'''

def verify_slots(imports, exports):
    verify_bindings(imports, exports)
    for ordinal, slot in VALUE_SLOTS.items():
        matches = [r for r in imports if r["library"] == "xam.xex" and
                   int(r["ordinal"], 16) == ordinal]
        if len(matches) != 1 or matches[0]["value_slots"] != f"{slot:08X}":
            raise ValueError(f"unexpected Metro value slot {ordinal:04X}")

    # This is a data import, not a thunk. Verify both ends against the
    # hash-verified retail images and require a writable, non-executable XAM
    # section before hard-wiring the guest address.
    imports_3db = [r for r in imports if r["library"] == "xam.xex" and
                   int(r["ordinal"], 16) == VARIABLE_ORDINAL]
    exports_3db = [r for r in exports if int(r["ordinal"], 16) == VARIABLE_ORDINAL]
    if (len(imports_3db) != 1 or imports_3db[0]["value_slots"] != f"{VARIABLE_SLOT:08X}" or
            imports_3db[0]["thunk_slots"] or len(exports_3db) != 1 or
            int(exports_3db[0]["address"], 16) != VARIABLE_TARGET):
        raise ValueError("unexpected Metro g_XuiAutomation import/export binding")
    meta = json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text())
    if meta.get("state") != "verified" or meta.get("source_sha256") != EXPECTED["xam_17559"]:
        raise ValueError("unverified retail XAM image for data import")
    in_writable_data = any(
        (section["flags"] & 0x80000000) and not (section["flags"] & 0x20000000) and
        meta["image_base"] + section["rva"] <= VARIABLE_TARGET and
        VARIABLE_TARGET + 4 <= meta["image_base"] + section["rva"] + section["loaded_bytes"]
        for section in meta["pe"]["sections"]
    )
    if VARIABLE_TARGET & 3 or not in_writable_data:
        raise ValueError("g_XuiAutomation is not in a verified writable XAM data section")


def verify_variable_catalog(source):
    if not re.search(
            r"REX_EXPORT\(xam,\s*0x000003DB,\s*g_XuiAutomation,\s*kVariable\)",
            source):
        raise ValueError("SDK XAM catalog does not identify 03DB as g_XuiAutomation variable")

def corrected(source):
    if (NEW in source or source.count(OLD) != 1 or VARIABLE_NEW in source or
            source.count(VARIABLE_OLD) != 1):
        raise ValueError("unexpected or previously patched XEX loader")
    return source.replace(VARIABLE_OLD, VARIABLE_NEW, 1).replace(OLD, NEW, 1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    revision = subprocess.check_output(["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    verify_slots(rows(ROOT/"analysis/dash_17559/imports.tsv"),
                 rows(ROOT/"analysis/xam_17559/exports.tsv"))
    verify_variable_catalog((a.sdk/"src/kernel/xam/export_table.inc").read_text())
    path = a.sdk/"src/kernel/xex_module.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)

if __name__ == "__main__":
    main()
