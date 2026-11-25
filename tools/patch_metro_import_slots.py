#!/usr/bin/env python3
"""Patch five verified Metro function import value slots during XEX loading.

The codegen forwards these same five thunks to the real recompiled XAM
exports. The loader must likewise point the function-pointer slots at the
original thunks rather than leaving their raw ordinal markers in memory.
"""
import argparse
import subprocess
from pathlib import Path
from prepare_recompilation import ROOT
from patch_rexglue_imports import REVISION
from stage_metro_xam_aot import BINDINGS, rows, verify_bindings

VALUE_SLOTS = {
    0x0546: 0x92000BC4,
    0x0547: 0x92000BCC,
    0x0548: 0x92000BC8,
    0x0549: 0x92000BD0,
    0x054B: 0x920005D0,
}
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

def corrected(source):
    if NEW in source or source.count(OLD) != 1:
        raise ValueError("unexpected or previously patched XEX loader")
    return source.replace(OLD, NEW, 1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    revision = subprocess.check_output(["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    verify_slots(rows(ROOT/"analysis/dash_17559/imports.tsv"),
                 rows(ROOT/"analysis/xam_17559/exports.tsv"))
    path = a.sdk/"src/kernel/xex_module.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)

if __name__ == "__main__":
    main()
