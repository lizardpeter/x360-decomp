#!/usr/bin/env python3
"""Route the five verified Metro imports to actual recompiled XAM exports.

This is a compile/link trial, not an executable boot or security override.
The SDK's standard ModuleImport resolver fails explicitly if XAM is absent.
"""
import argparse
import csv
import re
import subprocess
from pathlib import Path
from prepare_recompilation import ROOT, EXPECTED, original, sha, manifest_text
from pirs import parse as parse_pirs
from stage_aot_host import stage, write_exact
from verify_aot_hints import verified_manifest
from patch_rexglue_imports import REVISION

# SDK linker diagnostics, joined to original dash import and XAM export tables.
HUD_SHA = "37e10612afde211e1d349838704f7cc2648ad5a4d1f8ca459f18ecd2c1f31ac7"

BINDINGS = {
    0x0546: (0x9293C8BC, 0x8168EB50),
    0x0547: (0x9293C89C, 0x8168EB88),
    0x0548: (0x9293C8AC, 0x8168EBC0),
    0x0549: (0x9293C88C, 0x8168EBF8),
    0x054B: (0x9293CE6C, 0x816DEF20),
}
OLD = """      } else if (resolved_name.empty()) {
        REXCG_ERROR("Cannot resolve ordinal {} from {}", ordinal, lib_name);"""
CONDITION = " ||\n             ".join(
    f"(ordinal == 0x{o:04X} && sym.address == 0x{a:08X})"
    for o, (a, _) in BINDINGS.items()
)
NEW = """      } else if (resolved_name.empty() && binary.GetBaseAddress() == 0x92000000 &&
                 lib_name == "xam" &&
             (""" + CONDITION + """)) {
        // Metro 17559: preserve verified retail XAM import bindings.
        // The ordinary module resolver is deliberately fatal if XAM is not loaded.
        resolved_name = std::format("sub_{:X}", sym.address);
        state.module_imports[sym.address] = {lib_name, ordinal};
        module_import_count++;
      } else if (resolved_name.empty()) {
        REXCG_ERROR("Cannot resolve ordinal {} from {}", ordinal, lib_name);"""

def rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))

def verify_bindings(imports, exports):
    for ordinal, (thunk, target) in BINDINGS.items():
        matches = [r for r in imports if r["library"] == "xam.xex"
                   and int(r["ordinal"], 16) == ordinal]
        if len(matches) != 1 or matches[0]["thunk_slots"] != f"{thunk:08X}":
            raise ValueError(f"unexpected dashboard thunk {ordinal:04X}")
        matches = [r for r in exports if int(r["ordinal"], 16) == ordinal]
        if len(matches) != 1 or int(matches[0]["address"], 16) != target:
            raise ValueError(f"unexpected XAM export {ordinal:04X}")

def verify_catalog(source):
    for ordinal in BINDINGS:
        if re.search(r"\b0x0*" + f"{ordinal:x}" + r"\b", source, re.I):
            raise ValueError(f"SDK now lists XAM ordinal {ordinal:04X}; re-evaluate patch")

def corrected(source):
    if NEW in source or source.count(OLD) != 1 or "state.module_imports[sym.address] = {lib_name, ordinal};" not in source:
        raise ValueError("unexpected SDK register phase; refusing to patch")
    return source.replace(OLD, NEW, 1)

def patch(sdk):
    revision = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    verify_bindings(rows(ROOT/"analysis/dash_17559/imports.tsv"), rows(ROOT/"analysis/xam_17559/exports.tsv"))
    verify_catalog((sdk/"src/kernel/xam/export_table.inc").read_text())
    path = sdk/"src/codegen/phase_register.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(sdk), "diff", "--check"], check=True)

def manifest():
    return manifest_text("dash_17559") + '''includes = ["verified-entries.toml"]

[[modules]]
project_name = "metro_xam"
file_path = "inputs/xam.xex"
guest_path = "xam.xex"
out_directory_path = "generated_xam"
is_dll = true

[[modules]]
project_name = "metro_hud"
file_path = "inputs/hud.xex"
guest_path = "hud.xex"
out_directory_path = "generated_hud"
is_dll = true
'''

def stage_pair(output):
    verify_bindings(rows(ROOT/"analysis/dash_17559/imports.tsv"), rows(ROOT/"analysis/xam_17559/exports.tsv"))
    xam = parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam) != EXPECTED["xam_17559"]:
        raise ValueError("XAM input mismatch")
    folder = output/"dash_17559"
    manifest_path = folder/"dash_17559_manifest.toml"
    if manifest_path.exists() and manifest_path.read_text() == manifest():
        if sha((folder/"inputs/dash.xex").read_bytes()) != EXPECTED["dash_17559"]:
            raise ValueError("dashboard input mismatch")
    else:
        stage("dash_17559", output)
    hints, _, _ = verified_manifest()
    write_exact(folder/"verified-entries.toml", hints)
    binary = folder/"inputs/xam.xex"
    if binary.exists():
        if sha(binary.read_bytes()) != EXPECTED["xam_17559"]:
            raise ValueError("staged XAM differs")
    else:
        binary.write_bytes(xam)
    hud = parse_pirs(original("pirs"))["$flash_hud.xex"]["payload"]
    if sha(hud) != HUD_SHA:
        raise ValueError("HUD input mismatch")
    binary = folder/"inputs/hud.xex"
    if binary.exists() and sha(binary.read_bytes()) != HUD_SHA:
        raise ValueError("staged HUD differs")
    if not binary.exists():
        binary.write_bytes(hud)
    manifest_path.write_text(manifest())

def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("patch").add_argument("sdk", type=Path)
    sub.add_parser("stage").add_argument("output", type=Path)
    a = p.parse_args()
    if a.action == "patch":
        patch(a.sdk)
    else:
        output = a.output.resolve()
        if not output.is_relative_to((ROOT/"build").resolve()):
            p.error("stage under ignored build/ only")
        stage_pair(output)

if __name__ == "__main__":
    main()
