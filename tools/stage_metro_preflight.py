#!/usr/bin/env python3
"""Add the load-only Metro runtime preflight to an already staged AOT pair."""
import argparse
import json
from pathlib import Path
from prepare_recompilation import ROOT, EXPECTED, sha
from stage_aot_host import write_exact
from stage_metro_xam_aot import BINDINGS, rows, verify_bindings, manifest

OLD = "add_executable(dash_17559 src/main.cpp)"
NEW = "add_executable(dash_17559 src/metro_aot_preflight.cpp)"

def image_identity(meta, module):
    if meta["source_sha256"] != EXPECTED[module] or meta["state"] != "verified":
        raise ValueError(f"unverified metadata for {module}")
    base, size = meta["image_base"], meta["image_bytes"]
    entry = meta["pe"]["entry_point"]
    if not (base <= entry < base + size <= 1 << 32):
        raise ValueError(f"invalid image extent for {module}")
    return base, size, entry

def executable(meta, address):
    return address % 4 == 0 and any(
        s["flags"] & 0x20000000 and
        meta["image_base"] + s["rva"] <= address and
        address + 4 <= meta["image_base"] + s["rva"] + s["loaded_bytes"]
        for s in meta["pe"]["sections"]
    )

def header(dash, xam):
    d = image_identity(dash, "dash_17559")
    x = image_identity(xam, "xam_17559")
    for meta, (_, _, entry) in ((dash, d), (xam, x)):
        if not executable(meta, entry):
            raise ValueError("entry is not executable")
    if d[0] < x[0] + x[1] and x[0] < d[0] + d[1]:
        raise ValueError("dashboard and XAM image extents overlap")
    for ordinal, (thunk, target) in BINDINGS.items():
        if not executable(dash, thunk) or not executable(xam, target):
            raise ValueError(f"invalid executable binding {ordinal:04X}")
    result = "#pragma once\n#include <cstdint>\n"
    for name, values in (("Dash", d), ("Xam", x)):
        for field, value in zip(("Base", "Size", "Entry"), values):
            result += f"inline constexpr std::uint32_t k{name}{field} = 0x{value:08X}u;\n"
    result += "struct Binding {std::uint16_t ordinal; std::uint32_t thunk, target;};\n"
    result += "inline constexpr Binding kBindings[] = {\n"
    result += "".join(f"    {{0x{o:04X}u, 0x{a:08X}u, 0x{b:08X}u}},\n"
                      for o, (a, b) in sorted(BINDINGS.items()))
    return result + "};\n"

def cmake_preflight(text):
    if text.count(NEW) == 1 and OLD not in text:
        return text
    if text.count(OLD) != 1 or NEW in text:
        raise ValueError("unexpected host CMake scaffold")
    return text.replace(OLD, NEW, 1)

def stage(folder):
    if (folder/"dash_17559_manifest.toml").read_text() != manifest():
        raise ValueError("expected exact paired manifest")
    for name, module in (("dash.xex", "dash_17559"), ("xam.xex", "xam_17559")):
        if sha((folder/"inputs"/name).read_bytes()) != EXPECTED[module]:
            raise ValueError(f"staged {name} identity mismatch")
    verify_bindings(rows(ROOT/"analysis/dash_17559/imports.tsv"), rows(ROOT/"analysis/xam_17559/exports.tsv"))
    dash, xam = (json.loads((ROOT/"analysis"/module/"decoded.json").read_text())
                 for module in ("dash_17559", "xam_17559"))
    bindings = header(dash, xam)
    cmake = folder/"CMakeLists.txt"
    updated = cmake_preflight(cmake.read_text())
    write_exact(folder/"src/metro_preflight_bindings.hpp", bindings)
    write_exact(folder/"src/metro_aot_preflight.cpp",
                (ROOT/"tools/native/metro_aot_preflight.cpp").read_text())
    write_exact(folder/"src/metro_aot_boot.hpp",
                (ROOT/"tools/native/metro_aot_boot.hpp").read_text())
    cmake.write_text(updated)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder", type=Path)
    a = p.parse_args()
    folder = a.folder.resolve()
    if not folder.is_relative_to((ROOT/"build").resolve()):
        p.error("preflight must stay under ignored build/")
    stage(folder)
    print("Staged load-only native Metro preflight with five verified export mappings")

if __name__ == "__main__":
    main()
