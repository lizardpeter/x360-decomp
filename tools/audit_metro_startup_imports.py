#!/usr/bin/env python3
"""Evidence-only census of startup-reachable native imports; never executes guest code."""
import argparse
import csv
import json
import re
import subprocess
from collections import defaultdict, deque
from pathlib import Path

from prepare_recompilation import ROOT
from patch_rexglue_imports import REVISION

EXPORT = re.compile(r"REX_EXPORT\(\s*(\w+),\s*0x([0-9a-fA-F]+),\s*(\w+),\s*(kFunction|kVariable)\s*\)")
STUB = re.compile(r"REX_EXPORT_STUB\(__imp__(\w+)\)")
ENTRY = {"dash_17559": "92196610", "xam_17559": "81696AF0"}
LIBS = {"xam.xex": "xam", "xboxkrnl.exe": "xboxkrnl"}

def rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))

def startup_edges(edges, entry, max_depth=4):
    """Minimum statically known PDATA-call depth, not a dynamic execution trace."""
    if max_depth < 0 or max_depth > 32:
        raise ValueError("depth must be between 0 and 32")
    by_caller = defaultdict(list)
    for edge in edges:
        if edge["kind"] not in {"pdata", "import", "unclassified"}:
            raise ValueError("unrecognized edge classification")
        by_caller[edge["caller"]].append(edge)
    queue = deque([(entry, (entry,))])
    visited = {entry}
    imports = {}
    unresolved_targets = set()
    while queue:
        caller, path = queue.popleft()
        depth = len(path)-1
        for edge in by_caller[caller]:
            target = edge["target"]
            kind = edge["kind"]
            if kind == "import":
                key = (edge["library"], edge["ordinal"])
                imports.setdefault(key, {
                    "library": key[0], "ordinal": key[1], "thunk": target,
                    "depth": depth, "path": list(path),
                })
            elif kind == "unclassified":
                unresolved_targets.add(target)
            elif depth < max_depth and target not in visited:
                visited.add(target)
                queue.append((target, path+(target,)))
    return {
        "known_functions_visited": len(visited),
        "unclassified_direct_targets": sorted(unresolved_targets),
        "imports": list(imports.values()),
    }

def sdk_catalog(sdk):
    exports = {}
    explicit_stubs = set()
    for lib in sorted(set(LIBS.values())):
        directory = sdk/"src/kernel"/lib
        for m in EXPORT.finditer((directory/"export_table.inc").read_text()):
            name, ordinal, symbol, kind = m.groups()
            if name != lib:
                raise ValueError("export table library mismatch")
            exports[(lib, int(ordinal, 16))] = (symbol, kind)
        for path in sorted(directory.glob("*.cpp")):
            explicit_stubs.update((lib, name) for name in STUB.findall(path.read_text()))
    return exports, explicit_stubs

def classify(item, exports, stubs, xam_exports, pdata, executable):
    result = dict(item)
    lib = LIBS.get(item["library"])
    ordinal = int(item["ordinal"], 16)
    entry = exports.get((lib, ordinal))
    if entry:
        result["sdk_name"], result["sdk_type"] = entry
        result["sdk_status"] = ("explicit_stub" if (lib, entry[0]) in stubs
                                else "catalogued_not_explicit_stub")
    else:
        result["sdk_status"] = "not_catalogued"
    if lib == "xam" and ordinal in xam_exports:
        target = xam_exports[ordinal]
        result["retail_xam_target"] = target
        result["retail_pdata_entry"] = target in pdata
        result["retail_target_executable"] = executable(int(target, 16))
    return result

def audit(sdk, max_depth=4):
    revision = subprocess.check_output(["git", "-C", str(sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("audit requires the pinned SDK")
    exports, stubs = sdk_catalog(sdk)
    xam = ROOT/"analysis/xam_17559"
    targets = {int(row["ordinal"], 16): row["address"] for row in rows(xam/"exports.tsv")}
    pdata = {row["address"] for row in rows(xam/"functions.tsv")}
    meta = json.loads((xam/"decoded.json").read_text())
    def executable(address):
        return any((s["flags"] & 0x20000000) and
                   meta["image_base"]+s["rva"] <= address <
                   meta["image_base"]+s["rva"]+s["loaded_bytes"]
                   for s in meta["pe"]["sections"])
    result = {"sdk_revision": revision, "depth": max_depth,
              "dynamic_execution_verified": False, "modules": {}}
    for module, entry in ENTRY.items():
        census = startup_edges(rows(ROOT/"analysis"/module/"direct_call_edges.tsv"), entry, max_depth)
        census["imports"] = [classify(x, exports, stubs, targets, pdata, executable)
                             for x in census["imports"]]
        result["modules"][module] = census
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    p.add_argument("--depth", type=int, default=4)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):
        p.error("startup audit receipt must remain under ignored build/")
    result = audit(a.sdk, a.depth)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2)+"\n")
    for module, data in result["modules"].items():
        print(module, "known functions", data["known_functions_visited"],
              "distinct imports", len(data["imports"]),
              "explicit SDK stubs", sum(x["sdk_status"] == "explicit_stub" for x in data["imports"]))

if __name__ == "__main__":
    main()
