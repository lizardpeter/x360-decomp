#!/usr/bin/env python3
"""Read-only probes at verified original XAM heap/initialization instructions.

The compiler still executes the original instructions. Instrumentation adds
diagnostics only, in ignored generated source, never in original images.
"""
import argparse
import collections
import json
import re
from pathlib import Path

# Pre-instruction observations. At after-call PCs r3 is the genuine return
# register, and at entry PCs r3..r8 are ABI arguments, not local temporaries.
PROBES = {
    0x816968BC: "heap_init_call",
    0x816968C0: "heap_init_return",
    0x816E6518: "heap_descriptor_enter",
    0x816E65A0: "backing_allocation_return",
    0x816E6600: "heap_create_boolean",
    0x816E6218: "heap_create_enter",
    0x816E6264: "heap_protect_status",
    0x816E62C4: "heap_create_call",
    0x816E62C8: "heap_create_result",
    0x8171F270: "heap_process_type",
    0x8171F2E8: "heap_query_call",
    0x8171F2EC: "heap_query_status",
    0x8171F340: "heap_query_next_call",
    0x8171F344: "heap_query_next_status",
    0x8171F3A8: "heap_reserve_call",
    0x8171F3AC: "heap_reserve_status",
    0x8171F3F8: "heap_commit_call",
    0x8171F3FC: "heap_commit_status",
    0x816A17B8: "system_object_enter",
    0x816A17D0: "system_object_allocation",
    0x816A17E4: "system_object_constructor_result",
    0x816A17F8: "system_object_initialize_call",
    0x816A17FC: "system_object_initialize_result",
    0x816E6C9C: "heap_normalize_call",
    0x816E6CA0: "heap_normalize_result",
    0x816E6CB0: "heap_dispatch_call",
    0x816E6CB4: "heap_dispatch_status",
    0x816E63D8: "heap_dispatch_enter",
    0x816E5D58: "heap_allocation_enter",
    0x816E5D98: "heap_raw_allocation_result",
    0x816E5DB0: "heap_output_address",
    0x8169D060: "system_object_consumer",
}
REQUIRED = {0x816A17D0,0x816A17E4,0x816E6CB0,0x816E6CB4,0x816E5D58,0x8169D060}
MARKER = re.compile(r"^([ \t]*)// METRO_GUEST_PC ([0-9a-fA-F]{8})\s*$")
INSTRUMENTED = "// METRO_HEAP_TRACE_INSERTED"

def insert(source):
    if INSTRUMENTED in source:
        raise ValueError("source already instrumented")
    result=[]; hits=collections.Counter()
    for line in source.splitlines(keepends=True):
        result.append(line)
        m=MARKER.fullmatch(line.rstrip("\r\n"))
        if not m: continue
        pc=int(m[2],16)
        label=PROBES.get(pc)
        if label is None: continue
        hits[pc]+=1
        prefix=m[1]
        # r3..r8 are argument registers, shared across the original direct
        # calls, unlike the code generator's localized nonvolatile GPRs.
        # Use unsigned casts to avoid printf varargs type mismatches.
        result.append(prefix+f'if (std::getenv("X360_METRO_BOOT")) {{\n')
        result.append(prefix+'  static std::atomic<unsigned> metro_samples{0};\n')
        result.append(prefix+'  if (metro_samples.fetch_add(1, std::memory_order_relaxed) < 32) {\n')
        args=", ".join(f"static_cast<unsigned>(ctx.r{i}.u32)" for i in range(3,9))
        result.append(prefix+f'    std::fprintf(stderr, "METRO_HEAP pc={pc:08X} stage={label} r3=%08X r4=%08X r5=%08X r6=%08X r7=%08X r8=%08X\\n", {args});\n')
        result.append(prefix+'    std::fflush(stderr);\n'+prefix+'  }\n'+prefix+'}\n')
    if not hits: return source,hits
    return INSTRUMENTED+"\n#include <atomic>\n#include <cstdio>\n#include <cstdlib>\n"+"".join(result),hits

def instrument(directory):
    if directory.name!="generated_xam" or not directory.is_dir():
        raise ValueError("expected generated XAM directory")
    total=collections.Counter(); pending={}
    for path in sorted(directory.rglob("*.cpp")):
        if path.is_symlink(): raise ValueError("unexpected generated symlink")
        original=path.read_text()
        patched,hits=insert(original)
        if hits:
            pending[path]=patched
            total.update(hits)
    missing=REQUIRED-total.keys()
    if missing:
        raise ValueError("missing required original guest PC markers: "+
                         ", ".join(f"{pc:08X}" for pc in sorted(missing)))
    for path,patched in pending.items():path.write_text(patched)
    return {"scope":"read-only before-instruction observations, original instructions unchanged",
            "instrumented_translation_units":len(pending),
            "probes":[{"pc":f"{pc:08X}","stage":label,"occurrences":total[pc]}
                      for pc,label in PROBES.items()]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    if not a.directory.resolve().is_relative_to(root/"build"):
        p.error("instrument generated sources under ignored build/ only")
    result=instrument(a.directory)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print("Metro heap probes:",sum(r["occurrences"] for r in result["probes"]),
          "in",result["instrumented_translation_units"],"translation units")
if __name__=="__main__": main()
