#!/usr/bin/env python3
"""Tag generated source lines with the original PPC instruction PC.

This changes generated comments only, not executable guest semantics.
The line-table symbolizer uses the comments locally and emits addresses,
never source lines or original instructions.
"""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

OLD = '        Disassemble(data, 4, block_base, insn);'
NEW = OLD + '\n        EmitPrintln(body, "\\t// METRO_GUEST_PC {:08X}", block_base);'

def corrected(source):
    if source.count(OLD)!=1 or NEW in source:
        raise ValueError("unexpected codegen instruction marker anchor")
    return source.replace(OLD,NEW,1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    path=a.sdk/"src/codegen/function_graph.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
