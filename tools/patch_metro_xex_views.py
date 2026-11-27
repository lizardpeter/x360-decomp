#!/usr/bin/env python3
"""Separate independently allocated XEX heap backing views in the pinned native host."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

OLD = "    {\n        0x90000000,\n        0x9FFFFFFF,\n        0x0000000080000000ull,\n    },"
NEW = "    {\n        0x90000000,\n        0x9FFFFFFF,\n        // Independently allocated XEX heaps must not share backing bytes.\n        // In particular native dispatch tables in the 64 KiB heap cannot\n        // overwrite loaded images in the 4 KiB heap.\n        0x0000000090000000ull,\n    },"

def corrected(source):
    if source.count(OLD)!=1 or NEW in source:
        raise ValueError("unexpected XEX backing view")
    if "0x120000000ull" not in source:
        raise ValueError("backing mapping extent must cover the independent view")
    return source.replace(OLD,NEW,1)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    path=a.sdk/"src/kernel/memory.cpp"
    test=a.sdk/"tests/unit/kernel/function_dispatcher_test.cpp"
    source=corrected(path.read_text())
    original=test.read_text()
    if "metro_xex_isolation" in original:raise ValueError("regression already staged")
    path.write_text(source)
    test.write_text(original+"\n"+a.tests.read_text())
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
