#!/usr/bin/env python3
"""Rebase PE/XEX PDATA BeginAddress RVAs to absolute Xenon guest addresses."""
import argparse
import subprocess
from pathlib import Path

REVISION = "a3e1d82678ca20d68d4837a8e9ee4652ff073745"
OLD = "    const u32 begin_addr = entries[i].begin;"
NEW = "    const u32 begin_addr = binary.GetBaseAddress() + entries[i].begin;"

def corrected(source):
    if source.count(OLD) != 1:
        raise ValueError("unexpected or previously patched PDATA begin-address reader")
    if NEW in source:
        raise ValueError("PDATA RVA rebasing already applied")
    if "u32 pdata_addr = binary.GetExceptionDirectoryAddress();" not in source:
        raise ValueError("expected absolute PDATA directory lookup is missing")
    return source.replace(OLD, NEW, 1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    revision = subprocess.check_output(
        ["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True
    ).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    path = a.sdk / "src/codegen/phase_register.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)
    print("Rebased PE PDATA BeginAddress RVAs using the loaded guest image base")

if __name__ == "__main__":
    main()
