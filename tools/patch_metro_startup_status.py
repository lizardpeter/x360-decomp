#!/usr/bin/env python3
"""Implement the hosted startup status contracts without fabricated output."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

OLD="REX_EXPORT_STUB(__imp__EtxProducerRegister);"
NEW="REX_EXPORT_STUB_RETURN(__imp__EtxProducerRegister, rex::kernel::X_STATUS_NOT_SUPPORTED);"

def patch_status(source):
    if source.count(OLD)!=1 or NEW in source:
        raise ValueError("unexpected producer registration stub")
    return source.replace(OLD,NEW)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    source=a.sdk/"src/kernel/xboxkrnl/xboxkrnl_stub.cpp"
    tests=a.sdk/"tests/unit/kernel/xam_input_test.cpp"
    old=tests.read_text()
    if "metro_startup_status" in old:raise ValueError("tests already installed")
    replacements={
        source:patch_status(source.read_text()),
    }
    # Original XAM treats these as value-returning APIs, not NTSTATUS.
    # This hosted runtime has no persisted console raw dump or Argon
    # hardware-error record. Never populate unknown output layouts.
    for filename,symbol in (
        ("xboxkrnl_debug.cpp","DumpGetRawDumpInfo"),
        ("xboxkrnl_hal.cpp","HalGetNotedArgonErrors"),
    ):
        path=source.parent/filename
        original=path.read_text()
        anchor=f"REX_EXPORT_STUB(__imp__{symbol});"
        if original.count(anchor)!=1:raise ValueError(f"unexpected {symbol} stub")
        replacements[path]=original.replace(anchor,f"REX_EXPORT_STUB_RETURN(__imp__{symbol}, 0);")
    for path,updated in replacements.items():
        path.write_text(updated)
    tests.write_text(old+"\n"+a.tests.read_text())
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
