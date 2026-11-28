#!/usr/bin/env python3
"""Correct the pinned PPC scalar FPSCR field mask and host rounding update."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1:raise ValueError("scalar codegen anchor: "+old[:100])
    return source.replace(old,new,1)

def patch(sdk,tests):
    system=sdk/"src/codegen/builder/system.cpp"
    context=sdk/"include/rex/ppc/context.h"
    codegen=sdk/"tests/unit/codegen/flush_mode_test.cpp"
    runtime=sdk/"tests/unit/ppc/fpscr_flush_test.cpp"
    s=system.read_text()
    # PPC field 0 is the high-order nibble. The numeric FLM bit 0
    # selects field 7 (rounding), not field 0.
    s=replace(s,"""  for (int j = 0; j < 8; j++) {
    if (fm & (1 << (7 - j)))
      mask |= 0xF << (4 * j);
  }""","""  for (u32 j=0;j<8;++j) {
    if (fm & (1u << j))
      mask |= 0xFu << (4*j);
  }""")
    c=replace(context.read_text(),"  void StoreToHost(u32 value) noexcept {\n    csr &= ~kRoundMaskVal;",
        """  void StoreToHost(u32 value) noexcept {
    // The cached value belongs to the guest context, but host calls can
    // update FP status between guest instructions. Change rounding only.
    csr=GetCSR();
    csr &= ~kRoundMaskVal;""")
    t=codegen.read_text()
    u=runtime.read_text()
    if "metro_scalar_codegen" in t or "metro_scalar_codegen" in u:raise ValueError("already patched")
    system.write_text(s)
    context.write_text(c)
    # Split the file at a single explicit marker, so the native tests use
    # the existing SDK test helpers in their own translation units.
    a,b=tests.read_text().split("// METRO_SCALAR_RUNTIME_TESTS\n")
    codegen.write_text(t+"\n"+a)
    runtime.write_text(u+"\n"+b)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    patch(a.sdk,a.tests)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
