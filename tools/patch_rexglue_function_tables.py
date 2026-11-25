#!/usr/bin/env python3
"""Fix pinned SDK function-table heap selection for XEX images at 0x90000000."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

ALLOC = """  if (!heaps_.v80000000.AllocFixed(
          table_base, table_size, 0x10000,"""
FIXED_ALLOC = """  // XEX images may live in either virtual XEX heap. The Metro dashboard
  // is in the 4 KiB page heap (0x90000000), not the 64 KiB heap.
  auto* table_heap = LookupHeap(table_base);
  const u64 table_end = static_cast<u64>(table_base) + table_size;
  if (!table_heap || table_base < 0x80000000 || table_base >= 0xA0000000 ||
      table_size == 0 || table_end > 0xA0000000 ||
      LookupHeap(static_cast<u32>(table_end - 1)) != table_heap) {
    REXSYS_FAIL(false, "Function table outside a single XEX heap at {:08X}", table_base);
  }
  if (!table_heap->AllocFixed(
          table_base, table_size, table_heap->GetPageSize(),"""
RELEASE = "  heaps_.v80000000.Release(table_base);"
FIXED_RELEASE = """  auto* table_heap = LookupHeap(table_base);
  if (!table_heap || table_base < 0x80000000 || table_base >= 0xA0000000) {
    REXSYS_FAIL(false, "Function table release outside XEX heap at {:08X}", table_base);
  }
  table_heap->Release(table_base);"""

def corrected(source):
    if any(source.count(old) != 1 for old in (ALLOC, RELEASE)):
        raise ValueError("unexpected or previously patched function-table implementation")
    if FIXED_ALLOC in source or FIXED_RELEASE in source:
        raise ValueError("already patched function-table implementation")
    return source.replace(ALLOC, FIXED_ALLOC, 1).replace(RELEASE, FIXED_RELEASE, 1)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk", type=Path)
    a = p.parse_args()
    revision = subprocess.check_output(["git", "-C", str(a.sdk), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION:
        raise ValueError("unexpected SDK revision")
    path = a.sdk/"src/kernel/memory.cpp"
    path.write_text(corrected(path.read_text()))
    subprocess.run(["git", "-C", str(a.sdk), "diff", "--check"], check=True)
    print("Corrected function-table allocation/release for both XEX guest heaps")

if __name__ == "__main__":
    main()
