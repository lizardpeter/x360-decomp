#!/usr/bin/env python3
"""Apply a narrowly scoped record-walk correction to the pinned ReXGlue source."""
import argparse
import subprocess
from pathlib import Path

REVISION="a3e1d82678ca20d68d4837a8e9ee4652ff073745"
OLD="""  u32 offset = table_size + 12;
  for (u32 n = 0; n < table_count; ++n) {"""
NEW="""  u32 offset = table_size + 12;
  // The string count counts distinct names, not import records.
  // Retail dashboard 17559 uses two XAM records followed by xboxkrnl.
  while (offset < total) {"""

def corrected(source):
    if source.count(OLD)!=1:
        raise ValueError("unexpected import parser source; refusing to patch")
    if "if (size < kLibraryHeaderSize || u64{offset} + size > total ||" not in source or "offset += size;" not in source:
        raise ValueError("expected record bounds/progress guards missing")
    return source.replace(OLD,NEW,1)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("sdk",type=Path);a=p.parse_args()
    revision=subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()
    if revision!=REVISION:
        raise ValueError("unexpected SDK revision")
    path=a.sdk/"src/filesystem/xex.cpp"
    source=path.read_text()
    path.write_text(corrected(source))
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
    print("Patched bounded XEX import record walk on pinned SDK "+revision)
if __name__=="__main__":main()
