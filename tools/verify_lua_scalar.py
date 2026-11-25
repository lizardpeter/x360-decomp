#!/usr/bin/env python3
"""Compare bounded native execution of original isolated scalar Lua functions."""
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path
from verify_xui_resources import source
from decode_image import decode
from xex import parse
def main():
    raw=source("dash_basic");image,info=decode(raw)
    assert info["sha256"]=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
    manifest=[f"{r['id']} {int(r['address'],16)-info['image_base']} {r['bytes']}\n" for r in parse(raw)["resources"]]
    with tempfile.TemporaryDirectory() as d:
        t=Path(d);(t/"image").write_bytes(image);(t/"manifest").write_text("".join(manifest))
        counts=list(map(int,subprocess.check_output([str(Path(sys.argv[1]).resolve()),str(t/"image"),str(t/"manifest"),str(t/"results")],text=True).split()))
        digest=hashlib.sha256((t/"results").read_bytes()).hexdigest()
    assert counts==[61,1114,106],counts
    assert digest=="b047badef92841385c63c943781819f652a3f12b8b8435981da5cfa004bbf199",digest
    print("Original scalar Lua execution: 61 prototypes, 1,220 cases, 1,114 returns and 106 explicit type rejections; independent Python reference digest matched")
if __name__=="__main__":main()
