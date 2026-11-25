#!/usr/bin/env python3
"""Audit candidate native virtual URI mounts against original dashboard references."""
import hashlib
import subprocess
import tempfile
import sys
from pathlib import Path
from verify_xui_resources import source
from decode_image import decode
from xex import parse

def main():
    probe=Path(sys.argv[1]).resolve()
    raw=source("dash_basic");image,info=decode(raw)
    assert info["sha256"]=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
    shared=source("shared_resources")
    manifest=[f"{r['id']} {int(r['address'],16)-info['image_base']} {r['bytes']}\n" for r in parse(raw)["resources"]]
    with tempfile.TemporaryDirectory() as directory:
        t=Path(directory);(t/"image.bin").write_bytes(image);(t/"manifest").write_text("".join(manifest));(t/"shared").write_bytes(shared)
        counts=list(map(int,subprocess.check_output([str(probe),str(t/"image.bin"),str(t/"manifest"),str(t/"shared")],text=True).split()))
    assert counts==[187,24,1,2,0,0],counts
    print("Original URI reference census: 214 references, 187 exact, 24 normalized, 1 missing, 2 unsupported")
if __name__=="__main__":main()
