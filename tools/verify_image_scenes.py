#!/usr/bin/env python3
"""Render the supported original scenes; compare with independent diagnostic pixel hashes."""
import argparse
import hashlib
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path
from verify_xui_resources import source
from decode_image import decode
from xex import parse

EXPECTED={
 ("dvd","DvdSplash169.xur"):(720,480,"5dd6f607c39cc33f4e275bf90abc41f43c5ae1a62f65361e794e41c81690f6c0"),
 ("dvd","DvdSplash43.xur"):(720,480,"ed5c22a854d382458152edabd48a68968dd1c9d20bc6d503488c782da7a04812"),
 ("consoles","metaPane_DisplayNormal.xur"):(420,450,"aceaa14fcf4005d733a1d5d71c4c0b49554acbb3983ccb0fb34f0855bcdf5864"),
 ("consoles","metaPane_DisplayWidescreen.xur"):(420,450,"f3dbba2cdb809e8fde218d84ae27c1f77af1250376b0b3702a98c7b07b8d6843"),
}

def save_png(path,w,h,rgba):
    def chunk(tag,payload):
        return struct.pack(">I",len(payload))+tag+payload+struct.pack(">I",zlib.crc32(tag+payload))
    scanlines=b"".join(b"\0"+rgba[y*w*4:(y+1)*w*4] for y in range(h))
    path.write_bytes(b"\x89PNG\r\n\x1a\n"+chunk(b"IHDR",struct.pack(">IIBBBBB",w,h,8,6,0,0,0))+chunk(b"IDAT",zlib.compress(scanlines))+chunk(b"IEND",b""))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path);p.add_argument("--preview-dir",type=Path,help="write local diagnostic PNGs after verification")
    args=p.parse_args()
    raw=source("dash_basic");image,info=decode(raw)
    assert info["sha256"]=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
    shared=source("shared_resources")
    manifest=[f"{r['id']} {int(r['address'],16)-info['image_base']} {r['bytes']}\n" for r in parse(raw)["resources"]]
    with tempfile.TemporaryDirectory() as d:
        t=Path(d);(t/"image").write_bytes(image);(t/"manifest").write_text("".join(manifest));(t/"shared").write_bytes(shared)
        output=subprocess.check_output([str(args.probe.resolve()),str(t/"image"),str(t/"manifest"),str(t/"shared"),str(t)],text=True)
        seen=set();previews=[]
        for line in output.splitlines():
            index,archive,name,w,h=line.split("\t")
            key=(archive,name);w,h=int(w),int(h)
            assert key not in seen and key in EXPECTED
            rgba=(t/f"scene_{int(index)}.rgba").read_bytes()
            assert len(rgba)==w*h*4 and (w,h,hashlib.sha256(rgba).hexdigest())==EXPECTED[key]
            seen.add(key);previews.append((name,w,h,rgba))
        assert seen==set(EXPECTED),seen
        if args.preview_dir:
            args.preview_dir.mkdir(parents=True,exist_ok=True)
            for name,w,h,rgba in previews:save_png(args.preview_dir/(Path(name).stem+".png"),w,h,rgba)
    print("4 original image scenes rendered; 1,069,200 canvas pixels match independent diagnostic raster hashes")

if __name__=="__main__":main()
