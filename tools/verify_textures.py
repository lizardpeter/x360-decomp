#!/usr/bin/env python3
"""Compare native original PNG pixels with independently measured reference hashes."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_xui_resources import source
from pirs import parse as parse_pirs
from xex import parse
from decode_image import decode

def audit(probe,ident,image,manifest,expected):
    with tempfile.TemporaryDirectory() as d:
        temp=Path(d);binary=temp/"image.bin";index=temp/"manifest.tsv";pixels=temp/"rgba.bin"
        binary.write_bytes(image);index.write_text("".join(manifest))
        output=subprocess.check_output([str(probe.resolve()),str(binary),str(index),str(pixels)],text=True)
        images,count=map(int,output.split())
        data=pixels.read_bytes()
        assert len(data)==count*4
        actual=dict(images=images,pixels=count,rgba_sha256=hashlib.sha256(data).hexdigest())
        assert actual==expected,(ident,actual,expected)
        print(f"{ident}: {images} original PNGs, {count} pixels, exact RGBA digest match",flush=True)
        return images,count

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path);p.add_argument("--lzx",required=True,type=Path);a=p.parse_args()
    reference=json.loads((ROOT/"analysis/xui/texture-reference.json").read_text())["modules"]
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    sources=parse_pirs(source("pirs"))
    empty=dict(images=0,pixels=0,rgba_sha256=hashlib.sha256(b"").hexdigest())
    images=pixels=0;seen=set()
    for name,record in sources.items():
        if not name.endswith(".xex"):continue
        ident=name.removeprefix("$flash_").removeprefix("$install_").removesuffix(".xex")+"_17559"
        raw=record["payload"];meta=parse(raw)
        if meta.get("encryption"):continue
        image,info=decode(raw,a.lzx.resolve())
        assert info["sha256"]==summary[ident]["sha256"]
        manifest=[f"{r['id']} {int(r['address'],16)-info['image_base']} {r['bytes']}\n" for r in meta["resources"]]
        n,p=audit(a.probe,ident,image,manifest,reference.get(ident,empty));images+=n;pixels+=p
        if n:seen.add(ident)
    shared=source("shared_resources")
    n,p=audit(a.probe,"sharedres",shared,[f"sharedres 0 {len(shared)}\n"],reference["sharedres"]);images+=n;pixels+=p;seen.add("sharedres")
    assert seen==set(reference) and (images,pixels)==(930,5844455)
    print(f"Exact independent RGBA reference match: {images} PNGs, {pixels} pixels")
if __name__=="__main__":main()
