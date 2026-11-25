#!/usr/bin/env python3
"""Exercise the native XUI parser on every embedded original dashboard archive."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from fetch_originals import ROOT, config, check, safe_key
from decode_image import decode
from xex import parse

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path)
    args=p.parse_args()
    source=next(s for s in config()["source"] if s["id"]=="dash_basic")
    path=ROOT/"originals"/safe_key(source["key"])
    check(path,source)
    raw=path.read_bytes()
    image,info=decode(raw)
    assert info["sha256"]=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
    catalog=json.loads((ROOT/"analysis/dash_17559/resource_hashes.json").read_text())
    by_id={r["id"]:r for r in catalog}
    resources=parse(raw)["resources"]
    assert len(resources)==len(by_id)==36
    manifest=[]
    for r in resources:
        offset=int(r["address"],16)-info["image_base"]
        size=r["bytes"]
        assert 0<=offset<=len(image)-size
        data=image[offset:offset+size]
        assert hashlib.sha256(data).hexdigest()==by_id[r["id"]]["sha256"]
        manifest.append(f"{r['id']} {offset} {size}\n")
    with tempfile.TemporaryDirectory() as tmp:
        temp=Path(tmp)
        (temp/"image.bin").write_bytes(image)
        (temp/"manifest.tsv").write_text("".join(manifest))
        output=subprocess.check_output([str(args.probe.resolve()),str(temp/"image.bin"),str(temp/"manifest.tsv")],text=True)
    counts=dict((k,int(v)) for k,v in (token.split("=") for token in output.split()))
    expected=dict(archives=35,members=5035,scenes=363,sections=2034,scene_strings=13155,localizations=3824,localized_strings=46598,duplicates=1,unicode_delta=2)
    assert counts==expected,(counts,expected)
    print("All 36 resource SHA-256 digests and complete native XUI inventory verified:",output.strip())

if __name__=="__main__":main()
