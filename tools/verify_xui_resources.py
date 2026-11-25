#!/usr/bin/env python3
"""Exercise the native XUI parser on verified original firmware resource tables."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from fetch_originals import ROOT, config, check, safe_key
from decode_image import decode
from pirs import parse as parse_pirs
from xex import parse

def source(source_id):
    item=next(s for s in config()["source"] if s["id"]==source_id)
    path=ROOT/"originals"/safe_key(item["key"])
    check(path,item)
    return path.read_bytes()

def audit(probe,ident,raw,image,info,expected):
    catalog=json.loads((ROOT/"analysis"/ident/"resource_hashes.json").read_text())
    by_id={r["id"]:r for r in catalog}
    resources=parse(raw)["resources"]
    assert len(resources)==len(by_id)==expected["resource_count"]
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
        output=subprocess.check_output([str(probe.resolve()),str(temp/"image.bin"),str(temp/"manifest.tsv")],text=True)
    counts=dict((k,int(v)) for k,v in (token.split("=") for token in output.split()))
    points=counts.pop("path_points")
    assert points>=counts["shapes"]
    assert counts=={k:v for k,v in expected.items() if k!="resource_count"},(ident,counts,expected)
    print(f"{ident}: {len(resources)} resource digests and native XUI inventory verified: {output.strip()}",flush=True)
    return points

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path)
    p.add_argument("--system",action="store_true")
    p.add_argument("--lzx",type=Path)
    args=p.parse_args()
    expected=json.loads((ROOT/"analysis/xui/system-census.json").read_text())
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    if args.system:
        if not args.lzx:p.error("--system requires --lzx")
        originals=parse_pirs(source("pirs"))
        inputs={name.removeprefix("$flash_").removeprefix("$install_").removesuffix(".xex")+"_17559":m["payload"]
                for name,m in originals.items() if name.endswith(".xex")}
        assert set(inputs)==set(expected)|{"mfgbootlauncher_17559","extender_17559"}
        total=0
        for ident,raw in sorted(inputs.items()):
            if ident not in expected:
                assert parse(raw).get("encryption") and summary[ident]["state"]=="unsupported-encrypted"
                print(ident+": encrypted, explicitly excluded")
                continue
            image,info=decode(raw,args.lzx.resolve())
            assert info["sha256"]==summary[ident]["sha256"]
            total+=audit(args.probe,ident,raw,image,info,expected[ident])
        print(f"All {len(expected)} decoded original modules audited; {total} contour points generated")
    else:
        raw=source("dash_basic")
        image,info=decode(raw)
        assert info["sha256"]==summary["dash_17559"]["sha256"]
        audit(args.probe,"dash_17559",raw,image,info,expected["dash_17559"])

if __name__=="__main__":main()
