#!/usr/bin/env python3
"""Audit the native scene graph against digest-verified original resources."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_xui_resources import source
from compile_xui_schema import compile_schema
from decode_image import decode
from xex import parse

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path)
    p.add_argument("schema_root",type=Path)
    p.add_argument("--strict",action="store_true")
    args=p.parse_args()
    raw=source("dash_basic")
    image,info=decode(raw)
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    assert info["sha256"]==summary["dash_17559"]["sha256"]
    catalog=json.loads((ROOT/"analysis/dash_17559/resource_hashes.json").read_text())
    hashes={r["id"]:r["sha256"] for r in catalog}
    manifest=[]
    for r in parse(raw)["resources"]:
        off=int(r["address"],16)-info["image_base"]
        size=r["bytes"]
        assert 0<=off<=len(image)-size
        assert hashlib.sha256(image[off:off+size]).hexdigest()==hashes[r["id"]]
        manifest.append(f"{r['id']} {off} {size}\n")
    with tempfile.TemporaryDirectory() as tmp:
        t=Path(tmp)
        (t/"image").write_bytes(image)
        (t/"manifest").write_text("".join(manifest))
        (t/"schema").write_text(compile_schema(args.schema_root),encoding="utf-8")
        result=subprocess.run([str(args.probe.resolve()),str(t/"schema"),str(t/"image"),str(t/"manifest")],text=True,stdout=subprocess.PIPE)
        print(result.stdout,flush=True)
        if result.returncode==2:raise RuntimeError("schema or probe failure")
        counts=dict(x.split("=") for x in result.stdout.split())
        assert int(counts["total"])==363
        assert int(counts["parsed"])>0
        if args.strict:assert result.returncode==0
        elif result.returncode:print("Incomplete scene support; failures remain explicit.")
if __name__=="__main__":main()
