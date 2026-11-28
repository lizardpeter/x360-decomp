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
    p.add_argument("--header-layout",type=Path,help="Write authored header/social geometry metadata (TSV)")
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
        command=[str(args.probe.resolve()),str(t/"schema"),str(t/"image"),str(t/"manifest")]
        if args.header_layout:command.append("--header-layout")
        result=subprocess.run(command,text=True,stdout=subprocess.PIPE)
        if result.returncode==2:raise RuntimeError("schema or probe failure")
        rows=result.stdout.splitlines()
        if not rows or not rows[-1].startswith("total="):raise RuntimeError("missing probe summary")
        print(rows[-1],flush=True)
        if args.header_layout:
            layout=rows[:-1]
            if not layout or not any(x.startswith("node\t") for x in layout):
                raise RuntimeError("no original scene nodes recovered")
            if not any(x.startswith("property\t") and ('"PointSize"' in x or '"TextScale"' in x) for x in layout):
                raise RuntimeError("no authored text geometry recovered")
            print("Header archive parsed:",any(x.startswith('node\t"epix"\t') for x in layout),flush=True)
            # The localization archive alone does not contain the skin.
            # Retain a receipt but do not mark the header investigation
            # complete if its actual visual scene was not decoded.
            skin=[x for x in layout if '\t"dashuisk"\t"skin.xur"\t' in x]
            print("Actual dashboard skin layout records:",len(skin),flush=True)
            twist=[x for x in skin if '"HubScene_Twist"' in x]
            print("Exact HubScene_Twist matches in dashboard skin:",len(twist),flush=True)
            args.header_layout.parent.mkdir(parents=True,exist_ok=True)
            args.header_layout.write_text("\n".join(layout)+"\n",encoding="utf-8")
            print(f"Authored layout records: {len(layout)}",flush=True)
            if args.strict and not skin:
                raise RuntimeError("actual dashuisk/skin.xur was not decoded")
            if args.strict and not twist:
                raise RuntimeError("actual HubScene_Twist visual was not found")
        counts=dict(x.split("=") for x in rows[-1].split())
        assert int(counts["total"])==363
        assert int(counts["parsed"])>0
        if args.strict:assert result.returncode==0
        elif result.returncode:print("Incomplete scene support; failures remain explicit.")
if __name__=="__main__":main()
