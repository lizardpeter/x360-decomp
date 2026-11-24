#!/usr/bin/env python3
"""Prepare a verified loaded image and Ghidra seed manifest, without modifying it."""
import argparse
import csv
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("module")
    p.add_argument("--analysis",type=Path,default=Path("analysis"))
    p.add_argument("--images",type=Path,default=Path("originals/decoded"))
    p.add_argument("--output",type=Path,default=Path("build/ghidra"))
    a=p.parse_args()
    ident=a.module
    if not ident.replace("_","").isalnum(): raise ValueError("invalid module")
    source=a.analysis/ident
    meta=json.loads((source/"decoded.json").read_text())
    if meta["state"]!="verified" or not meta["pe"]: raise ValueError("no verified executable image")
    image=a.images/(ident+".image.bin")
    if hashlib.sha256(image.read_bytes()).hexdigest()!=meta["sha256"]: raise ValueError("decoded image hash mismatch")
    out=a.output/ident; out.mkdir(parents=True,exist_ok=True)
    base=meta["image_base"]
    rows=["BASE\t%08X\t%d"%(base,meta["image_bytes"])]
    for s in meta["pe"]["sections"]:
        if s["loaded_bytes"]:
            rows.append("SECTION\t%08X\t%d\t%08X\t%s"%(base+s["rva"],s["loaded_bytes"],s["flags"],s["name"]))
    rows.append("ENTRY\t%08X"%meta["pe"]["entry_point"])
    with (source/"functions.tsv").open() as f:
        seeds=list(csv.DictReader(f,delimiter="\t"))
    if len(seeds)!=meta["pdata_functions"]: raise ValueError("function inventory count mismatch")
    for r in seeds: rows.append("FUNCTION\t%s\t%s"%(r["address"],r["size"]))
    with (source/"imports.tsv").open() as f:
        for r in csv.DictReader(f,delimiter="\t"):
            lib=r["library"].split(".")[0]
            for kind,key in (("VALUE","value_slots"),("THUNK","thunk_slots")):
                for address in filter(None,r[key].split(",")):
                    rows.append(f"{kind}\t{address}\t{lib}_{r['ordinal']}_{address}")
    if (source/"exports.tsv").exists():
        with (source/"exports.tsv").open() as f:
            for r in csv.DictReader(f,delimiter="\t"):
                rows.append(f"EXPORT\t{r['address']}\tordinal_{r['ordinal']}")
    (out/"seeds.tsv").write_text("\n".join(rows)+"\n")
    (out/"base.txt").write_text(f"0x{base:08X}\n")
    print(f"{ident}: {len(seeds)} original exception-table seeds, image {meta['sha256']}")
if __name__=="__main__":
    main()
