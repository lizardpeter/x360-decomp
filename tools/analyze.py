#!/usr/bin/env python3
"""Generate reproducible XEX and PIRS inventories from exact original data."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile
from fetch_originals import ROOT, config, check, safe_key
import pirs
import xex

def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--originals", type=Path, default=ROOT / "originals")
    p.add_argument("--output", type=Path, default=ROOT / "analysis")
    a = p.parse_args()
    c = config()
    paths = {}
    for item in c["source"]:
        path = a.originals.joinpath(*safe_key(item["key"]).parts)
        check(path, item)
        paths[item["id"]] = path
    members = pirs.parse(paths["pirs"].read_bytes())
    if len(members) != 31:
        raise ValueError("unexpected original PIRS entry count")
    if members["$flash_dash.xex"]["sha256"] != hashlib.sha256(paths["dash"].read_bytes()).hexdigest():
        raise ValueError("PIRS dashboard mismatch")
    xam = next(b for b in c["build"] if b["id"] == "xam_17559")
    if members[xam["member"]]["sha256"] != xam["sha256"]:
        raise ValueError("PIRS XAM mismatch")
    write(a.output/"pirs_17559"/"members.json",
          {k:{f:v for f,v in m.items() if f!="payload"} for k,m in members.items()})
    for build in c["build"]:
        payload = members[build["member"]]["payload"] if "member" in build else paths[build["source"]].read_bytes()
        info = xex.parse(payload)
        info["sha256"] = hashlib.sha256(payload).hexdigest()
        write(a.output/build["id"]/"xex.json", info)
    for name,m in members.items():
        if name.lower().endswith(".xex"):
            info = xex.parse(m["payload"])
            info["sha256"] = m["sha256"]
            write(a.output/"pirs_17559"/"modules"/(name+".json"), info)
    # Catalog all archive member names, sizes and CRCs without extracting or running tools.
    for ident in ("system_update","jrunner","xebuild"):
        with zipfile.ZipFile(paths[ident]) as archive:
            write(a.output/"archives"/(ident+".json"),
                  [{"path":i.filename,"bytes":i.file_size,"crc32":f"{i.CRC:08X}"}
                   for i in archive.infolist() if not i.is_dir()])
    print(f"Verified {len(paths)} source objects and inventoried {len(members)} PIRS members.")

if __name__ == "__main__":
    main()
