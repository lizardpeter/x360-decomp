#!/usr/bin/env python3
"""Read original staged files only through guest NT file services and compare digests."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(1024*1024), b""):
            h.update(data)
    return h.hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path)
    p.add_argument("root",type=Path)
    p.add_argument("receipt",type=Path)
    a=p.parse_args()
    receipt=json.loads(a.receipt.read_text())
    verified=[]
    with tempfile.TemporaryDirectory() as tmp:
        output=Path(tmp)/"resource"
        for file in receipt["files"]:
            name=file["path"]
            original=a.root/name
            assert original.stat().st_size==file["bytes"] and digest(original)==file["sha256"]
            # The original name is deliberately varied in case to exercise
            # guest-volume lookup rather than the host's path case rules.
            result=subprocess.check_output([str(a.probe.resolve()),str(a.root.resolve()),
                "flash:/"+name.upper(),str(output)],text=True)
            assert int(result.strip())==file["bytes"]
            assert output.stat().st_size==file["bytes"] and digest(output)==file["sha256"],name
            verified.append(name)
    print(f"NT file-provider verification: {len(verified)} original staged files, "
          f"{sum(f['bytes'] for f in receipt['files']):,} bytes, exact SHA-256 matches")

if __name__=="__main__":
    main()
