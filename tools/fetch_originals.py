#!/usr/bin/env python3
"""Retrieve only the pinned original objects, never execute them."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import tomllib
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def config():
    return tomllib.loads((ROOT / "target.toml").read_text(encoding="utf-8"))

def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def check(path, item):
    if path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
        raise ValueError(f"source verification failed: {item['id']}")

def safe_key(key):
    p = PurePosixPath(key)
    if p.is_absolute() or "\\" in key or any(x in ("", ".", "..") for x in key.split("/")):
        raise ValueError("unsafe source key")
    return p

def acquire(item, output, origin, archive=None):
    key = item["key"]
    dest = output.joinpath(*safe_key(key).parts)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        check(dest, item)
        return dest
    with tempfile.NamedTemporaryFile(dir=dest.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            if archive is not None:
                matches = [n for n in archive.namelist() if n == key or n == "handoff/" + key]
                if len(matches) != 1:
                    raise ValueError(f"expected exactly one artifact member for {key}")
                if archive.getinfo(matches[0]).file_size != item["bytes"]:
                    raise ValueError("artifact member size mismatch")
                with archive.open(matches[0]) as src:
                    shutil.copyfileobj(src, f)
            else:
                url = origin.rstrip("/") + "/" + quote(key, safe="/")
                with urlopen(Request(url, headers={"User-Agent": "x360-decomp/1.0"}), timeout=120) as src:
                    shutil.copyfileobj(src, f)
            f.flush()
            check(tmp, item)
            f.close()
            tmp.replace(dest)
        finally:
            tmp.unlink(missing_ok=True)
    return dest

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, default=ROOT / "originals")
    p.add_argument("--artifact", type=Path)
    p.add_argument("--only", action="append", help="source id; repeat as needed")
    a = p.parse_args()
    c = config()
    ids = {i["id"] for i in c["source"]}
    if a.only and set(a.only) - ids:
        p.error("unknown source id")
    archive = zipfile.ZipFile(a.artifact) if a.artifact else None
    try:
        for item in c["source"]:
            if not a.only or item["id"] in a.only:
                path = acquire(item, a.output, c["r2_public"], archive)
                print(f"verified {item['id']}: {path}")
    finally:
        if archive:
            archive.close()

if __name__ == "__main__":
    main()
