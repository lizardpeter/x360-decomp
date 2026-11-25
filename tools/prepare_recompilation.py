#!/usr/bin/env python3
"""Stage exact original inputs and minimal ReXGlue manifests for an AOT trial."""
import argparse
import hashlib
import json
import tomllib
from pathlib import Path
from fetch_originals import ROOT, config, check, safe_key
from pirs import parse as parse_pirs

SDK_VERSION = "0.11.0"
EXPECTED = {
    "dash_17559": "3ad8f38d070eaf63cadac0697e3e8802c565cbfd0825a485347c5d718014f927",
    "xam_17559": "78b3dbd8ae866f4258f5444205486ea9f8451afaa30f469c875dcf345f828467",
}

def original(ident):
    row = next(s for s in config()["source"] if s["id"] == ident)
    path = ROOT / "originals" / safe_key(row["key"])
    check(path, row)
    return path.read_bytes()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def manifest_text(module):
    if module not in EXPECTED:
        raise ValueError("unknown module")
    filename = "dash.xex" if module == "dash_17559" else "xam.xex"
    return (
        "# Minimal standalone code-generation trial, not a bootable project.\n"
        "[project]\n"
        f'name = "{module}"\n'
        f'sdk_version = "{SDK_VERSION}"\n'
        'game_root = "inputs"\n\n'
        "[entrypoint]\n"
        f'file_path = "inputs/{filename}"\n'
        'out_directory_path = "generated"\n'
    )

def prepare(destination, module, image):
    if module not in EXPECTED or sha(image) != EXPECTED[module]:
        raise ValueError("unverified AOT input")
    folder = destination / module
    folder.mkdir(parents=True, exist_ok=True)
    manifest = manifest_text(module)
    parsed = tomllib.loads(manifest)
    binary = folder / parsed["entrypoint"]["file_path"]
    binary.parent.mkdir(exist_ok=True)
    if binary.exists() and sha(binary.read_bytes()) != EXPECTED[module]:
        raise ValueError("existing staged original differs")
    if not binary.exists():
        binary.write_bytes(image)
    target = folder / f"{module}_manifest.toml"
    if target.exists() and target.read_text() != manifest:
        raise ValueError("existing manifest differs; use a fresh output directory")
    target.write_text(manifest)
    return {"module": module, "sha256": sha(image), "bytes": len(image), "manifest": target.name}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--module", choices=tuple(EXPECTED), required=True)
    p.add_argument("--output", type=Path, default=ROOT / "build" / "aot")
    a = p.parse_args()
    output = a.output.resolve()
    if not output.is_relative_to((ROOT / "build").resolve()):
        p.error("AOT originals and generated code must stay under ignored build/")
    image = original("dash") if a.module == "dash_17559" else parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    print(json.dumps(prepare(output, a.module, image), sort_keys=True))

if __name__ == "__main__":
    main()
