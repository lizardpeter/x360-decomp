#!/usr/bin/env python3
"""Remove invalid address-zero entries before the SDK's zero-address sentinel."""
import argparse
import json
import re
from pathlib import Path

DASH_REQUIRED = (0x92196610,)
XAM_REQUIRED = (
    0x81696AF0, 0x8168EB50, 0x8168EB88, 0x8168EBC0, 0x8168EBF8, 0x816DEF20,
)
TABLE = "const PPCFuncMapping kPPCFuncMappings[] = {"
ROW = re.compile(r"^(\s*)\{\s*(0x[0-9A-Fa-f]+|0)\s*,\s*([^}]+?)\s*\},?\s*$")

def filter_text(source, required=()):
    if source.count(TABLE) != 1:
        raise ValueError("expected exactly one generated PPCFuncMappings table")
    start = source.index(TABLE)
    end = source.find("\n};", start)
    if end < 0:
        raise ValueError("unterminated PPCFuncMappings table")
    prefix, body, suffix = source[:start], source[start:end], source[end:]
    lines = body.splitlines(keepends=True)
    rows = []
    for index, line in enumerate(lines):
        match = ROW.match(line.rstrip("\r\n"))
        if not match:
            continue
        token = match.group(2)
        address = int(token, 16) if token.lower().startswith("0x") else int(token)
        rows.append((index, address, match.group(3).strip()))
    if not rows:
        raise ValueError("generated mapping table contains no rows")
    sentinel_index, sentinel_address, sentinel_host = rows[-1]
    if sentinel_address != 0 or sentinel_host != "nullptr":
        raise ValueError("mapping table does not end with the expected {0, nullptr} sentinel")
    remove_indices = {index for index, address, _ in rows[:-1] if address == 0}
    removed = [host for index, address, host in rows[:-1] if address == 0]
    addresses = {address for index, address, _ in rows if address != 0}
    missing = [f"0x{x:08X}" for x in required if x not in addresses]
    if missing:
        raise ValueError("required guest function mappings missing: " + ", ".join(missing))
    if not addresses:
        raise ValueError("no valid nonzero function mappings remain")
    updated_body = "".join(line for index, line in enumerate(lines) if index not in remove_indices)
    return prefix + updated_body + suffix, removed, len(addresses)

def process(path, required):
    source = path.read_text()
    updated, removed, retained = filter_text(source, required)
    if updated != source:
        path.write_text(updated)
    return {
        "path": str(path),
        "removed_zero_address_mappings": len(removed),
        "removed_symbols": removed,
        "retained_nonzero_mappings": retained,
        "required_addresses": [f"0x{x:08X}" for x in required],
    }

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("root", type=Path)
    p.add_argument("--receipt", type=Path, required=True)
    a = p.parse_args()
    root = a.root.resolve()
    dash = root / "generated/dash_17559_init.cpp"
    xam = root / "generated_xam/metro_xam_init.cpp"
    if not dash.is_file() or not xam.is_file():
        raise FileNotFoundError("expected dashboard and XAM generated init sources")
    hud = root / "generated_hud/metro_hud_init.cpp"
    results = [process(dash, DASH_REQUIRED), process(xam, XAM_REQUIRED), process(hud,(0x913F8D00,))]
    if any(x["removed_zero_address_mappings"] for x in results):
        raise ValueError("corrected loader unexpectedly emitted address-zero mappings")
    a.receipt.parent.mkdir(parents=True, exist_ok=True)
    a.receipt.write_text(json.dumps({"files": results}, indent=2) + "\n")
    print(json.dumps({"files": results}, indent=2))

if __name__ == "__main__":
    main()
