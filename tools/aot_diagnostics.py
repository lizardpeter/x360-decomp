#!/usr/bin/env python3
"""Summarize codegen/compile failures without copying original code or data."""
import argparse
import collections
import json
import re
from pathlib import Path

# Only error category + numeric addresses are emitted from codegen logs.
# No instruction listings, source lines, local paths or raw log text.
def summarize(text):
    categories = collections.Counter()
    addresses = collections.defaultdict(set)
    for line in text.splitlines():
        low = line.lower()
        if not re.search(r"\berror\b|\bfatal\b|\bcritical\b|\bfailed\b|\[e\]",low):
            continue
        if "branch" in low or "jump" in low or "target" in low:
            kind = "control_flow"
        elif "instruction" in low or "opcode" in low:
            kind = "instruction"
        elif "overlap" in low or "function" in low:
            kind = "function"
        elif "undefined reference" in low or "undefined symbol" in low:
            kind = "link"
        elif "cmake" in low or "compiler" in low or "header" in low:
            kind = "toolchain"
        else:
            kind = "other"
        categories[kind] += 1
        for a in re.findall(r"(?<![0-9A-Fa-f])(?:0x)?([89][0-9A-Fa-f]{7})(?![0-9A-Fa-f])",line):
            addresses[kind].add(a.upper())
    return {"categories":dict(categories),"guest_addresses":{k:sorted(v) for k,v in addresses.items()}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("log",type=Path);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=summarize(a.log.read_text(errors="replace"))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))

if __name__=="__main__":
    main()
