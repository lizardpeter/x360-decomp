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
    unresolved = []
    validation_totals = []
    current_group = None
    addresses = collections.defaultdict(set)
    for line in text.splitlines():
        low = line.lower()
        # ReXGlue's AnalysisErrorLog writes an explicit grouped report.
        group = re.search(r"\b(UnresolvedCall|Millicode)\s*\((\d+)\):",line)
        if group:
            current_group=group[1]
        if "=== ANALYSIS ERRORS ===" in line or re.search(r"\bTotal: \d+ errors",line):
            current_group=None
        entry=re.search(r"0x([0-9A-Fa-f]{8})\s+from\s+0x([0-9A-Fa-f]{8}):",line)
        if entry and current_group=="UnresolvedCall":
            unresolved.append({"target":entry[1].upper(),"site":entry[2].upper()})
        total=re.search(r"Validation failed:\s*(\d+) unresolved calls,\s*(\d+) millicode errors",line)
        if total:
            item={"unresolved_calls":int(total[1]),"millicode_errors":int(total[2])}
            if item not in validation_totals:validation_totals.append(item)
        if not re.search(r"\berror\b|\bfatal\b|\bcritical\b|\bfailed\b|\[e\]|\bunresolved\b|not in any function|\be>|\bvalidation\b",low):
            continue
        if "branch" in low or "jump" in low or "target" in low or "unresolved" in low or "not in any function" in low:
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
    return {"categories":dict(categories),"guest_addresses":{k:sorted(v) for k,v in addresses.items()},
            "unresolved_branches":unresolved,"validation_totals":validation_totals}

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
