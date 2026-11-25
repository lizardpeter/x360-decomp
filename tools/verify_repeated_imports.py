#!/usr/bin/env python3
"""Verify the SDK parser defect against the unchanged exact dashboard input."""
from prepare_recompilation import original
from xex import parse, u32

def audit(raw):
    result=parse(raw)
    offset=result["optional_headers"]["000103FF"]
    names=u32(raw,offset+8)
    records=result["imports"]
    counts=[(r["library"],r["slot_count"]) for r in records]
    expected=[("xam.xex",623),("xam.xex",421),("xboxkrnl.exe",584)]
    if names!=2 or counts!=expected:
        raise ValueError((names,counts))
    if any(r["library"]=="xboxkrnl.exe" for r in records[:names]):
        raise ValueError("expected old loop to miss kernel records")
    return names,counts

if __name__=="__main__":
    names,records=audit(original("dash"))
    print(f"Original import layout: {names} names, {len(records)} records; counts {records}. Old SDK loop drops all 584 kernel slots.")
