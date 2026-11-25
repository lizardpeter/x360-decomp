#!/usr/bin/env python3
"""Verify the native leaf binding set against the original independently decoded dashboard."""
import hashlib
import re
from pathlib import Path
from fetch_originals import ROOT, config, check, safe_key
from decode_image import decode
from analyze_decoded import pe_info

def main():
    item=next(s for s in config()["source"] if s["id"]=="dash_basic")
    path=ROOT/"originals"/safe_key(item["key"])
    check(path,item)
    image,info=decode(path.read_bytes())
    assert hashlib.sha256(image).hexdigest()=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
    base=info["image_base"]
    # .pdata ranges are independent of the Ghidra function discovery heuristics.
    pe=pe_info(image,base)
    expected={a for a,n,_ in pe["functions"] if n==12 and image[a-base:a-base+n]==bytes.fromhex("386000017d0843784e800020")}
    native=(ROOT/"src/os/dashboard/leaf_17559.cpp").read_text()
    bindings=[int(a,16) for a in re.findall(r"\{0x([0-9A-F]{8})u,\s*return_one\}",native)]
    assert len(bindings)==len(set(bindings))==47
    assert set(bindings)==expected
    memory=(ROOT/"src/os/dashboard/memory_leaf_17559.cpp").read_text()
    patterns={"compare_17":"3d60c000616b001781430000814a00007d6a58507d6b00345563dffe7d0843784e800020","compare_05":"3d60c000616a000581230000810900007ce850507ce6003454c3dffe7d0843784e800020"}
    for name,pattern in patterns.items():
        payload=bytes.fromhex(pattern)
        expected={a for a,n,_ in pe["functions"] if n==len(payload) and image[a-base:a-base+n]==payload}
        actual=[int(a,16) for a in re.findall(r"\{0x([0-9A-F]{8})u,"+name+r"\}",memory)]
        assert len(actual)==len(set(actual)) and set(actual)==expected and actual
        print(f"{name}: {len(actual)} exact original bodies verified")
    print(f"Original image digest and every one of {len(bindings)} native leaf entry bodies verified")
if __name__=="__main__":
    main()
