#!/usr/bin/env python3
"""Stage original, hash-verified skin input only for native tests, never as an artifact."""
import argparse
from pathlib import Path
from decode_image import decode
from pirs import parse
from prepare_recompilation import ROOT,original,sha

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("build-only fixtures")
    raw=parse(original("pirs"))["$flash_huduiskin.xex"]["payload"]
    if sha(raw)!="fdbe68d20fa6b013282ce8f21cebddc34fe4e3a92a71c28983d63f288d2252cc":
        raise ValueError("original skin identity")
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!="d7cc1f96a9ac09853d325c9522ba257e5e23c43c819de5007f36fb49e33cedf4":
        raise ValueError("decoded skin identity")
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/"huduiskin.xex").write_bytes(raw)
    (a.output/"huduiskin.decoded").write_bytes(image)
    print("Native HUD skin fixtures staged; no firmware artifact uploaded")
if __name__=="__main__":main()
