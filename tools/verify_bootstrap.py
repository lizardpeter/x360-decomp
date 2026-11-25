#!/usr/bin/env python3
"""Compare original startup prefixes with independent instruction reference traces."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path);p.add_argument("--lzx",required=True,type=Path);a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    reference=json.loads((ROOT/"analysis/modules/bootstrap-reference.json").read_text())["modules"]
    pirs=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        temp=Path(d)
        for name,ident,raw,lzx in [("dash.xex","dash_17559",source("dash_basic"),None),("xam.xex","xam_17559",pirs["$flash_xam.xex"]["payload"],a.lzx.resolve())]:
            run=temp/ident;run.mkdir()
            inputs=write_module(run,name,ident,raw,lzx,summary)
            output=subprocess.check_output([str(a.probe.resolve()),*inputs,str(run)],text=True)
            kind,retired,attempted,address,pc,library,ordinal=output.split()
            observed=dict(kind=kind,retired=int(retired),attempted=int(attempted),address=int(address),pc=int(pc),library=library,ordinal=int(ordinal))
            for key in ("trace","state","stack","image_after"):observed[key]=hashlib.sha256((run/key).read_bytes()).hexdigest()
            assert observed==reference[ident],(ident,observed,reference[ident])
            print(f"{ident}: {retired} original startup instructions retired, {kind} import {library}:{ordinal} at 0x{int(address):08X}; trace, state, stack and loaded image hashes match")
if __name__=="__main__":main()
