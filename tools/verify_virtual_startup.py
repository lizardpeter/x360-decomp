#!/usr/bin/env python3
"""Verify original dashboard startup after reserve/commit, retaining the unsupported XAM selector."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs
from verify_hosted_startup import REFERENCE as BASELINE
DASH=dict(retired=347,attempted=348,pc=0x92194bc4,services=[403,299,204,204],notifications=[],
 trace="c1ee8f53483d77cd78803c357411af6cc5aaf4236b2dd1b5c22f3c9c1ca0133d",
 state="ac82ebba53e40145a78c24c6f4a61e44cc3fdaffd1f99164151e3058726b335d",
 stack="2a111a5b5daf880626ff5780d574c95831bd3cfd219d6e163cfa63a286bbd814",
 image_after="b4596516b527a01ef8e2d663b7207cfb10df7000b114a84ecf9cf22d8da1943f",
 heap="c282012b95724f31684aab20f20c4e4830985076c0499997d7019edbc9b0d6f3")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("probe",type=Path);p.add_argument("--lzx",type=Path,required=True);a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text());originals=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        for name,ident,raw,lzx in [("dash.xex","dash_17559",source("dash_basic"),None),("xam.xex","xam_17559",originals["$flash_xam.xex"]["payload"],a.lzx.resolve())]:
            run=Path(d)/ident;run.mkdir();inputs=write_module(run,name,ident,raw,lzx,summary)
            header=run/"header";header.write_bytes(raw[:int.from_bytes(raw[8:12],"big")])
            result=subprocess.check_output([str(a.probe.resolve()),*inputs,str(run),str(header),"--allocator"],text=True).split()
            expected=DASH if ident=="dash_17559" else BASELINE[ident]
            assert result[0]==("heap" if ident=="dash_17559" else "allocation")
            retired,attempted,pc,n,callbacks=map(int,result[1:6]);rest=list(map(int,result[6:]))
            assert len(rest)==n+callbacks*2
            observed=dict(retired=retired,attempted=attempted,pc=pc,services=rest[:n],notifications=rest[n:])
            for k in ("trace","state","stack","image_after","heap"):
                if k in expected:observed[k]=hashlib.sha256((run/k).read_bytes()).hexdigest()
            assert observed==expected,(ident,observed,expected)
            print(f"{ident}: {retired} retired original instructions; allocator-enabled snapshot hashes match; "+("1 MiB reserved, 64 KiB committed" if ident=="dash_17559" else "selector 2 remains unresolved"))
if __name__=="__main__":main()
