#!/usr/bin/env python3
"""Verify original dashboard startup after reserve/commit, retaining the unsupported XAM selector."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs
from verify_hosted_startup import REFERENCE as BASELINE
DASH=dict(retired=352,attempted=352,pc=0x9293a74c,services=[403,299,204,204],notifications=[],
 trace="f03b7f9ec1f939e8b33f4d1f15ece893a891b053d6f9c55ebacca1a16edfa2b8",
 state="8405119dec1018c99041582c973c42c3d7d3be2c9b26dce88a88a81b6e364297",
 stack="2a111a5b5daf880626ff5780d574c95831bd3cfd219d6e163cfa63a286bbd814",
 image_after="b4596516b527a01ef8e2d663b7207cfb10df7000b114a84ecf9cf22d8da1943f",
 heap="6005edea7057f159028018dce2305f42cd555564a69b76966e8703ed4070294a")
HEAP=dict(retired=1173,attempted=1174,pc=0x92198b18,services=[403,299,204,204,102,302],notifications=[],
 trace="a60efa099827131016dcb208393d1baa88cdce5b163d69aae501d6860e2a0b67",
 state="adc7bb8b1f10fda00d8e0627307b3bb1e5fcc315dce20c87ca8707f0792a2b0b",
 stack="2cfe253918e873d4c1176873ca58dc770f4259091b297d24fac790b03f35c535",
 image_after="afbf4d74afde03a425af183890b1d618376990a998d697976a0661ceb0ee5f0c",
 heap="372def7f933cd5724662952837011268cd5cf9564d13508f24220df4581cc477")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("probe",type=Path);p.add_argument("--lzx",type=Path,required=True);p.add_argument("--heap-startup",action="store_true");a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text());originals=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        for name,ident,raw,lzx in [("dash.xex","dash_17559",source("dash_basic"),None),("xam.xex","xam_17559",originals["$flash_xam.xex"]["payload"],a.lzx.resolve())]:
            run=Path(d)/ident;run.mkdir();inputs=write_module(run,name,ident,raw,lzx,summary)
            header=run/"header";header.write_bytes(raw[:int.from_bytes(raw[8:12],"big")])
            result=subprocess.check_output([str(a.probe.resolve()),*inputs,str(run),str(header),"--heap-startup" if a.heap_startup else "--allocator"],text=True).split()
            expected=(HEAP if a.heap_startup else DASH) if ident=="dash_17559" else BASELINE[ident]
            assert result[0]==("heap" if ident=="dash_17559" else "allocation")
            retired,attempted,pc,n,callbacks=map(int,result[1:6]);rest=list(map(int,result[6:]))
            assert len(rest)==n+callbacks*2
            observed=dict(retired=retired,attempted=attempted,pc=pc,services=rest[:n],notifications=rest[n:])
            for k in ("trace","state","stack","image_after","heap"):
                if k in expected:observed[k]=hashlib.sha256((run/k).read_bytes()).hexdigest()
            assert observed==expected,(ident,observed,expected)
            print(f"{ident}: {retired} retired original instructions; allocator-enabled snapshot hashes match; "+("1 MiB reserved, 64 KiB committed" if ident=="dash_17559" else "selector 2 remains unresolved"))
if __name__=="__main__":main()
