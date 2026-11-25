#!/usr/bin/env python3
"""Audit original startup continuation with explicit hosted services and independent trace hashes."""
import argparse, hashlib, json, subprocess, tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs

REFERENCE={
 "dash_17559":dict(retired=258,attempted=258,pc=0x9293a71c,services=[403,299],notifications=[],trace="f005e5a978d6c97c8bb636c9a50d3b610121706213ec505b23177bd6dda84de5",state="8e4fa664b6b7c7011e577926f5c71164a26202bc60699487adc7d201b7fd0e37",stack="474e2c4629c507d3cdcdcd1ca8b220c9bb52fad25d8ca80d1d32c454700fa7c8",image_after="b4596516b527a01ef8e2d663b7207cfb10df7000b114a84ecf9cf22d8da1943f"),
 "xam_17559":dict(retired=172,attempted=172,pc=0x81a72fa4,services=[21],notifications=[0x817399f0,0x6c000000],trace="68a237cd1abe9d6a0da7b3aedd6a6906f74a5a5823e371250e8fb6387db10656",state="69d5397ce6cf428b8fcd3099ac254c597203959169b4fdc1fd5624c8a44adf74",stack="cf9718d40be4bdce6209edc7911cf44c86bedf3f950d778c082c4c81452c97d7",image_after="747b60db59d8a25b2f3d12f103ac64075b84d8b35c52b45bccf9f5bc3ae5138e"),
}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("probe",type=Path);p.add_argument("--lzx",type=Path,required=True);a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text())
    originals=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        for name,ident,raw,lzx in [("dash.xex","dash_17559",source("dash_basic"),None),("xam.xex","xam_17559",originals["$flash_xam.xex"]["payload"],a.lzx.resolve())]:
            run=Path(d)/ident;run.mkdir()
            inputs=write_module(run,name,ident,raw,lzx,summary)
            header=run/"header";header.write_bytes(raw[:int.from_bytes(raw[8:12],"big")])
            result=subprocess.check_output([str(a.probe.resolve()),*inputs,str(run),str(header)],text=True).split()
            assert result[0]=="allocation"
            retired,attempted,pc,n,callbacks=map(int,result[1:6]);rest=list(map(int,result[6:]))
            assert len(rest)==n+callbacks*2
            observed=dict(retired=retired,attempted=attempted,pc=pc,services=rest[:n],notifications=rest[n:])
            for k in ("trace","state","stack","image_after"):observed[k]=hashlib.sha256((run/k).read_bytes()).hexdigest()
            assert observed==REFERENCE[ident],(ident,observed,REFERENCE[ident])
            print(f"{ident}: {retired} retired original instructions, {n} hosted imports; NtAllocateVirtualMemory thunk at 0x{pc:08X}; all snapshot hashes match")
if __name__=="__main__":main()
