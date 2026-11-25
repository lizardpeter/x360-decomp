#!/usr/bin/env python3
"""Audit original startup continuation with explicit hosted services and independent trace hashes."""
import argparse, hashlib, json, subprocess, tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs

REFERENCE={
 "dash_17559":dict(retired=128,attempted=129,pc=0x9219a204,services=[403,299],notifications=[],trace="5719e29d5649f170c24756a1c44ca40762d44d5317651cf54a6b5cb4ff66a97f",state="0c649d6c1df013666e2f3f8fb750014a720898989980ad41db3be07553e3317d",stack="309aafb7182a8cb53f748cb33bca706fd0aaa7248710e873f1b389179ef14045",image_after="b4596516b527a01ef8e2d663b7207cfb10df7000b114a84ecf9cf22d8da1943f"),
 "xam_17559":dict(retired=110,attempted=111,pc=0x816e6558,services=[21],notifications=[0x817399f0,0x6c000000],trace="716b22355461eddc152e3e219d8b85dfe648ac35d760ed7077c7e1abf2a9f519",state="8ee567bc607848db463b44df07cde223a28b5503fb470b37017bbde4492ff0da",stack="58c91f4917579c2e13586e1e42a6206020f3027298ec25fe75db9dadc6ec3d10",image_after="57e9783c7fe7f38cb2e2e7da1b001b20023719b1d46ff85dceccc194442fd40f"),
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
            assert result[0]=="unsupported"
            retired,attempted,pc,n,callbacks=map(int,result[1:6]);rest=list(map(int,result[6:]))
            assert len(rest)==n+callbacks*2
            observed=dict(retired=retired,attempted=attempted,pc=pc,services=rest[:n],notifications=rest[n:])
            for k in ("trace","state","stack","image_after"):observed[k]=hashlib.sha256((run/k).read_bytes()).hexdigest()
            assert observed==REFERENCE[ident],(ident,observed,REFERENCE[ident])
            print(f"{ident}: {retired} retired original instructions, {n} hosted imports; next opcode at 0x{pc:08X}; all snapshot hashes match")
if __name__=="__main__":main()
