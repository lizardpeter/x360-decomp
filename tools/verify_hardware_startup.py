#!/usr/bin/env python3
"""Check explicit diagnostic hardware and XAM selector profiles; no retail parity claim."""
import argparse,hashlib,json,subprocess,tempfile
from pathlib import Path
from fetch_originals import ROOT
from verify_module_loading import write_module
from verify_xui_resources import source
from pirs import parse as parse_pirs

DASH=dict(retired=1245,attempted=1245,pc=0x9293a6ac,services=[403,299,204,204,102,302,342,293,304],notifications=[],
 trace="794dce243986bdf5e93b12363feb36a6e72ed7072466aa68e63dbf9432f73c0e",
 state="9d7ee1da3b2aa645fa0e9222f00aa1f451e94641b3fb4110a4f7e1246c1ef44a",
 stack="875a51fec764c9f4649fa68541b44a7a0a4db7d23d676c12c62b6afae59e6b2f",
 image_after="afbf4d74afde03a425af183890b1d618376990a998d697976a0661ceb0ee5f0c",
 heap="372def7f933cd5724662952837011268cd5cf9564d13508f24220df4581cc477")
XAM=dict(retired=196,attempted=197,pc=0x8168af2c,services=[21,204],notifications=[0x817399f0,0x6c000000],
 trace="73da37d629e4a4fae41b1214b4667292214ffba8753670cec0f8aaaa4552b6f0",
 state="8a52336864f5bc5cdb55e7b1328409365c5d2c157069863590189d7056c0ef17",
 stack="cf9718d40be4bdce6209edc7911cf44c86bedf3f950d778c082c4c81452c97d7",
 image_after="8dd2c06b78b906ae88bd8d3a3cdc473cd079ec4ccde352bafa1825f0e5dfd4e6",
 heap="53bc62f02174b727ce8e17bcb3f7f109193852dd6e4ec1a73d75e87275df98f5")
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("probe",type=Path);p.add_argument("--lzx",type=Path,required=True);a=p.parse_args()
    summary=json.loads((ROOT/"analysis/decoded_summary.json").read_text());originals=parse_pirs(source("pirs"))
    with tempfile.TemporaryDirectory() as d:
        for name,ident,raw,lzx,option,expected in [("dash.xex","dash_17559",source("dash_basic"),None,"--hardware",DASH),("xam.xex","xam_17559",originals["$flash_xam.xex"]["payload"],a.lzx.resolve(),"--selector2",XAM)]:
            run=Path(d)/ident;run.mkdir();inputs=write_module(run,name,ident,raw,lzx,summary)
            header=run/"header";header.write_bytes(raw[:int.from_bytes(raw[8:12],"big")])
            result=subprocess.check_output([str(a.probe.resolve()),*inputs,str(run),str(header),option],text=True).split()
            if ident=="xam_17559":
                assert result[0]=="selector2" and int(result[4])==0x8e03860a
                del result[4]
            else:assert result[0]=="heap"
            retired,attempted,pc,n,callbacks=map(int,result[1:6]);rest=list(map(int,result[6:]))
            assert len(rest)==n+callbacks*2
            observed=dict(retired=retired,attempted=attempted,pc=pc,services=rest[:n],notifications=rest[n:])
            for k in ("trace","state","stack","image_after","heap"):
                observed[k]=hashlib.sha256((run/k).read_bytes()).hexdigest()
            assert observed==expected,(ident,observed,expected)
            print(f"{ident}: {retired} retired original instructions; diagnostic profile snapshot hashes match; "+("privilege check left unresolved" if ident=="dash_17559" else "selector2 allocation committed, next access fault preserved"))
if __name__=="__main__":main()
