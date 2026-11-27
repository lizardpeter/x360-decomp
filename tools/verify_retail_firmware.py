#!/usr/bin/env python3
"""Authenticate the pinned, read-only PIRS package using retail public RSA.

Public key and format cross-reference:
emoose/xbox-reversing, 5f85b9ec8c771577532ca1cfa20c691e9033f2c2,
stfschk/XeCrypt.cs and StfsFileSystem.cs. No private keys or execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
from fetch_originals import ROOT
from prepare_recompilation import original
from pirs import parse,block_offset
KEY=bytes.fromhex("0000002000000003000000000000000070e005f220d9e88bc61bf461b468a8571b0411c6a64ed240171288dd907c47bd89f08e4bf6b0f784a048deecaacee5c7f7bd8351113037a43da99f2f962710a219edf40e36792532a6cf37d8d4ae024afc66b3fbd1e687eb72f82c20612a06099ebb103d28ff48fe597ac86025033db300ac999718b9844ddf57c1d324134e2297f44b471caaa4bc357a344bcf51279c76a420ae2f4966be7117e136bc46604564a02e11089ba7c5777de7a60291f8d0637a057224804a11e7f74caf0e637ce674e6c8ba77ab02fc71feeb6997aeb0b2eea3c4a3b6eb58a6f9253e1ab58503ba20ac901abc8eba8e46e3d67240180dde47589441725cfc9de79e9e8db2323be6")
DIGEST_INFO=bytes.fromhex("3021300906052b0e03021a05000414")
def sha1(data):return hashlib.sha1(data).digest()
def read(data,off,n):
    if off<0 or n<0 or off+n>len(data):raise ValueError("truncated signed package")
    return data[off:off+n]
def u32(data,off):return int.from_bytes(read(data,off,4),"big")
def rsa_valid(signature,digest):
    # STFS stores the signature reversed and the modulus in per-qword
    # byte-swapped order. Require exact PKCS#1 v1.5 SHA-1 encoding.
    modulus=int.from_bytes(b"".join(KEY[i:i+8][::-1] for i in range(16,len(KEY),8)),"big")
    exponent=int.from_bytes(KEY[4:8],"big")
    value=int.from_bytes(signature[::-1],"big")
    if len(signature)!=256 or value>=modulus:return False
    decoded=pow(value,exponent,modulus).to_bytes(256,"big")
    suffix=DIGEST_INFO+digest
    expected=b"\0\1"+b"\xff"*(253-len(suffix))+b"\0"+suffix
    return decoded==expected
def table_block(block,level):
    if level==0:
        group=block//170
        return 0 if not group else group*171+block//28900+1+(block>=28900)
    if level==1:
        group=block//28900
        return 171 if not group else group*29071+1
    if level==2:return 29071
    raise ValueError("unsupported hash level")
def authenticate(data):
    if data[:4]!=b"PIRS":raise ValueError("expected PIRS")
    signature=rsa_valid(read(data,4,256),sha1(read(data,0x22c,0x118)))
    header_size=u32(data,0x340);base=(header_size+4095)&~4095
    if header_size<0x39d or base>len(data):raise ValueError("invalid header extent")
    metadata=sha1(read(data,0x344,base-0x344))==read(data,0x32c,20)
    if read(data,0x379,1)!=b"\x24" or not data[0x37b]&1:
        raise ValueError("expected read-only STFS volume")
    count=u32(data,0x395)
    if not 0<count<=170**3:raise ValueError("invalid volume block count")
    root=read(data,0x381,20)
    highest=2 if count>28900 else 1 if count>170 else 0
    tables={};bad_tables=set();bad_blocks=[]
    for block in range(count):
        expected=root
        for level in range(highest,-1,-1):
            location=table_block(block,level)
            if location not in tables:
                table=read(data,base+location*4096,4096)
                tables[location]=(table,sha1(table))
            table,digest=tables[location]
            if digest!=expected:bad_tables.add(location)
            record=(block//(170**level))%170
            expected=read(table,record*24,20)
        payload=read(data,block_offset(base,block),4096)
        if sha1(payload)!=expected:bad_blocks.append(block)
    return {"retail_pirs_rsa_signature_valid":signature,"metadata_hash_valid":metadata,
            "data_blocks":count,"hash_tables":len(tables),"bad_hash_tables":sorted(bad_tables),
            "bad_data_blocks":bad_blocks,
            "authenticated":signature and metadata and not bad_tables and not bad_blocks}
def audit():
    data=original("pirs")
    result=authenticate(data)
    members=parse(data)
    result["archive_sha256"]=hashlib.sha256(data).hexdigest()
    result["public_key_sha256"]=hashlib.sha256(KEY).hexdigest()
    result["key_reference"]="emoose/xbox-reversing@5f85b9ec8c771577532ca1cfa20c691e9033f2c2/stfschk/XeCrypt.cs"
    result["members"]={name:{"sha256":m["sha256"],"bytes":m["bytes"],
                             "authenticated_by_pirs":result["authenticated"]} for name,m in members.items()}
    dash=original("dash")
    result["standalone_dashboard_identical_to_member"]=dash==members["$flash_dash.xex"]["payload"]
    result["standalone_dashboard_authenticated_by_pirs"]=result["authenticated"] and result["standalone_dashboard_identical_to_member"]
    result["shared_resources_sha256"]=hashlib.sha256(original("shared_resources")).hexdigest()
    result["shared_resources_identical_to_members"]=[name for name,m in members.items() if m["sha256"]==result["shared_resources_sha256"]]
    result["individual_xex_rsa_verified"]=False
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    result=audit()
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    if not result["authenticated"] or not result["standalone_dashboard_authenticated_by_pirs"]:raise SystemExit(1)
if __name__=="__main__":main()
