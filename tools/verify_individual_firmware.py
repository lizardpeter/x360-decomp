#!/usr/bin/env python3
"""Independently verify original XEX headers and compare detached input bytes.

XEX verifier cross-reference: landaire/acceleration at
97f9ae6e0469d60c9320d5ea6010f133acb35e45:
crates/xecrypt/src/{xex_sig,symmetric,keys}.rs and
crates/xex2/src/{hashes,header}.rs. Public verification only.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path
from fetch_originals import ROOT,config,acquire
from prepare_recompilation import original
from verify_retail_firmware import KEY,authenticate,read,u32
from pirs import parse
from decode_image import decode

MASK=(1<<64)-1
def rol(x,n):return ((x<<n)|(x>>(64-n)))&MASK
def rot_sum_sha(data):
    a,b,c,d=0,0,0,0
    for offset in range(0,len(data)-7,8):
        q=int.from_bytes(data[offset:offset+8],"big")
        s=(b+q)&MASK
        a=(a+(s<q))&MASK
        b=rol(s,29)
        diff=(d-q)&MASK
        c=(c-(diff>q))&MASK
        d=rol(diff,31)
    words=(a,b,c,d)
    rot=b"".join(x.to_bytes(8,"big") for x in words)
    inv=b"".join((x^MASK).to_bytes(8,"big") for x in words)
    return hashlib.sha1(rot*2+data+inv*2).digest()
def rc4(key,data):
    s=list(range(256));j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&255
        s[i],s[j]=s[j],s[i]
    i=j=0;out=bytearray()
    for v in data:
        i=(i+1)&255;j=(j+s[i])&255
        s[i],s[j]=s[j],s[i]
        out.append(v^s[(s[i]+s[j])&255])
    return bytes(out)
def reverse_qwords(b):
    if len(b)%8:raise ValueError("partial qword")
    return b"".join(b[i:i+8] for i in range(len(b)-8,-1,-8))
def xex_rsa(sig,digest,salt):
    n=int.from_bytes(b"".join(KEY[i:i+8][::-1] for i in range(16,len(KEY),8)),"big")
    e=int.from_bytes(KEY[4:8],"big")
    value=int.from_bytes(reverse_qwords(sig),"big")
    if value>=n:return False
    inner=hashlib.sha1(bytes(8)+digest+salt).digest()
    natural=bytearray(rc4(inner,bytes(0xe0)+b"\1"+salt)+inner+b"\xbc")
    natural[0]&=0x7f
    expected=int.from_bytes(natural,"big")*pow(1<<2048,e-1,n)%n
    return pow(value,e,n)==expected
def xex_header(data):
    if data[:4]!=b"XEX2":raise ValueError("not XEX2")
    end=u32(data,8);sec=u32(data,16)
    if not 24<=sec<=end-0x184 or end>len(data):raise ValueError("bad XEX bounds")
    size=u32(data,sec);info=u32(data,sec+0x108)
    if not 0x184<=size<=end-sec or not 0x104<=info<=0x174:
        raise ValueError("bad security info size")
    flags=u32(data,sec+0x10c)
    salt=b"XBOXREVXEX" if flags&0x80000000 else b"XBOX360XEX"
    digest=rot_sum_sha(read(data,sec+0x108,info-0x100))
    signature=xex_rsa(read(data,sec+8,256),digest,salt)
    header_hash=hashlib.sha1(data[sec+0x17c:end]+data[:sec+8]).digest()==read(data,sec+0x164,20)
    return {"retail_xex_rsa_valid":signature,"signed_header_hash_valid":header_hash,
            "salt":salt.decode(),"authenticated_header":signature and header_hash,
            "sha256":hashlib.sha256(data).hexdigest()}
def check_xex(data,lzx):
    try:r=xex_header(data)
    except ValueError as e:return {"authenticated_header":False,"error":str(e)}
    try:
        _,proof=decode(data,lzx)
        r["verified_page_runs"]=proof["verified_page_runs"]
        r["decoded_image_sha256"]=proof["sha256"]
        r["payload_hash_chain_valid"]=True
    except Exception as e:
        r["payload_hash_chain_valid"]=False
        r["payload_validation_limit"]=str(e)
    r["individually_authenticated"]=r["authenticated_header"] and r["payload_hash_chain_valid"]
    return r
def matches_in_zip(archive,targets):
    # Compare complete bytes only. No extracted or executed archive contents.
    matches={k:[] for k in targets}
    sizes={}
    for label,data in targets.items():sizes.setdefault(len(data),[]).append(label)
    with zipfile.ZipFile(archive) as z:
        for member in z.infolist():
            if member.is_dir() or member.file_size not in sizes:continue
            payload=z.read(member)
            for label in sizes[member.file_size]:
                if payload==targets[label]:matches[label].append(member.filename)
    return matches
def audit(lzx):
    archive=original("pirs")
    auth=authenticate(archive)
    if not auth["authenticated"]:raise ValueError("PIRS package failed signature or hash tree")
    members=parse(archive)
    rows={}
    for name,m in members.items():
        if name.lower().endswith(".xex"):
            rows[name]=check_xex(m["payload"],lzx)
            rows[name]["authenticated_by_pirs"]=True
    cfg=config()
    fonts={}
    for spec in cfg.get("local_resource",[]):
        path=acquire(spec|{"id":spec["name"]},ROOT/"originals",cfg["r2_public"])
        fonts[spec["name"]]=path.read_bytes()
    targets={"pirs":archive,"dash":original("dash"),"dash_basic":original("dash_basic"),
             "shared_resources":original("shared_resources"),**fonts}
    for name in ("dash","dash_basic"):rows[name]=check_xex(targets[name],lzx)
    rows["dash"]["authenticated_by_pirs"]=targets["dash"]==members["$flash_dash.xex"]["payload"]
    # Source ZIP is a separate archive from the individually pinned files.
    # Identical copies here corroborate provenance, not a cryptographic
    # Microsoft signature unless they are inside a verified signed container.
    archives={}
    for source in ("system_update","jrunner","xebuild"):
        spec=next(s for s in cfg["source"] if s["id"]==source)
        archive_path=ROOT/"originals"/spec["key"]
        archives[source]=matches_in_zip(archive_path,targets)
    detached={}
    for name in ("shared_resources",*fonts):
        data=targets[name]
        # Check exact bytes against signed PIRS members, including embedded
        # regions. Also locate full SHA1/SHA256 digests in authenticated
        # members, without assuming a matching sequence is a signed manifest
        # entry or declaring an unparsed patch authentic.
        sha1=hashlib.sha1(data).digest();sha256=hashlib.sha256(data).digest()
        exact=[];contained=[];digest_refs=[]
        for member,m in members.items():
            payload=m["payload"]
            if payload==data:exact.append(member)
            elif data in payload:contained.append(member)
            for kind,d in (("sha1",sha1),("sha256",sha256)):
                off=payload.find(d)
                if off>=0:digest_refs.append({"member":member,"algorithm":kind,"offset":off})
        detached[name]={"bytes":len(data),"sha256":sha256.hex(),"signed_pirs_exact_members":exact,
                        "signed_pirs_embedded_members":contained,"signed_member_digest_candidates":digest_refs,
                        "archive_matches":{a:v[name] for a,v in archives.items()},
                        "authenticated_by_signed_pirs":bool(exact or contained)}
    # Compare alternate dashboard's decoded image with signed retail dash.
    alternate=rows["dash_basic"];retail=rows["$flash_dash.xex"]
    alternate["decoded_image_identical_to_signed_dash"]=bool(alternate.get("decoded_image_sha256") and
          alternate["decoded_image_sha256"]==retail.get("decoded_image_sha256"))
    return {"pirs_authenticated":True,"xex":rows,"detached":detached,"archive_matches":archives,
            "all_runtime_xex_individually_authenticated":all(rows["$flash_"+n+".xex"]["individually_authenticated"]
                    for n in ("dash","xam","hud","bootanim")),
            "all_detached_authenticated":all(r["authenticated_by_signed_pirs"] for r in detached.values()),
            "scope":"Archive byte matches alone are corroboration, not Microsoft signature validation. No files executed."}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    result=audit(a.lzx.resolve())
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result,indent=2))
    if not result["all_runtime_xex_individually_authenticated"]:
        raise SystemExit("Individual XEX verification incomplete; inspect receipt")
if __name__=="__main__":main()
