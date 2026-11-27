#!/usr/bin/env python3
"""Read-only evidence for the original signed font path.

Only metadata, checked public-verification outcomes and original instruction
operands are emitted. Never exports font content, signatures, hashes of
individual signed messages, private keys, or runtime guest data.
"""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from decode_image import decode
from metro_import_contracts import DIGESTS, branch, hx
from metro_xam_fault_evidence import bounded_entry, operand
from analyze_decoded import pe_info
from patch_metro_public_verification import modulus,reference_signature_result
from prepare_recompilation import ROOT,original,EXPECTED,sha
from pirs import parse
from stage_dashboard_runtime import acquire_font_complements,verify_members
from fetch_originals import config

# Original verified call sites: wrapper, direct caller, salt-address formation.
MODULES={
    "dash":(0x9222F2A0,0x9222F7E0,0x9222F964,0x9222F330,0x9222F338),
    "xam":(0x81795B68,0x817960A8,0x8179622C,0x81795BF8,0x81795C00),
}
MASK=(1<<64)-1
MAX_HEADER=4096
MAX_HASH_BYTES=128*1024*1024
ORIGINAL_SIGNED_RANGES={
    "SegoeXbox-Light.xtt":(260,3836),
    "XenonCLatin.xtt":(260,48892),
    "XenonJKLatin.xtt":(260,98044),
}

def rot(value,count):
    return ((value<<count)|(value>>(64-count)))&MASK

def rotsum_sha(data):
    # One input, as proved by the original wrapper: r5=r6=0.
    a=b=c=d=0
    for (word,) in struct.iter_unpack(">Q",data[:len(data)&~7]):
        b=(b+word)&MASK
        d=(d-word)&MASK
        a=(a+(b<word))&MASK
        c=(c-(d>word))&MASK
        b=rot(b,29)
        d=rot(d,31)
    prefix=struct.pack(">4Q",a,b,c,d)
    inverse=bytes(x^255 for x in prefix)
    h=hashlib.sha1()
    for segment in (prefix,prefix,data,inverse,inverse):h.update(segment)
    return h.digest()

def rc4(key,data):
    s=list(range(256));j=0
    for i in range(256):
        j=(j+s[i]+key[i%len(key)])&255
        s[i],s[j]=s[j],s[i]
    i=j=0;result=bytearray()
    for b in data:
        i=(i+1)&255;j=(j+s[i])&255
        s[i],s[j]=s[j],s[i]
        result.append(b^s[(s[i]+s[j])&255])
    return bytes(result)

def signature_integer(data):
    if len(data)!=256:raise ValueError("signature extent")
    return sum(v<<(i*64) for i,(v,) in enumerate(struct.iter_unpack(">Q",data)))

def recover_block(signature,n,e,salt):
    number=signature_integer(signature)
    recovered=reference_signature_result(number,e,n)
    if recovered is None:return None
    raw=recovered.to_bytes(256,"big")
    if raw[-1]!=0xBC or raw[0]&0x80:return None
    digest=raw[235:255]
    decoded=rc4(digest,raw[:235])
    if decoded[0] not in (0,0x80) or any(decoded[1:224]) or decoded[224]!=1 or decoded[225:]!=salt:
        return None
    return digest

def scan_headers(data,n,e,salt):
    # Search bounded aligned locations, not a key search. Return only
    # candidate positions and internal expected digest for further checking.
    limit=min(MAX_HEADER,len(data))
    offsets=set(range(0,max(0,limit-255),4))
    # Some signed containers put the signature in a fixed trailer.
    offsets.update(range((max(0,len(data)-MAX_HEADER)+3)&~3,max(0,len(data)-255),4))
    matches=[]
    for offset in sorted(offsets):
        if (digest:=recover_block(data[offset:offset+256],n,e,salt)) is not None:
            matches.append((offset,digest))
    return matches,len(offsets)

def candidate_ranges(data,offset):
    # Evidence-only candidate search. Never used by the runtime verifier.
    # Prefer contiguous bytes immediately before/after the found signature.
    size=len(data);after=offset+256
    candidates=[(after,size),(0,offset)]
    # The original reader requests 260 bytes first and obtains the signed
    # buffer separately. The length metadata therefore lives after the
    # 256-byte signature, not in the signature itself.
    values=set()
    for begin,end in ((0,min(offset,64)),(after,min(after+64,size))):
        for i in range(begin,end-3,4):
            for endian in ("big","little"):
                v=int.from_bytes(data[i:i+4],endian)
                if 0<v<=size:values.add(v)
    starts=[i for i in range(after,min(after+64,size),4)]
    # Test header-derived lengths first, before expensive whole-file ranges.
    priority=[]
    for start in starts:
        for v in sorted(values):
            if start+v<=size:priority.append((start,start+v))
            if start<v<=size:priority.append((start,v))
    candidates=priority+candidates
    boundaries=sorted({0,after,size,offset}|{v for v in values if 0<v<size})
    for start in (after,0):
        for end in boundaries:
            if start<end and (end<=offset or start>=after):
                candidates.append((start,end))
    for start in boundaries:
        if start>=after and start<size:candidates.append((start,size))
        if 0<=start<offset:candidates.append((start,offset))
    return list(dict.fromkeys((a,b) for a,b in candidates if 0<=a<b<=size))

def inspect_signature(data,n,e,salt):
    matches,count=scan_headers(data,n,e,salt)
    found=[];budget=MAX_HASH_BYTES;cached={}
    for offset,digest in matches:
        accepted=[];examined=0;limited=False
        for start,end in candidate_ranges(data,offset):
            if (start,end) not in cached:
                if end-start>budget:
                    limited=True
                    continue
                budget-=end-start
                cached[start,end]=rotsum_sha(data[start:end])
            examined+=1
            calculated=hashlib.sha1(bytes(8)+cached[start,end]+salt).digest()
            if calculated==digest:accepted.append({"offset":start,"length":end-start})
        found.append({"signature_offset":offset,"encoded_padding_and_salt_valid":True,
                      "signed_contiguous_ranges":accepted,"ranges_examined":examined,
                      "hash_budget_limited":limited})
    return {"bytes":len(data),"signature_locations_examined":count,
            "matching_encoded_signatures":found,"hash_bytes_examined":MAX_HASH_BYTES-budget,
            "signed_range_verified":any(item["signed_contiguous_ranges"] for item in found),
            "scope":"Bounded original public signature and contiguous-range evidence; no acceptance override."}

def original_module(label,raw,lzx):
    image,meta=decode(raw,lzx)
    if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong original image")
    base=meta["image_base"];pe=pe_info(image,base)
    wrapper,parent,call,hi,lo=MODULES[label]
    def read_word(pc):
        if not base<=pc<=base+len(image)-4:raise ValueError("instruction extent")
        return struct.unpack_from(">I",image,pc-base)[0]
    if branch(call,read_word(call))!=(wrapper,True):raise ValueError("signature caller changed")
    high=operand(hi,read_word(hi));low=operand(lo,read_word(lo))
    if (high.get("kind")!="immediate" or low.get("kind")!="register_offset"
        or high.get("writes")!=low.get("base") or low.get("writes")!=5):
        raise ValueError("salt argument construction changed")
    address=(high["value"]+low["value"])&0xffffffff
    if not base<=address<=base+len(image)-10:raise ValueError("salt extent")
    salt=image[address-base:address-base+10]
    body=bounded_entry(image,base,pe,parent,{},4096)
    if not body["extent_verified"] or hx(call) not in {o["pc"] for o in body["operands"]}:
        raise ValueError("original signature caller extent")
    index=next(i for i,o in enumerate(body["operands"]) if o["pc"]==hx(call))
    return salt,{"wrapper":hx(wrapper),"caller":hx(parent),"callsite":hx(call),"salt_address":hx(address),
                 "salt_bytes":len(salt),"setup_operands":body["operands"][:index+8],
                 "verification_wrapper":bounded_entry(image,base,pe,wrapper,{},4096)}

def verify_original_range(name,data,n,e,salt):
    # Exact recovered payload, not a runtime candidate search. Only checked
    # signature validity is reported; no signature or signed hash is exported.
    start,length=ORIGINAL_SIGNED_RANGES[name]
    end=start+length
    if end>len(data):return False
    expected=recover_block(data[4:260],n,e,salt)
    if expected is None:return False
    payload=data[start:end]
    if hashlib.sha1(bytes(8)+rotsum_sha(payload)+salt).digest()!=expected:return False
    changed=bytearray(payload)
    changed[len(changed)//2]^=1
    return hashlib.sha1(bytes(8)+rotsum_sha(changed)+salt).digest()!=expected

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--native-fixtures",type=Path,
                   help="write local-only original signed ranges for native regression; never upload")
    a=p.parse_args()
    if a.native_fixtures and not a.native_fixtures.resolve().is_relative_to(ROOT/"build"):
        p.error("native fixtures must remain under build")
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    members=parse(original("pirs"))
    census=json.loads((ROOT/"analysis/pirs_17559/members.json").read_text())
    verify_members(members,census)
    xam=members["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong XAM source")
    ds,dash=original_module("dash",original("dash_basic"),a.lzx.resolve())
    xs,xam_info=original_module("xam",xam,a.lzx.resolve())
    if ds!=xs:raise ValueError("original module signature salts differ")
    directory=acquire_font_complements(ROOT/"build/metro-font-signature-inputs",config())
    fonts={"SegoeXbox-Light.xtt":members["$flash_SegoeXbox-Light.xtt"]["payload"]}
    for spec in config().get("local_resource",[]):fonts[spec["name"]]=(directory/spec["name"]).read_bytes()
    report={"original_modules":{"dash":dash,"xam":xam_info},
            "original_salt_agrees":True,
            "fonts":{name:inspect_signature(data,modulus(),3,ds) for name,data in sorted(fonts.items())}}
    if set(fonts)!=set(ORIGINAL_SIGNED_RANGES):raise ValueError("unexpected original font inventory")
    for name,data in fonts.items():
        passed=verify_original_range(name,data,modulus(),3,ds)
        report["fonts"][name]["exact_original_range_and_mutation_rejection"]=passed
        if not passed:raise ValueError("original signed range or mutation check failed: "+name)
        if a.native_fixtures:
            start,length=ORIGINAL_SIGNED_RANGES[name]
            payload=data[start:start+length]
            # Local test input only: signature, padded salt, expected digest,
            # exact original authenticated byte range. No private data.
            a.native_fixtures.mkdir(parents=True,exist_ok=True)
            (a.native_fixtures/(name+".bin")).write_bytes(
                data[4:260]+ds+b"\0\0"+rotsum_sha(payload)+payload)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    for name,item in report["fonts"].items():
        print(name,"encoded candidates",len(item["matching_encoded_signatures"]),
              "verified ranges",sum(len(r["signed_contiguous_ranges"]) for r in item["matching_encoded_signatures"]))
if __name__=="__main__":main()
