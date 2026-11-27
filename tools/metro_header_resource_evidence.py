#!/usr/bin/env python3
"""Locate exact authored header strings in verified dashboard resources.

Only known-label categories, lengths, resource/member identity and offsets
are reported; no original localized text, font data or scene payloads.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

LABELS={"home":"home","home_short":"hom","movies":"movies & tv",
        "movies_short":"movies & t","movies_and":"movies and tv",
        "social":"social","games":"games","apps":"apps","settings":"settings"}

def take(data,p,n):
    if p<0 or n<0 or p>len(data)-n:raise ValueError("truncated resource")
    return data[p:p+n]

def u16(data,p):return int.from_bytes(take(data,p,2),"big")
def u32(data,p):return int.from_bytes(take(data,p,4),"big")

def cstring(data,p):
    end=data.find(b"\0",p)
    if end<0:raise ValueError("unterminated string")
    return data[p:end].decode("utf-8"),end+1

def wide(data,p):
    n=u16(data,p)
    return take(data,p+2,n*2).decode("utf-16-be"),p+2+n*2

def archive(data):
    if data[:4]!=b"XUIZ" or u32(data,8)!=len(data) or u32(data,12)!=0:raise ValueError("bad archive")
    version=u32(data,4)
    if version not in (1,3):raise ValueError("archive version")
    end=22+u32(data,16)
    directory=take(data,22,end-22)
    payload=data[end:]
    p=0;members=[]
    for i in range(u16(data,20)):
        n,off,length=struct.unpack(">IIB",take(directory,p,9));p+=9
        size=length*(2 if version==1 else 1)
        name=take(directory,p,size).decode("utf-16-be" if version==1 else "utf-8");p+=size
        if not name or "\0" in name:raise ValueError("invalid member")
        members.append((name,off,take(payload,off,n)))
    cursor=0
    for _,off,content in sorted(members,key=lambda m:m[1]):
        if off!=cursor:raise ValueError("member extent")
        cursor+=len(content)
    if cursor!=len(payload) or p!=len(directory):raise ValueError("archive extent")
    return members

def string_table(data):
    if data[:4]!=b"XUIS" or u32(data,6)!=len(data):raise ValueError("bad string table")
    version,mode=data[4:6]
    if version not in (1,2) or mode not in (0,1,2):raise ValueError("table type")
    read=wide if version==1 else cstring
    p=12;rows=[]
    for index in range(u16(data,10)):
        offset=p
        value,p=read(data,p)
        if mode==0:_,p=read(data,p)
        if mode==1:take(data,p,4);p+=4
        rows.append((index,offset,value))
    if p!=len(data):raise ValueError("string table extent")
    return rows

def scene_strings(data):
    version=u32(data,4);count=u16(data,18)
    if data[:4]!=b"XUIB" or version!=8 or u16(data,12)!=14 or u32(data,14)!=len(data):raise ValueError("scene header")
    if not 1<=count<=64:raise ValueError("section count")
    candidates=[]
    for p in range(20,min(512,len(data)-count*12)+1):
        if data[p:p+4]!=b"STRN":continue
        cursor=p+count*12;tags=set();sections={}
        for i in range(count):
            tag,off,n=struct.unpack(">4sII",take(data,p+i*12,12))
            if not re.fullmatch(b"[A-Z]{4}",tag) or tag in tags or off!=cursor or n>len(data)-cursor:break
            tags.add(tag);sections[tag]=(off,n);cursor+=n
        else:
            if cursor==len(data):candidates.append(sections)
    if len(candidates)!=1:raise ValueError("ambiguous scene directory")
    start,n=candidates[0][b"STRN"];strings=take(data,start,n)
    p=6;rows=[];units=0
    for index in range(u16(strings,4)):
        offset=p;value,p=cstring(strings,p)
        units+=len(value.encode("utf-16-be"))//2+1
        rows.append((index,start+offset,value))
    if p!=len(strings) or units!=u32(strings,0):raise ValueError("scene string extent")
    return rows

def classify(value):
    normalized=" ".join(value.casefold().split())
    return next((key for key,text in LABELS.items() if text==normalized),None)

def audit(raw,image,base,resources,census):
    expected={r["id"]:r["sha256"] for r in census}
    counts={"archives":0,"string_tables":0,"scenes":0,"strings":0}
    matches=[]
    if set(expected)!={r["id"] for r in resources}:raise ValueError("resource census mismatch")
    for r in resources:
        ident=r["id"];data=take(image,int(r["address"],16)-base,r["bytes"])
        if hashlib.sha256(data).hexdigest()!=expected[ident]:raise ValueError("resource digest mismatch")
        if data[:4]!=b"XUIZ":continue
        counts["archives"]+=1
        for name,member_offset,content in archive(data):
            if content[:4]==b"XUIS":
                rows=string_table(content);kind="string_table";counts["string_tables"]+=1
            elif content[:4]==b"XUIB":
                rows=scene_strings(content);kind="scene";counts["scenes"]+=1
            else:continue
            counts["strings"]+=len(rows)
            for index,offset,value in rows:
                if label:=classify(value):
                    matches.append({"label":label,"resource":ident,"member":name,"member_offset":member_offset,
                                    "kind":kind,"index":index,"offset":offset,"utf16_units":len(value.encode("utf-16-be"))//2})
    if counts["archives"]!=35 or counts["scenes"]!=363 or counts["string_tables"]!=3824:
        raise ValueError(f"incomplete authored dashboard census: {counts}")
    return {"counts":counts,"matches":matches,"label_counts":{k:sum(m["label"]==k for m in matches) for k in LABELS},
            "scope":"Exact original authored string records; not proof of runtime string selection."}

def main():
    from prepare_recompilation import ROOT,original
    from decode_image import decode
    from xex import parse
    from metro_import_contracts import DIGESTS
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    raw=original("dash_basic")
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!=DIGESTS["dash"]:raise ValueError("wrong original identity")
    census=json.loads((ROOT/"analysis/dash_17559/resource_hashes.json").read_text())
    report=audit(raw,image,meta["image_base"],parse(raw)["resources"],census)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print(report["counts"],report["label_counts"])
if __name__=="__main__":main()
