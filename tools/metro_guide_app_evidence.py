#!/usr/bin/env python3
"""Read the original XAM app initialization table and exact loader contracts."""
import argparse
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog
from metro_xam_fault_evidence import operand,bounded_entry,conditional_details
from metro_live_slot_and_input_evidence import executable
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,sha,original
from xex import parse as parse_xex

APP_LOOP=0x816BD270
APP_TABLE=0x815F91F0

def word(image,base,pc):
    offset=pc-base
    if offset<0 or offset+4>len(image):raise ValueError("word outside original image")
    return struct.unpack_from(">I",image,offset)[0]

def read_name(image,base,address):
    if not address:return None
    offset=address-base
    if not 0<=offset<len(image):return None
    raw=image[offset:offset+128]
    end=raw.find(b"\0")
    if not 0<end<=127:return None
    raw=raw[:end]
    if not all(32<=c<127 for c in raw):return None
    return raw.decode("ascii")

def app_table(image,base,pe):
    def check(pc,**expected):
        row=operand(pc,word(image,base,pc))
        if any(row.get(k)!=v for k,v in expected.items()):
            raise ValueError("original app table operand mismatch "+hx(pc))
        return row
    hi=check(0x816BD2BC,kind="immediate",writes=11)
    lo=check(0x816BD2C4,kind="register_offset",base=11,writes=11)
    addr=(hi["value"]+lo["value"])&0xffffffff
    if addr!=APP_TABLE:raise ValueError("app table base changed")
    check(0x816BD2C8,kind="register_offset",base=11,writes=31,value=4)
    limit=check(0x816BD2D4,kind="compare_immediate",register=27,unsigned=True,value=240)
    for pc,reg in ((0x816BD3FC,27),(0x816BD400,31)):
        check(pc,kind="register_offset",base=reg,writes=reg,value=16)
    for pc,offset in ((0x816BD314,0),(0x816BD338,8),(0x816BD344,4),(0x816BD360,-4)):
        check(pc,kind="memory_load",base=31,offset=offset,width=4)
    for pc,dst in ((0x816BD368,0x816BCC38),(0x816BD3B0,0x816BCD08)):
        if branch(pc,word(image,base,pc))!=(dst,True):raise ValueError("original app initialization edge changed")
    # Exact original object index calculation: mulli r10,r4,imm;
    # subf r30,r10,r11. Do not infer struct field names.
    m=word(image,base,0x816BD324)
    if (m>>26,(m>>21)&31,(m>>16)&31)!=(7,10,4):raise ValueError("app object multiplier changed")
    stride=struct.unpack(">h",struct.pack(">H",m&65535))[0]
    hi=check(0x816BD2CC,kind="immediate",writes=11)
    lo=check(0x816BD2D0,kind="register_offset",base=11,writes=26)
    initial=(hi["value"]+lo["value"])&0xffffffff
    add=check(0x816BD320,kind="register_offset",base=26,writes=11)
    sub=check(0x816BD328,kind="register_offset",base=11,writes=11)
    check(0x816BD330,kind="arithmetic",operation="subf",writes=30,inputs=[10,11])
    object_origin=(initial+add["value"]+sub["value"])&0xffffffff
    records=[]
    for offset in range(0,limit["value"],16):
        slot=addr+offset
        name,app_id,ptr,flags=(word(image,base,slot+j) for j in (0,4,8,12))
        text=read_name(image,base,name)
        location=("code" if executable(pe,base,ptr) else
                  "image_data" if base<=ptr<base+len(image) else "null" if not ptr else "outside_image")
        # The original code selects pointer-indirect registration with bit 3
        # and conditionally skips load depending on flags and mode. No
        # invented interpretation of the remaining bits.
        entry={"index":offset//16,"slot":hx(slot),"name":text,"name_pointer":hx(name),
               "app_id":app_id,"pointer":hx(ptr),"pointer_location":location,"flags":hx(flags),
               "pointer_indirect":bool(flags&8),"load_flag_bit0":bool(flags&1),"disabled_entry":not app_id}
        if app_id:
            entry["object_address"]=hx((object_origin-app_id*stride)&0xffffffff)
            if flags&8 and location=="image_data" and ptr+4<=base+len(image):
                target=word(image,base,ptr)
                entry["indirect_pointer_candidate"]=hx(target)
                entry["indirect_candidate_is_code"]=executable(pe,base,target)
        records.append(entry)
    return {"table":hx(addr),"record_bytes":16,"records":records,"object_multiplier":stride,
            "object_origin":hx(object_origin),"object_formula":"origin - id * signed multiplier"}

def loader_audit(image,base,pe,thunks,records,members):
    identities=[]
    def identity(name):
        if not name:return None
        leaf=name.replace("\\","/").rsplit("/",1)[-1].lower()
        member=members.get("$flash_"+leaf)
        if not member and "." not in leaf:member=members.get("$flash_"+leaf+".xex")
        if not member:return {"name":name,"present_in_original_flash":False}
        payload=member["payload"]
        if payload[:4]!=b"XEX2":return {"name":name,"present_in_original_flash":True,"xex":False}
        header=parse_xex(payload)
        return {"name":name,"present_in_original_flash":True,"xex":True,"source_sha256":sha(payload),
            "image_base":header["image_base"],"image_bytes":header["image_bytes"],"entry_point":header["entry_point"],
            "import_libraries":[i["library"] for i in header["imports"]]}
    for row in records:identities.append({"app_id":row["app_id"],"identity":identity(row["name"])})
    hi=operand(0x816BDF00,word(image,base,0x816BDF00))
    lo=operand(0x816BDF08,word(image,base,0x816BDF08))
    if hi.get("writes")!=11 or lo.get("writes")!=11 or lo.get("base")!=11:raise ValueError("original final loader path operands")
    addr=(hi["value"]+lo["value"])&0xffffffff
    sites=[]
    for pc,name in ((0x816BDF20,"XexLoadImage"),(0x816BCDC8,"XexLoadImage"),(0x8168B3DC,"XexLoadImageFromMemory")):
        b=branch(pc,word(image,base,pc))
        if not b or not b[1] or thunks.get(b[0],{}).get("name")!=name:raise ValueError("original app load import changed")
        sites.append({"site":hx(pc),"name":name,"thunk":hx(b[0])})
    tail=branch(0x816E0250,word(image,base,0x816E0250))
    if tail!=(0x816CECD8,False):raise ValueError("original shared tail changed")
    entries={a:n for a,n,_ in pe["functions"]}
    # This verified branch target is not necessarily a PDATA start.
    # Report its bounded instruction window without claiming a full function.
    containing=[a+size-tail[0] for a,size,_ in pe["functions"] if a<=tail[0]<a+size]
    limit=entries.get(tail[0],min(containing,default=128))
    body=bounded_entry(image,base,pe,tail[0],thunks,min(limit,512))
    if not body["operands"]:raise ValueError("empty original shared tail evidence")
    return {"app_flash_identity":identities,"final_load":identity(read_name(image,base,addr)),
            "loader_sites":sites,"shared_tail_body":body}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("build output only")
    members=parse(original("pirs"));raw=members["$flash_xam.xex"]["payload"]
    if sha(raw)!=EXPECTED["xam_17559"]:raise ValueError("original XAM hash mismatch")
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!=DIGESTS["xam"]:raise ValueError("original decoded XAM mismatch")
    base=meta["image_base"];pe=pe_info(image,base)
    catalog,stubs=sdk_catalog(a.sdk);thunks={}
    for r in imports(image,base,parse_xex(raw)):
        lib=library(r["library"]);ordinal=int(r["ordinal"],16);name,_=catalog.get((lib,ordinal),("","unknown"))
        for t in r["thunk_slots"]:thunks[t]={"name":name,"ordinal":r["ordinal"],"sdk_stub":name in stubs}
    result=app_table(image,base,pe)
    result["loaders"]=loader_audit(image,base,pe,thunks,result["records"],members)
    print("APP_TABLE",json.dumps(result["records"],sort_keys=True))
    print("APP_OBJECT_LAYOUT",result["object_origin"],result["object_multiplier"])
    print("APP_MODULES",json.dumps(result["loaders"]["app_flash_identity"],sort_keys=True))
    print("APP_FINAL_LOAD",json.dumps(result["loaders"]["final_load"],sort_keys=True))
    print("APP_SHARED_TAIL",json.dumps(result["loaders"]["shared_tail_body"]["operands"],sort_keys=True))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
