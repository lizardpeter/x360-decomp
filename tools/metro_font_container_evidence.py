#!/usr/bin/env python3
"""Audit the original local font containers without exporting any font bytes."""
import argparse
import hashlib
import json
import struct
from pathlib import Path
from fetch_originals import ROOT,config
from prepare_recompilation import original
from pirs import parse
from stage_dashboard_runtime import acquire_font_complements,verify_members

SFNT={b"\x00\x01\x00\x00",b"OTTO",b"true",b"typ1"}
TAGS={b"head",b"maxp",b"cmap",b"name",b"glyf",b"loca",b"hhea",b"hmtx",b"CFF ",b"CFF2",b"OS/2",b"GSUB",b"GPOS"}
def u16(d,a):
    return struct.unpack_from(">H",d,a)[0]
def u32(d,a):
    return struct.unpack_from(">I",d,a)[0]
def sfnt(data,offset):
    if offset<0 or offset>len(data)-12 or data[offset:offset+4] not in SFNT:return None
    count=u16(data,offset+4)
    if not 1<=count<=128 or offset+12+count*16>len(data):return None
    tables={}
    for i in range(count):
        p=offset+12+i*16
        tag,checksum,start,size=struct.unpack_from(">4sIII",data,p)
        if any(c<32 or c>126 for c in tag) or tag in tables or start>len(data) or size>len(data)-start:return None
        tables[tag]={"offset":start,"bytes":size}
    if not {b"head",b"cmap",b"maxp"}<=tables.keys():return None
    maxp=tables[b"maxp"]
    head=tables[b"head"]
    if maxp["bytes"]<6 or head["bytes"]<54 or u32(data,head["offset"]+12)!=0x5F0F3CF5:return None
    return {"offset":offset,"format":"opentype_cff" if data[offset:offset+4]==b"OTTO" else "sfnt",
            "tables":{k.decode():v for k,v in tables.items() if k in TAGS},
            "table_count":count,"glyph_count":u16(data,maxp["offset"]+4),
            "units_per_em":u16(data,head["offset"]+18)}
def inspect(data):
    result={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),"format":"unclassified",
            "faces":[],"embedded_sfnt_offsets":[]}
    if data[:4]==b"ttcf" and len(data)>=12:
        n=u32(data,8)
        if 0<n<=128 and 12+4*n<=len(data):
            faces=[sfnt(data,u32(data,12+i*4)) for i in range(n)]
            if all(faces):
                result["format"]="truetype_collection";result["faces"]=faces
    elif face:=sfnt(data,0):
        result["format"]=face["format"];result["faces"]=[face]
    if not result["faces"]:
        # A magic value alone is not a face. Require a complete bounded table
        # directory and the actual head magic before reporting an embedded face.
        for magic in SFNT:
            start=0
            while (off:=data.find(magic,start))>=0:
                start=off+1
                if sfnt(data,off):result["embedded_sfnt_offsets"].append(off)
        result["embedded_sfnt_offsets"]=sorted(set(result["embedded_sfnt_offsets"]))
        # Only report printable four-character container magic, never a dump.
        result["container_magic"]=data[:4].decode("ascii") if all(32<=b<127 for b in data[:4]) else "nonprintable"
    return result
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    members=parse(original("pirs"))
    census=json.loads((ROOT/"analysis/pirs_17559/members.json").read_text())
    verify_members(members,census)
    directory=acquire_font_complements(ROOT/"build/metro-font-format-inputs",config())
    fonts={"SegoeXbox-Light.xtt":members["$flash_SegoeXbox-Light.xtt"]["payload"]}
    for spec in config().get("local_resource",[]):fonts[spec["name"]]=(directory/spec["name"]).read_bytes()
    report={"fonts":{name:inspect(data) for name,data in sorted(fonts.items())},
            "scope":"Verified source identity and bounded container metadata; no font payload or glyph data."}
    for name,r in report["fonts"].items():
        print(name,r["bytes"],r["format"],"faces",len(r["faces"]),"embedded",r["embedded_sfnt_offsets"],r.get("container_magic",""))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
