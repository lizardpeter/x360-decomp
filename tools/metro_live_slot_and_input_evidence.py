#!/usr/bin/env python3
"""Check failed live relocations and the 17559 input binding ABI against originals.

Only address metadata, decoded operand descriptions, and classifications are
written. Never write a decoded image, function body, or executable bytes.
"""
import argparse
import json
import struct
from pathlib import Path
from analyze_decoded import pe_info, imports
from decode_image import decode
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from xex import parse as parse_xex
from metro_import_contracts import DIGESTS, branch, setup, registers, signed, hx

# Exact failed rows from 45936491530; no relocation is attempted here.
FAILED = {
    0x25A:(0x920004D0,0x9293A22C,0x90368207,1),
    0x269:(0x920004D4,0x9293A23C,0x467F0000,1),
    0x2D1:(0x920006E0,0x9293ABDC,0x609DEE06,1),
    0x580:(0x92000A84,0x9293BA6C,0x467F0000,1),
    0x581:(0x92000A80,0x9293BA5C,0x60CE5807,1),
    0x6A4:(0x920006E4,0x9293ABEC,0x467F0000,1),
    0x8E2:(0x920008DC,0x9293B3CC,0,0),
}
CALLBACK_SITE=0x81696914
CALLBACK_THUNK=0x81A72984
CALLBACK_CANDIDATE=0x816D9060
INPUT_SITES={
    "DrvSetUserBindingCallback":[CALLBACK_SITE],
    "XInputdGetCapabilities":[0x816F1348],
    "XInputdReadState":[0x816F15F8,0x816F28E8],
    "XInputdWriteState":[0x816F17A8],
    "XInputdNotify":[0x816DA7C0,0x816F1828],
    "XInputdReadTextKeystroke":[0x816F1E44],
}
def read_word(image,base,pc):
    if pc&3 or not base<=pc<=base+len(image)-4:raise ValueError("word out of image")
    return struct.unpack_from(">I",image,pc-base)[0]

def slot_evidence(image,base,rows):
    out=[]
    for ordinal,(slot,thunk,live,records) in FAILED.items():
        matches=[r for r in rows if r["library"].lower()=="xam.xex" and int(r["ordinal"],16)==ordinal]
        if len(matches)!=1 or matches[0]["value_slots"]!=[slot] or matches[0]["thunk_slots"]!=[thunk]:
            raise ValueError("original binding identity changed: "+hex(ordinal))
        raw=read_word(image,base,slot)
        if raw>>24!=0 or raw&65535!=ordinal:raise ValueError("original value record not a descriptor")
        out.append({"ordinal":f"{ordinal:04X}","slot":hx(slot),"thunk":hx(thunk),
            "original_descriptor":hx(raw),"observed_live":hx(live),
            "live_metadata_matches":records,"live_value_equals_original":live==raw,
            "classification":"missing_live_metadata" if not records else "live_word_diverged"})
    return out

def executable(pe,base,pc):
    return any(s["flags"]&0x20000000 and base+s["rva"]<=pc and pc+4<=base+s["rva"]+s["loaded_bytes"] for s in pe["sections"])

def local_values(image,base,start,end):
    """Conservative local literal propagation; reset on unrecognized effects."""
    known={}
    for pc in range(start,end,4):
        w=read_word(image,base,pc);op=w>>26
        if op in (16,17,18,19):
            known.clear()
            continue
        desc=setup(w)
        if desc:
            dst,expr=desc
            kind=expr["kind"]
            value=None
            if kind=="immediate":value=expr["value"]
            elif kind=="register_offset" and expr["base"] in known:value=known[expr["base"]]+expr["value"]
            elif kind=="or_immediate" and expr["source"] in known:value=known[expr["source"]]|expr["value"]
            elif kind=="register_copy":value=known.get(expr["source"])
            if value is None:known.pop(dst,None)
            else:known[dst]=value&0xffffffff
        elif op in (36,38,44,62) and (op!=62 or w&3==0):
            pass # recognized non-updating stores do not write a GPR
        else:
            known.clear()
    return known

def owner(pe,pc):
    matches=[(a,s) for a,s,_ in pe["functions"] if a<=pc<a+s]
    if len(matches)!=1:raise ValueError("ambiguous input call owner "+hx(pc))
    return matches[0]

def operand_window(image,base,pe,site):
    a,size=owner(pe,site)
    w=read_word(image,base,site)
    target=branch(site,w)
    if not target or not target[1]:raise ValueError("expected direct input call "+hx(site))
    before=[];after=[]
    for pc in range(max(a,site-48),min(a+size,site+64),4):
        if pc==site:continue
        ins=read_word(image,base,pc);op=ins>>26;r,ra,b=registers(ins)
        d=setup(ins)
        row={"address":hx(pc)}
        if d:
            dst,expr=d;row.update({"writes_gpr":dst,**expr})
        elif op in (36,38,44,62):
            row.update({"kind":"memory_store","source":r,"base":ra,
                        "offset":signed(ins&65535,16)&(~3 if op==62 else -1),
                        "width":{36:4,38:1,44:2,62:8}[op]})
        elif op in (10,11):
            row.update({"kind":"compare_immediate","source":ra,"value":signed(ins&65535,16)})
        elif op==16:
            row.update({"kind":"conditional_branch","target":hx(((0 if ins&2 else pc)+signed(ins&0xfffc,16))&0xffffffff)})
        elif branch(pc,ins):
            dest,linked=branch(pc,ins);row.update({"kind":"direct_branch","target":hx(dest),"linked":linked})
        else:row["kind"]="unclassified"
        (before if pc<site else after).append(row)
    return {"site":hx(site),"owner":hx(a),"target":hx(target[0]),"before":before,"after":after}

def analyze(dash,di,draw,xam,xi,xraw):
    dp=pe_info(dash,di["image_base"])
    xp=pe_info(xam,xi["image_base"])
    base=xi["image_base"]
    drows=imports(dash,di["image_base"],parse_xex(draw))
    xrows=imports(xam,base,parse_xex(xraw))
    callbacks={}
    for name,sites in INPUT_SITES.items():
        callbacks[name]=[operand_window(xam,base,xp,s) for s in sites]
    if branch(CALLBACK_SITE,read_word(xam,base,CALLBACK_SITE))!=(CALLBACK_THUNK,True):
        raise ValueError("binding callback import call changed")
    start,_=owner(xp,CALLBACK_SITE)
    known=local_values(xam,base,start,CALLBACK_SITE)
    target=known.get(3)
    # The nearby r11 producer can be separated by unrelated instructions.
    # In that case report the candidate as unconfirmed, not a verified entry.
    confirmed=target==CALLBACK_CANDIDATE and executable(xp,base,target)
    return {"scope":"static original evidence only; no guest callback invoked",
        "failed_relocations":slot_evidence(dash,di["image_base"],drows),
        "input_calls":callbacks,
        "binding_callback":{"call_site":hx(CALLBACK_SITE),"candidate":hx(CALLBACK_CANDIDATE),
            "locally_proven_r3":None if target is None else hx(target),
            "candidate_executable":executable(xp,base,CALLBACK_CANDIDATE),
            "verified_entry_candidate":confirmed},
        "input_imports":[{"ordinal":r["ordinal"],"thunks":[hx(a) for a in r["thunk_slots"]]}
            for r in xrows if int(r["ordinal"],16) in (0x20D,0x1E5,0x1E6,0x1E7,0x1E8,0x277)]}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):p.error("write under build/")
    draw=original("dash_basic")
    xraw=parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xraw)!=EXPECTED["xam_17559"]:raise ValueError("XAM identity")
    dash,di=decode(draw);xam,xi=decode(xraw,a.lzx.resolve())
    if di["sha256"]!=DIGESTS["dash"] or xi["sha256"]!=DIGESTS["xam"]:raise ValueError("decoded image identity")
    result=analyze(dash,di,draw,xam,xi,xraw)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"failed_relocations":result["failed_relocations"],"binding_callback":result["binding_callback"]},indent=2))
if __name__=="__main__":main()
