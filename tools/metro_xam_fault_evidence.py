#!/usr/bin/env python3
"""Recover the exact static call and memory-access evidence behind the first native XAM crash.

Addresses are from the symbolized unwind, not the less reliable stack scan.
The JSON contains decoded operand descriptions and import names, not raw
firmware bytes or a decompiled original function.
"""
import argparse
import json
from pathlib import Path
from analyze_decoded import pe_info, imports
from decode_image import decode
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from xex import parse as parse_xex
from metro_import_contracts import DIGESTS, branch, setup, registers, signed, hx, sdk_catalog, library
from metro_live_slot_and_input_evidence import read_word, owner, operand_window, executable

FRAMES=[0x81671250,0x81673B28,0x81673260,0x81675950,0x816A5AF8,0x816AE930,0x816AD998]
BINDING=0x816D9060

def operand(pc,w):
    op=w>>26
    r,a,b=registers(w)
    d=setup(w)
    if d:
        dst,desc=d
        return {"kind":desc["kind"],"writes":dst,**{k:v for k,v in desc.items() if k!="kind"}}
    if op in (36,37,38,39,44,45,46,47,52,54,62):
        return {"kind":"memory_store","source":r,"base":a,
                "offset":signed(w&65535,16)&(~3 if op==62 else -1),"update":op in (37,39,45) or op==62 and w&3==1,
                "width":{36:4,37:4,38:1,39:1,44:2,45:2,46:4,47:4,52:4,54:8,62:8}[op]}
    if op in (10,11):
        return {"kind":"compare_immediate","register":a,"value":signed(w&65535,16),"unsigned":op==10}
    if op==16:
        return {"kind":"conditional_branch","target":hx(((0 if w&2 else pc)+signed(w&0xfffc,16))&0xffffffff)}
    dest=branch(pc,w)
    if dest:
        return {"kind":"branch","target":hx(dest[0]),"linked":dest[1]}
    if w==0x4e800020:
        return {"kind":"return"}
    if op==19 and (w>>1)&1023 in (16,528):
        return {"kind":"indirect_branch","via":"lr" if (w>>1)&1023==16 else "ctr","linked":bool(w&1)}
    if op==31:
        xo=(w>>1)&1023
        if xo in (23,55,87,119,279,311,343,375,21,53):
            return {"kind":"indexed_load","writes":r,"base":a,"index":b,
                    "width":{23:4,55:4,87:1,119:1,279:2,311:2,343:2,375:2,21:8,53:8}[xo]}
        if xo in (151,183,215,247,407,439,149,181):
            return {"kind":"indexed_store","source":r,"base":a,"index":b,
                    "width":{151:4,183:4,215:1,247:1,407:2,439:2,149:8,181:8}[xo]}
        if xo in (266,40,8):
            return {"kind":"arithmetic","operation":{266:"add",40:"subf",8:"subfc"}[xo],"writes":r,"inputs":[a,b]}
        if xo in (0,32):
            return {"kind":"compare_register","inputs":[a,b]}
        if xo in (28,444,316):
            return {"kind":"logical","operation":{28:"and",444:"or",316:"xor"}[xo],"writes":a,"inputs":[r,b]}
        if xo in (339,467):
            spr=((w>>16)&31)|(((w>>11)&31)<<5)
            return {"kind":"special_register","operation":"read" if xo==339 else "write","register":r,"spr":spr}
    if op in (20,21,23):
        return {"kind":"rotate_mask","writes":a,"source":r,"shift_or_reg":b,
                "mask_start":(w>>6)&31,"mask_end":(w>>1)&31}
    return {"kind":"unclassified","primary":op}

def describe(image,base,start,length,thunks):
    result=[]
    for pc in range(start,start+length,4):
        w=read_word(image,base,pc)
        d=operand(pc,w)
        target=branch(pc,w)
        if target and target[0] in thunks:
            d["import"]=thunks[target[0]]
        result.append({"pc":hx(pc),**d})
    return result


# Actual stub trace from run 45941380448. LR is a runtime return address,
# not necessarily the address of a direct import branch: tail wrappers retain LR.
OBSERVED_LR = {
    0x8167EB94:"DrvGetContentStorageNotification",
    0x8167EE38:"DrvSetContentStorageCallback",
    0x816969EC:"EtxProducerRegister",
    0x81696A0C:"HalGetPowerUpCause",
    0x81696A10:"XexShimLock",
    0x816E0D44:"XeKeysGetStatus",
    0x816F190C:"XInputdGetDeviceStats",
    0x816D8F34:"XInputdSetRingOfLight",
}

def conditional_details(pc,w):
    if w>>26!=16:return None
    bo=(w>>21)&31;bi=(w>>16)&31
    # Only the simple CR-only forms support an unambiguous tested CR bit.
    tested = {"field":bi//4,"bit":("lt","gt","eq","so")[bi%4],
              "sense":"set" if bo&8 else "clear"} if bo&4 and not bo&16 else None
    return {"target":hx(((0 if w&2 else pc)+signed(w&0xfffc,16))&0xffffffff),
            "bo":bo,"bi":bi,"linked":bool(w&1),"cr_test":tested}

def observed_call(image,base,pe,lr,name,thunks):
    site=lr-4
    start,size=owner(pe,site)
    op=read_word(image,base,site)
    dest=branch(site,op)
    chain=[]
    target=dest[0] if dest and dest[1] else None
    # Follow only proven, unconditional, nonlinked one-instruction jumps.
    # An arbitrary wrapper is reported as unresolved, not guessed.
    visited=set()
    while target is not None and target not in thunks and len(chain)<8:
        if target in visited or not executable(pe,base,target):break
        visited.add(target)
        next_dest=branch(target,read_word(image,base,target))
        if not next_dest or next_dest[1]:break
        chain.append({"from":hx(target),"to":hx(next_dest[0])})
        target=next_dest[0]
    imp=thunks.get(target)
    classification=("direct_or_tail_match" if imp and imp["name"]==name else
                    "different_import" if imp else "unresolved_wrapper_or_indirect")
    # Bounded full-function operand report only, not raw code bytes.
    # Include each conditional edge and CR bit rather than interpreting it
    # as status success/failure without the original API contract.
    window=[]
    for pc in range(max(start,site-64),min(start+size,site+100),4):
        w=read_word(image,base,pc)
        row=operand(pc,w)
        if w>>26==16:row.update(conditional_details(pc,w))
        if w>>26 in (10,11):
            row["cr_field"]=(w>>23)&7
            row["value"]=(w&65535) if w>>26==10 else signed(w&65535,16)
        window.append({"pc":hx(pc),**row})
    return {"observed_export":name,"lr":hx(lr),"site":hx(site),
            "function":hx(start),"function_size":size,
            "first_target":hx(dest[0]) if dest else None,
            "tail_chain":chain,"resolved_import":imp,
            "classification":classification,"operand_window":window}

def observed_storage_report(image,base,pe,thunks):
    observed=[observed_call(image,base,pe,lr,name,thunks)
              for lr,name in OBSERVED_LR.items()]
    # Include both original notification call sites, including the second
    # polling iteration not necessarily reached before the live crash.
    storage=[]
    for start,size in [(0x8167EB60,owner(pe,0x8167EB60)[1]),
                       (0x8167ED90,owner(pe,0x8167ED90)[1])]:
        if owner(pe,start)[0]!=start:raise ValueError("storage owner mismatch")
        ops=describe(image,base,start,size,thunks)
        for row in ops:
            pc=int(row["pc"],16)
            w=read_word(image,base,pc)
            if w>>26==16:row.update(conditional_details(pc,w))
            if w>>26 in (10,11):
                row["cr_field"]=(w>>23)&7
                row["value"]=(w&65535) if w>>26==10 else signed(w&65535,16)
        storage.append({"entry":hx(start),"size":size,"operands":ops})
    return {"source_run":45941380448,
            "scope":"observed LR and original static operand/branch evidence; no inferred ABI or guest execution",
            "observed_calls":observed,"storage_worker_and_registration":storage}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):p.error("write only under build/")
    raw=parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(raw)!=EXPECTED["xam_17559"]:raise ValueError("XAM source identity")
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!=DIGESTS["xam"]:raise ValueError("decoded identity")
    base=meta["image_base"]
    pe=pe_info(image,base)
    catalog,stubs=sdk_catalog(a.sdk)
    thunks={}
    for row in imports(image,base,parse_xex(raw)):
        ordinal=int(row["ordinal"],16)
        lib=library(row["library"])
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for addr in row["thunk_slots"]:
            thunks[addr]={"library":lib,"ordinal":f"{ordinal:04X}","name":name,"sdk_stub":name in stubs}
    functions=[]
    for addr in FRAMES:
        start,length=owner(pe,addr)
        if start!=addr:raise ValueError("unwind symbol is interior")
        ops=describe(image,base,start,length,thunks)
        functions.append({"entry":hx(start),"size":length,
                          "calls":[op for op in ops if op["kind"] in ("branch","indirect_branch") and op.get("linked")],
                          "first_memory_accesses":[op for op in ops if "memory_" in op["kind"] or op["kind"]=="indexed_load"][:20],
                          "operands":ops if addr==FRAMES[0] else []})
    edges=[]
    for inner,outer in zip(FRAMES,FRAMES[1:]):
        start,length=owner(pe,outer)
        sites=[pc for pc in range(start,start+length,4) if branch(pc,read_word(image,base,pc))==(inner,True)]
        edges.append({"caller":hx(outer),"callee":hx(inner),
                      "direct_sites":[operand_window(image,base,pe,pc) for pc in sites]})
    # The exact address-taken callback is in the gap after a PDATA function.
    if not executable(pe,base,BINDING):raise ValueError("binding callback outside code")
    following=min(addr for addr,_,_ in pe["functions"] if addr>BINDING)
    if following-BINDING>256:raise ValueError("callback extent must remain bounded")
    binding_ops=describe(image,base,BINDING,following-BINDING,thunks)
    report={"source_run":45935812586,"fault_guest_address":"00000000",
            "scope":"static operand and direct-call evidence; no dynamic fault operand claimed",
            "unwind_functions":functions,"adjacent_unwind_edges":edges,
            "binding_callback_operands":binding_ops,
            "observed_startup_stubs":observed_storage_report(image,base,pe,thunks)}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("fault function operands:",json.dumps(functions[0]["operands"],sort_keys=True))
    print("confirmed direct edges:",json.dumps([{k:v if k!="direct_sites" else [x["site"] for x in v] for k,v in e.items()} for e in edges]))
    print("binding callback:",json.dumps(binding_ops,sort_keys=True))
    print("observed startup calls:",json.dumps([{k:v for k,v in x.items() if k!="operand_window"} for x in report["observed_startup_stubs"]["observed_calls"]],sort_keys=True))
if __name__=="__main__":main()
