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

FRAMES=[0x816769D0,0x8167E760,0x8167E918,0x8167EB60,0x816B8B08,0x816B92C8,0x816B9668]
FAULT_PC=0x81676A3C
FRAME_PC_HINTS=[FAULT_PC,0x8167E7A8,0x8167E9D0,0x8167EC40,0x816B8B64,None,0x816B971C]
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
        if xo==824:
            return {"kind":"arithmetic_shift_right_immediate","writes":a,"source":r,"shift":b,"record":bool(w&1)}
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


def notification_gate(image,base,call_pc,negative_target,thunks):
    """Validate the original signed status test, not a reconstructed guest worker."""
    destination=branch(call_pc,read_word(image,base,call_pc))
    if not destination or not destination[1]:
        raise ValueError("storage gate is not a linked call")
    imp=thunks.get(destination[0])
    if not imp or imp["name"]!="DrvGetContentStorageNotification":
        raise ValueError("storage gate import changed")
    comparison=read_word(image,base,call_pc+4)
    if comparison>>26!=11 or ((comparison>>21)&31)!=0 or ((comparison>>16)&31)!=3 or (comparison&65535)!=0:
        raise ValueError("expected signed CR0 comparison of r3 against zero")
    detail=conditional_details(call_pc+8,read_word(image,base,call_pc+8))
    if not detail or detail["linked"] or detail["cr_test"] not in (
        {"field":0,"bit":"lt","sense":"set"},{"field":0,"bit":"lt","sense":"clear"}):
        raise ValueError("expected original signed status branch")
    branch_target=int(detail["target"],16)
    fallthrough=call_pc+12
    negative=branch_target if detail["cr_test"]["sense"]=="set" else fallthrough
    nonnegative=fallthrough if detail["cr_test"]["sense"]=="set" else branch_target
    if negative!=negative_target:
        raise ValueError("original failure edge changed")
    return {"call":hx(call_pc),"negative_status_target":hx(negative),
            "nonnegative_status_target":hx(nonnegative),
            "examples":[{"r3":hx(value),"next_pc":hx(negative if signed(value,32)<0 else nonnegative)}
                        for value in (0,0x7026FC30,0xC00000BB,0xC000000D)]}

def direct_tail_path(image,base,pe,start,target,max_depth=4):
    """Follow only unconditional non-link jumps to exact function entries."""
    entries={addr:size for addr,size,_ in pe["functions"]}
    if start not in entries or target not in entries:return None
    queue=[(start,[])]
    seen={start}
    for current,path in queue:
        if current==target:return path
        if len(path)>=max_depth:continue
        for pc in range(current,current+entries[current],4):
            dest=branch(pc,read_word(image,base,pc))
            if not dest or dest[1] or dest[0] not in entries or dest[0] in seen:continue
            seen.add(dest[0])
            queue.append((dest[0],path+[{"from":hx(current),"site":hx(pc),"to":hx(dest[0])}]))
    return None

def verified_device_stats_status(image,base,thunks):
    call=0x816F1908
    dest=branch(call,read_word(image,base,call))
    if not dest or not dest[1] or thunks.get(dest[0],{}).get("name")!="XInputdGetDeviceStats":
        raise ValueError("device stats call identity changed")
    shift=operand(call+4,read_word(image,base,call+4))
    immediate=operand(call+8,read_word(image,base,call+8))
    mask=operand(call+12,read_word(image,base,call+12))
    expected_shift={"kind":"arithmetic_shift_right_immediate","writes":11,"source":3,"shift":31,"record":False}
    if shift!=expected_shift or immediate.get("writes")!=10 or immediate.get("value")!=1167 or mask!={"kind":"logical","operation":"and","writes":3,"inputs":[11,10]}:
        raise ValueError("device stats status conversion changed: "+str([shift,immediate,mask]))
    return {"call":hx(call),"status_conversion":[shift,immediate,mask],
            "examples":[{"driver_r3":hx(value),"xam_result":1167 if signed(value,32)<0 else 0}
                        for value in (0,0x10000001,0xC000009D,0xC00000BB)]}

def verified_storage_fault_details(image,base,pe,thunks):
    gates=[notification_gate(image,base,pc,0x8167ED4C,thunks)
           for pc in (0x8167EB90,0x8167ED40)]
    # The return instruction in 8167E760 is immediately after 81679558,
    # not a direct call to the innermost unwind frame.
    site=0x8167E7A4
    dest=branch(site,read_word(image,base,site))
    if dest!=(0x81679558,True):raise ValueError("fault caller site changed")
    start=dest[0]
    if not executable(pe,base,start):raise ValueError("intermediary outside executable section")
    owners=[(a,size) for a,size,_ in pe["functions"] if a<=start<a+size]
    exact=len(owners)==1 and owners[0][0]==start
    # A direct branch target is known even when no PDATA entry covers it.
    # Inspect only a bounded prefix; do not invent a function boundary.
    following=min((a for a,_,_ in pe["functions"] if a>start),default=start+64)
    length=owners[0][1] if exact else min(64,following-start)
    while length and not executable(pe,base,start+length-4):length-=4
    ops=describe(image,base,start,length,thunks)
    first=branch(start,read_word(image,base,start))
    # This PDATA-free trampoline has an observed direct entry and a four-instruction bounded extent.
    # Record its exact final tail branch, without treating any following bytes as part of it.
    terminal=branch(start+length-4,read_word(image,base,start+length-4)) if length else None
    terminal_tail=None if not terminal or terminal[1] else {"site":hx(start+length-4),"target":hx(terminal[0])}
    return {"gates":gates,
            "caller_return_pc":"8167E7A8","caller_call_site":hx(site),
            "intermediate_entry":hx(start),"intermediate_operands":ops,
            "intermediate_pdata_owners":[{"entry":hx(a),"size":size} for a,size in owners],
            "intermediate_extent_verified":exact,
            "bounded_prefix_final_tail":terminal_tail,
            "intermediate_first_direct_branch":None if not first else {"target":hx(first[0]),"linked":first[1]},
            "intermediate_tail_path":direct_tail_path(image,base,pe,start,FRAMES[0]) if exact else None,
            "fault_load":operand(FAULT_PC,read_word(image,base,FAULT_PC))}


def startup_contract_inventory(image,base,pe,thunks):
    # Full bounded wrappers for navigation, text, statistics and initialization.
    # Record each actual kernel import call with its enclosing original range.
    names={"XInputdReadTextKeystroke","XInputdWriteState","XInputdNotify",
           "XInputdGetDeviceStats","XInputdGetCapabilities","XInputdReadState",
           "DrvSetContentStorageCallback","DrvGetContentStorageNotification",
           "XeKeysGetStatus","EtxProducerRegister","XexShimLock"}
    wanted={addr:meta for addr,meta in thunks.items() if meta["name"] in names}
    groups={}
    for start,length,_ in pe["functions"]:
        calls=[]
        for pc in range(start,start+length,4):
            target=branch(pc,read_word(image,base,pc))
            if target and target[1] and target[0] in wanted:
                calls.append({"site":hx(pc),"import":wanted[target[0]]})
        if not calls:continue
        records=[]
        for call in calls:
            pc=int(call["site"],16)
            ops=describe(image,base,max(start,pc-48),
                         min(start+length,pc+84)-max(start,pc-48),thunks)
            for row in ops:
                address=int(row["pc"],16)
                w=read_word(image,base,address)
                if w>>26==16:row.update(conditional_details(address,w))
                if w>>26 in (10,11):row["cr_field"]=(w>>23)&7
            records.append({**call,"nearby_operands":ops})
        short=length<=1024 and any(c["import"]["name"]!="EtxProducerRegister" for c in calls)
        groups[hx(start)]={"size":length,"calls":records,
                            "wrapper_operands":describe(image,base,start,length,thunks) if short else []}
    return {"function_groups":groups,"scope":"verified original operand metadata; no inferred hardware ABI"}


# Actual second native boot unwind, run 45944345779. The earlier storage
# worker fault is retained separately; do not conflate these crashes.
SECOND_FAULT=0x8169D068
SECOND_FRAMES=[(0x8169D060,SECOND_FAULT),(0x81696558,0x816965C4),
               (0x816B8B08,0x816B8B64),(0x816B92C8,None),(0x816B9668,0x816B971C)]
SECOND_LR={0x816B9830:"KeSetPriorityClassThread",0x816BA16C:"EtxProducerRegister",
           0x816969EC:"EtxProducerRegister",0x81696A0C:"HalGetPowerUpCause",
           0x81696A10:"XexShimLock",0x816E0D44:"XeKeysGetStatus"}

def bounded_entry(image,base,pe,addr,thunks,limit=256):
    if not executable(pe,base,addr):raise ValueError("nonexecutable observed entry "+hx(addr))
    exact=[s for a,s,_ in pe["functions"] if a==addr]
    containing=[{"entry":hx(a),"size":s} for a,s,_ in pe["functions"] if a<=addr<a+s]
    if len(exact)==1:
        length=min(exact[0],limit)
    else:
        following=min((a for a,_,_ in pe["functions"] if a>addr),default=addr+limit)
        length=min(limit,following-addr)
    while length and not executable(pe,base,addr+length-4):length-=4
    ops=describe(image,base,addr,length,thunks)
    for row in ops:
        pc=int(row["pc"],16)
        w=read_word(image,base,pc)
        if w>>26==16:row.update(conditional_details(pc,w))
        if w>>26 in (10,11):row["cr_field"]=(w>>23)&7
    return {"entry":hx(addr),"extent_verified":len(exact)==1,
            "pdata_owners":containing,"bounded_length":length,"operands":ops}

def second_fault_report(image,base,pe,thunks):
    frames=[{**bounded_entry(image,base,pe,addr,thunks,4096),"return_or_fault_pc":None if hint is None else hx(hint)}
            for addr,hint in SECOND_FRAMES]
    fault=operand(SECOND_FAULT,read_word(image,base,SECOND_FAULT))
    if fault.get("kind")!="memory_load" or fault.get("offset")!=0x274:
        raise ValueError("second crash instruction differs from observed guest address")
    # Enumerate actual direct callers of both innermost entries, including
    # tail branches and local call setup. No assumed name or ABI.
    incoming=[]
    for start,size,_ in pe["functions"]:
        for pc in range(start,start+size,4):
            dest=branch(pc,read_word(image,base,pc))
            if dest and dest[0] in (0x8169D060,0x81696558):
                lo=max(start,pc-48);hi=min(start+size,pc+32)
                incoming.append({"owner":hx(start),"site":hx(pc),"target":hx(dest[0]),
                                 "linked":dest[1],"operands":describe(image,base,lo,hi-lo,thunks)})
    # Inspect full original functions containing the observed startup calls,
    # not just their immediate return uses. LR trace may name a tail wrapper.
    related={}
    for lr,name in SECOND_LR.items():
        start,size=owner(pe,lr-4)
        related.setdefault(hx(start),bounded_entry(image,base,pe,start,thunks,4096))
    # Direct tail wrappers can lack PDATA. Capture them from the actual
    # call target rather than inventing boundaries or assuming a function.
    targets=set()
    for start in related.values():
        for row in start["operands"]:
            if row.get("kind")=="branch" and row.get("linked") and "import" not in row:
                target=int(row["target"],16)
                if executable(pe,base,target):targets.add(target)
    wrappers=[bounded_entry(image,base,pe,a,thunks,96) for a in sorted(targets)]
    return {"source_run":45944345779,"guest_fault_address":"00000274","fault_pc":hx(SECOND_FAULT),
            "fault_operand":fault,"unwind_functions":frames,"direct_incoming_edges":incoming,
            "related_startup_functions":related,"direct_call_target_prefixes":wrappers}

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
    for addr,hint in zip(FRAMES,FRAME_PC_HINTS):
        start,length=owner(pe,addr)
        if start!=addr:raise ValueError("unwind symbol is interior")
        ops=describe(image,base,start,length,thunks)
        if hint is not None and not start<=hint<start+length:
            raise ValueError("line-table candidate outside original function")
        functions.append({"entry":hx(start),"size":length,
                          "pc_hint":None if hint is None else hx(hint),
                          "pc_operand":None if hint is None else operand(hint,read_word(image,base,hint)),
                          "calls":[op for op in ops if op["kind"] in ("branch","indirect_branch") and op.get("linked")],
                          "first_memory_accesses":[op for op in ops if "memory_" in op["kind"] or op["kind"]=="indexed_load"][:20],
                          "operands":ops})
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
    report={"source_run":45942627248,"fault_guest_address":"00000000",
            "fault_pc_candidate":hx(FAULT_PC),
            "supersedes_uncorrected_symbolization_run":45935812586,
            "scope":"static operand and direct-call evidence; no dynamic fault operand claimed",
            "unwind_functions":functions,"adjacent_unwind_edges":edges,
            "binding_callback_operands":binding_ops,
            "observed_startup_stubs":observed_storage_report(image,base,pe,thunks),
            "verified_storage_fault_details":verified_storage_fault_details(image,base,pe,thunks),
            "verified_device_stats_status":verified_device_stats_status(image,base,thunks),
            "startup_contract_inventory":startup_contract_inventory(image,base,pe,thunks),
            "second_native_fault":second_fault_report(image,base,pe,thunks)}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("fault function operands:",json.dumps(functions[0]["operands"],sort_keys=True))
    print("fault and unwind instruction candidates:",json.dumps([{k:v for k,v in x.items() if k in ("entry","pc_hint","pc_operand")} for x in functions],sort_keys=True))
    print("confirmed direct edges:",json.dumps([{k:v if k!="direct_sites" else [x["site"] for x in v] for k,v in e.items()} for e in edges]))
    print("second native fault:",json.dumps({k:v for k,v in report["second_native_fault"].items() if k in ("source_run","guest_fault_address","fault_pc","fault_operand")},sort_keys=True))
    print("startup contract wrappers:",len(report["startup_contract_inventory"]["function_groups"]))
    print("device stats status conversion:",json.dumps(report["verified_device_stats_status"],sort_keys=True))
    print("storage fault gates:",json.dumps(report["verified_storage_fault_details"],sort_keys=True))
    print("binding callback:",json.dumps(binding_ops,sort_keys=True))
    print("observed startup calls:",json.dumps([{k:v for k,v in x.items() if k!="operand_window"} for x in report["observed_startup_stubs"]["observed_calls"]],sort_keys=True))
if __name__=="__main__":main()
