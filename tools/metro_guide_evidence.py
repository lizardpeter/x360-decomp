#!/usr/bin/env python3
"""Original Metro Guide/HUD lifecycle and system-request callback evidence."""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info,ordinal_exports
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context,variable_reference,registers
from metro_xam_fault_evidence import bounded_entry,operand
from metro_profile_evidence import linear_export_extent
from metro_stfs_abi_evidence import flow,render
from metro_live_slot_and_input_evidence import executable
from metro_ui_font_graph import forward
from metro_ui_startup_evidence import ancestors
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,sha,original
from stage_metro_xam_aot import HUD_SHA
from xex import parse as parse_xex

GUIDE_EXPORTS={"XamShowGuideUI":0x816C3580,"XamInputSendXenonButtonPress":0x816F2E60,
 "XamIsGuideDisabled":0x816E16F0,"XamSetHudContext":0x816E1768,
 "XamGetHudContext":0x816E1778,"XamOverrideHudOpenType":0x81692418,
 "XamHudGetUserIndex":0x81692440,"XamHudSetUserIndex":0x81693B28,
 "XamInputGetState":0x816F14E8,"XamInputGetKeystrokeHud":0x816F4AE0,
 "XamInputGetKeystrokeHudEx":0x816F4C78}
SYSREQ_OWNERS={0x816F0368,0x816F0410,0x816F0AE0,0x816F0DF0}
INPUT_OWNERS={0x816F14E8,0x816F28A8,0x816F19C0,0x816F2A70,0x816F2B98,
 0x816F2C50,0x816F2D88,0x816DA550,0x816F17E0,0x81696068,0x816D9060,0x816F06E8,0x816F0E70,0x816F3C48,0x816D8AA8,0x816F0400,0x816F0DE0,0x816C7D78,0x816CAF08,0x816E16E0,0x816C2AF0,0x81696AF0,0x816CE8B0,0x816F0F28,0x816968A8,0x816F4088}
KERNEL={"DrvSetSysReqCallback","DrvSetUserBindingCallback","XInputdReadState",
 "XInputdRawState","XInputdNotify","XInputdGetCapabilities"}
UI={"XamShowGuideUI","XamInputSendXenonButtonPress","XamIsGuideDisabled",
 "XamSetHudContext","XamGetHudContext","XamOverrideHudOpenType","XamHudGetUserIndex",
 "XamHudSetUserIndex","XamInputGetKeystrokeHud","XamInputGetKeystrokeHudEx",
 "XamShowSigninUI","XamShowSigninUIEx","XamShowSigninUIp"}

def body_words(image,base,a,n):
    return [w for w, in struct.iter_unpack(">I",image[a-base:a-base+n])]

def literal_mask(w):
    op=w>>26
    if op in (24,25,26,27,28,29):
        mask=(w&65535)<<(16 if op in (25,27,29) else 0)
        if mask==0x400:return {"kind":"literal_0400","primary":op}
    if op in (20,21):
        mb,me=(w>>6)&31,(w>>1)&31
        shift=(w>>11)&31
        if mb==me and ((31-mb-shift)%32)==10:
            return {"kind":"single_original_bit_10","shift":shift,"mask_start":mb,"mask_end":me}
    return None

def scan(label,raw,image,meta,catalog,stubs):
    base=meta["image_base"];pe=pe_info(image,base);thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);o=int(row["ordinal"],16)
        n,_=catalog.get((lib,o),("", "unknown"))
        for a in row["thunk_slots"]:thunks[a]={"name":n,"library":lib,"ordinal":f"{o:04X}","sdk_stub":n in stubs}
    funcs={a:n for a,n,_ in pe["functions"]}
    exports={}
    if label=="xam":
        for o,a in ordinal_exports(image,base,raw):
            name,_=catalog.get(("xam",o),("", "unknown"))
            if name in GUIDE_EXPORTS:exports[name]=a
        if exports!=GUIDE_EXPORTS:raise ValueError("original Guide export join differs")
        for a in exports.values():
            if a not in funcs and (extent:=linear_export_extent(image,base,pe,a)):
                funcs[a]=extent[0]
    # Include exact bounded tail wrappers for the observed callback dispatch
    # and startup path. These are not promoted to PDATA.
    if label=="xam":
        for a in INPUT_OWNERS:
            if a not in funcs and (extent:=linear_export_extent(image,base,pe,a)):
                funcs[a]=extent[0]
    inbound=collections.defaultdict(set);outbound=collections.defaultdict(set)
    by_owner=collections.defaultdict(list);call_sites=[];pointer_refs=[]
    roots=set(exports.values()) if label=="xam" else set()
    if label=="xam":roots|=SYSREQ_OWNERS|INPUT_OWNERS
    for a,n in sorted(funcs.items()):
        words=body_words(image,base,a,n)
        for i,w in enumerate(words):
            pc=a+4*i;dest=branch(pc,w)
            if dest:
                target,linked=dest
                if target in funcs and target!=a:
                    inbound[target].add((a,pc,linked))
                    outbound[a].add((target,pc,linked))
                imp=thunks.get(target)
                if imp and (imp["name"] in KERNEL|UI or
                            imp["name"] in {"XexLoadImage","XexUnloadImage","XexGetProcedureAddress"} and label=="hud"):
                    item={"owner":hx(a),"site":hx(pc),"target":hx(target),"linked":linked,"import":imp,**context(words,i,linked)}
                    call_sites.append(item);by_owner[a].append(item)
                    if imp["name"] in {"DrvSetSysReqCallback","XInputdNotify"}|UI:
                        roots.add(a)
            if i and label=="xam":
                ref=variable_reference(words[i-1],w)
                if ref and ref[0] in exports.values():
                    pointer_refs.append({"owner":hx(a),"site":hx(pc-4),"target":hx(ref[0]),"kind":ref[1]})
                    roots.add(a)
    if label=="xam":
        actual={int(c["owner"],16) for c in call_sites if c["import"]["name"]=="DrvSetSysReqCallback"}
        if actual!=SYSREQ_OWNERS:raise ValueError("system request owner set differs")
    # Capture registration arguments, callback candidate references, and full
    # exact owners. Non-PDATA export wrappers remain explicitly bounded.
    callbacks=[];extra=set();mask_sites=[]
    for a in sorted(roots):
        if a not in funcs:continue
        words=body_words(image,base,a,funcs[a])
        _,states=flow(words,a)
        for c in by_owner[a]:
            if c["import"]["name"] not in KERNEL:continue
            pc=int(c["site"],16);regs=states.get(pc,({},{}))[0]
            c["argument_provenance"]={f"r{k}":render(regs.get(k)) for k in range(3,9)}
            # Local address materialization may survive a conservative CFG
            # loss; keep candidates separate, never call them based on this.
            if c["import"]["name"]=="DrvSetSysReqCallback":
                candidates=[]
                i=(pc-a)//4
                for j in range(max(1,i-24),i):
                    ref=variable_reference(words[j-1],words[j])
                    if ref and ref[1]=="address_construction" and executable(pe,base,ref[0]):
                        candidates.append({"site":hx(a+4*(j-1)),"candidate":hx(ref[0])})
                        extra.add(ref[0])
                for k in range(3,9):
                    v=regs.get(k)
                    if v and v[0]=="const" and executable(pe,base,v[1]):
                        extra.add(v[1])
                callbacks.append({**c,"nearby_code_address_constructions":candidates})
        for i,w in enumerate(words):
            m=literal_mask(w)
            if m:mask_sites.append({"owner":hx(a),"site":hx(a+i*4),**m})
    roots|=extra
    lifecycle_refs=[]
    data_refs=[]
    if label=="xam":
        targets=SYSREQ_OWNERS|extra|{0x816F0E70,0x816F0DE0,0x816F0AE0,0x816F3C48,0x816F0400,0x816F0F28,0x816CE8B0}
        global_slots={0x81AAC260,0x81AAC264}
        # A constructor may be reached from a callback table, not via bl.
        # Find exact data words and original code materializations separately.
        for sec in pe["sections"]:
            if sec["flags"]&0x20000000:continue
            lo=sec["rva"];hi=lo+sec["loaded_bytes"]
            for off in range(lo,hi-3,4):
                w=struct.unpack_from(">I",image,off)[0]
                if w in targets:
                    data_refs.append({"slot":hx(base+off),"target":hx(w),"section":sec["name"],
                      "neighbor_pointer_candidates":[{"slot":hx(base+j),"target":hx(v)}
                       for j in range(max(lo,off-24),min(hi-3,off+28),4)
                       if executable(pe,base,(v:=struct.unpack_from(">I",image,j)[0]))]})
        slot_targets={int(r["slot"],16) for r in data_refs}
        for a,n in sorted(funcs.items()):
            words=body_words(image,base,a,n)
            for i in range(1,len(words)):
                ref=variable_reference(words[i-1],words[i])
                if ref and ref[0] in targets|global_slots|slot_targets:
                    lifecycle_refs.append({"owner":hx(a),"pc":hx(a+4*(i-1)),"address":hx(ref[0]),"kind":ref[1]})
                    roots.add(a)
        # Explicitly identify original callers (including non-PDATA direct
        # branches) of the selected entrypoints; bounded owner evidence only.
        for sec in pe["sections"]:
            if not sec["flags"]&0x20000000:continue
            lo=sec["rva"];hi=lo+sec["loaded_bytes"]
            for off in range(lo,hi-3,4):
                w=struct.unpack_from(">I",image,off)[0]
                b=branch(base+off,w)
                if not b or b[0] not in targets:continue
                owners=[a for a,n,_ in pe["functions"] if a<=base+off<a+n]
                if len(owners)==1:
                    roots.add(owners[0])
                    lifecycle_refs.append({"owner":hx(owners[0]),"pc":hx(base+off),
                                           "address":hx(b[0]),"kind":"direct_branch"})
                else:lifecycle_refs.append({"owner":None,"pc":hx(base+off),"address":hx(b[0]),"kind":"unowned_direct_branch"})

    # Include the adjacent original leaf/tail targets and first two levels
    # of exact direct calls from the narrowly chosen input/Guide roots.
    chosen,truncated=forward(roots,outbound,limit=300,depth=2)
    focused=set(roots)|{a for a in chosen if a in funcs and chosen[a]<=1}
    if label=="hud":
        # Original HUD entry and guide-related imported UI calls.
        focused.add(0x913F8D00)
    bodies={hx(a):bounded_entry(image,base,pe,a,thunks,min(8192,funcs.get(a,256)))
            for a in sorted(focused) if executable(pe,base,a)}
    # Trace point selection: exact original exports and registration owners,
    # calls and continuations, and only actual branch outcomes in those owners.
    trace={}
    def mark(a,name,phase):
        if executable(pe,base,a):trace.setdefault(hx(a),{"name":name,"phase":phase})
    for name,a in exports.items():mark(a,name,"entry")
    for a in SYSREQ_OWNERS|extra if label=="xam" else ():
        mark(a,"sysreq_"+hx(a),"entry")
    if label=="xam":
        for a in (0x816CE8B0,0x816F0F28,0x816F0E70,0x816F0DF0,0x816F0AE0,0x816F06E8,0x816F3C48,0x816F0400,0x816F0DE0,
                  0x816D8AA8,0x816F0E84,0x816F0E88,0x816F0EC8,0x816F0ED0,0x816F0E40,0x816F0E44,
                  0x816F0710,0x816F0724,0x816F0734,0x816F0760,0x816F0764,0x816F0794,0x816F0C8C,0x816F0C90,
                  0x816F0D08,0x816F0DAC,0x816F0DCC,0x816F03F0):
            mark(a,"guide_lifecycle_"+hx(a),"observed")
        # The sole original direct caller of the init wrapper is the UI
        # subsystem initializer. Probe every direct call/return in that
        # bounded original body to locate the first failing stage.
        for row in bodies[hx(0x816CE8B0)]["operands"]:
            if row["kind"]=="branch" and row["linked"]:
                a=int(row["pc"],16)
                mark(a,"ui_init_"+row["target"],"call")
                mark(a+4,"ui_init_"+row["target"],"return")
            elif row["kind"]=="conditional_branch":
                a=int(row["pc"],16)
                mark(a+4,"ui_init_branch_"+hx(a),"fallthrough")
                mark(int(row["target"],16),"ui_init_branch_"+hx(a),"taken_target")
    for c in callbacks:
        pc=int(c["site"],16)
        mark(pc,"DrvSetSysReqCallback","call")
        if c["linked"]:mark(pc+4,"DrvSetSysReqCallback","return")
        owner=int(c["owner"],16)
        for row in bodies[hx(owner)]["operands"]:
            if row["kind"]=="conditional_branch":
                a=int(row["pc"],16)
                mark(a+4,"sysreq_branch_"+hx(a),"fallthrough")
                target=int(row["target"],16)
                if owner<=target<owner+funcs[owner]:mark(target,"sysreq_branch_"+hx(a),"taken_target")
    for c in call_sites:
        if c["import"]["name"] in UI|{"XInputdNotify","XInputdRawState"}:
            a=int(c["site"],16);mark(a,c["import"]["name"],"call")
            if c["linked"]:mark(a+4,c["import"]["name"],"return")
    if label=="hud":mark(0x913F8D00,"HUD","entry")
    return {"exports":{k:hx(v) for k,v in exports.items()},"sysreq_registrations":callbacks,
      "input_and_ui_calls":call_sites,"possible_guide_bit_tests":mask_sites,
      "export_address_references":pointer_refs,"lifecycle_refs":lifecycle_refs,"data_pointer_refs":data_refs,"callback_candidates":[hx(a) for a in sorted(extra)],
      "reverse_graph":ancestors(roots,inbound,max_depth=3,max_nodes=1000),
      "forward_graph":{"nodes":{hx(a):n for a,n in chosen.items()},"truncated":truncated},
      "bodies":bodies,"trace_points":trace}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("build output only")
    catalog,stubs=sdk_catalog(a.sdk);members=parse(original("pirs"))
    result={"scope":"Verified original image metadata; static candidates are not invoked.","modules":{}}
    for label,raw in (("xam",members["$flash_xam.xex"]["payload"]),("hud",members["$flash_hud.xex"]["payload"]),("dash",original("dash_basic"))):
        if label=="xam" and sha(raw)!=EXPECTED["xam_17559"] or label=="hud" and sha(raw)!=HUD_SHA:raise ValueError("original XEX identity")
        image,meta=decode(raw,a.lzx.resolve())
        if label in DIGESTS and meta["sha256"]!=DIGESTS[label]:raise ValueError("decoded image identity")
        row=scan(label,raw,image,meta,catalog,stubs);result["modules"][label]=row
        print(label,"sysreq",len(row["sysreq_registrations"]),"callback candidates",row["callback_candidates"],
            "trace points",len(row["trace_points"]),"bodies",len(row["bodies"]))
        for c in row["sysreq_registrations"]:print(c["site"],c["argument_provenance"],c["nearby_code_address_constructions"])
        print("lifecycle pointer references",row["data_pointer_refs"],"code refs",len(row["lifecycle_refs"]))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
