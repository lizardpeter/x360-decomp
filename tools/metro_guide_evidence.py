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
 0x816F2C50,0x816F2D88,0x816DA550,0x816F17E0,0x81696068,0x816D9060,0x816F06E8,0x816F0E70,0x816F3C48,0x816D8AA8,0x816F0400,0x816F0DE0,0x816C7D78,0x816CAF08,0x816E16E0,0x816C2AF0,0x81696AF0,0x816CE8B0,0x816F0F28,0x816968A8,0x816F4088,0x81696558,0x816C9EA0,0x816CEBD8}
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

# Independently recovered original D3D device publication and retirement
# routines. Both modules select the system slot only for process type 2.
DEVICE_PATHS={
    "xam":((0x8184B8F4,0x8184B900,0x8184B90C,0x8184B914,31),
           (None,0x8184B5A0,0x8184B5C4,0x8184B5CC,30)),
    "dash":((0x921B6E54,0x921B6E60,0x921B6E6C,0x921B6E74,31),
            (None,0x921B6B00,0x921B6B24,0x921B6B2C,30)),
}

def device_trace_plan(label,image,base,raw,thunks):
    if label not in DEVICE_PATHS:return {}
    variable_slots={}
    for row in imports(image,base,parse_xex(raw)):
        if library(row["library"])=="xboxkrnl" and int(row["ordinal"],16) in (0x1be,0x1bf):
            if row["thunk_slots"] or len(row["value_slots"])!=1:raise ValueError("graphics device variable layout")
            variable_slots[int(row["ordinal"],16)]=row["value_slots"][0]
    if set(variable_slots)!={0x1be,0x1bf}:raise ValueError("missing original graphics device slots")
    def word(pc):return struct.unpack_from(">I",image,pc-base)[0]
    def op(pc):return operand(pc,word(pc))
    def slot(pc,ordinal):
        ref=variable_reference(word(pc),word(pc+4))
        if not ref or ref[0]!=variable_slots[ordinal]:
            raise ValueError(f"graphics device slot mismatch {pc:08X}")
    plan={}
    def add(pc,name,phase,kind="observed"):
        plan[hx(pc)]={"name":name,"phase":phase,"result_kind":kind}
    for call,title,system,store,reg in DEVICE_PATHS[label]:
        slot(system,0x1bf)
        # Publication selects one of the two variables. Retirement may
        # clear the user slot at a distinct store, before the system path.
        phase="publish" if reg==31 else "retire"
        if call is not None:
            b=branch(call,word(call))
            if not b or not b[1] or thunks.get(b[0],{}).get("name")!="KeGetCurrentProcessType":
                raise ValueError("device process type import mismatch")
            compare=op(call+4)
            if compare.get("kind")!="compare_immediate" or compare.get("register")!=3 or compare.get("value")!=2:
                raise ValueError("device process selection compare mismatch")
            slot(title,0x1be)
            add(call+4,"device_process_type","compare","r3_process_type")
            add(title,"device_title_slot","select")
        add(system,"device_system_slot_"+phase,"select")
        row=op(store)
        if any(row.get(k)!=v for k,v in {"kind":"memory_store","source":reg,"base":11,"offset":0,"width":4}.items()):
            raise ValueError("device publication store mismatch")
        add(store,"device_"+phase,"store","r"+str(reg)+"_nonzero")
    return plan

def deferred_trace_plan(rows):
    """Trace all bounded direct calls, actual compares, and branch exits.

    A continuation may coincide with the next call: keep its return marker
    first. Only classify registers at an actual original comparison.
    """
    by_pc={int(r["pc"],16):r for r in rows}
    if not by_pc:return {}
    plan={}
    def add(pc,name,phase,result_kind="observed"):
        if pc in by_pc:plan.setdefault(hx(pc),{"name":name,"phase":phase,"result_kind":result_kind})
    for pc,r in by_pc.items():
        if r["kind"]=="compare_immediate" and r.get("value")==0 and r.get("register") in (3,29,30):
            add(pc,"deferred_compare_"+hx(pc),"compare","r"+str(r["register"])+"_class")
    for pc,r in by_pc.items():
        if r["kind"]=="branch" and r.get("linked"):
            add(pc+4,"deferred_after_"+r["target"],"continuation")
    for pc,r in by_pc.items():
        if r["kind"]=="branch" and r.get("linked"):
            add(pc,"deferred_call_"+r["target"],"call")
        elif r["kind"]=="conditional_branch":
            add(pc+4,"deferred_branch_"+hx(pc),"fallthrough")
            add(int(r["target"],16),"deferred_branch_"+hx(pc),"target")
    return plan

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
    nonadjacent_refs=[]
    startup_arguments=[]
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
        slot_targets={int(r["slot"],16) for r in data_refs if r["section"]!=".pdata"}
        # Unwind records are not callback registration tables. Search for
        # actual computed code pointers across intervening instructions and
        # CFG edges, with the existing conservative register transfer model.
        focus={0x816CE8B0,0x816F0F28,0x816F0DE0}
        for a,n in sorted(funcs.items()):
            words=body_words(image,base,a,n)
            lows={v&65535 for v in focus}
            his={((v+0x8000)>>16)&65535 for v in focus}|{v>>16 for v in focus}
            if not any(w>>26==15 and ((w>>16)&31)==0 and (w&65535) in his for w in words):continue
            if not any(w>>26 in (14,24) and (w&65535) in lows for w in words):continue
            _,states=flow(words,a)
            for i,w in enumerate(words):
                pc=a+4*i
                if pc not in states or w>>26 not in (14,24) or (w&65535) not in lows:continue
                rt,ra,_=registers(w)
                regs=states[pc][0]
                v=regs.get(ra if w>>26==14 else rt)
                if not v or v[0]!="const":continue
                low=w&65535
                if w>>26==14 and low&0x8000:low-=65536
                address=((v[1]+low) if w>>26==14 else (v[1]|low))&0xffffffff
                if address in focus:
                    nonadjacent_refs.append({"owner":hx(a),"site":hx(pc),"target":hx(address),
                        "register":rt if w>>26==14 else ra,"prior_constant":hx(v[1]&0xffffffff)})
                    roots.add(a)
        # Recover the actual original XAM startup work items, which are
        # registered through the common 816BA440 queue instead of called.
        for owner in (0x816968A8,0x816F0DF0,0x816CE8B0):
            words=body_words(image,base,owner,funcs[owner])
            _,states=flow(words,owner)
            for i,w in enumerate(words):
                pc=owner+4*i
                b=branch(pc,w)
                if not b or b[0]!=0x816BA440:continue
                regs=states.get(pc,({},{}))[0]
                startup_arguments.append({"owner":hx(owner),"site":hx(pc),
                    "registers":{f"r{k}":render(regs.get(k)) for k in range(3,7)}})
                for v in regs.values():
                    if v and v[0]=="const" and executable(pe,base,v[1]&0xffffffff):
                        roots.add(v[1]&0xffffffff)

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
    hardware_gate={}
    if label=="xam":
        def check(pc,**want):
            actual=operand(pc,struct.unpack_from(">I",image,pc-base)[0])
            if any(actual.get(k)!=v for k,v in want.items()):
                raise ValueError(f"hardware UI gate mismatch {pc:08X}: {actual}")
        # Original retail XAM uses this one hosted kernel variable in both
        # graphics startup and deferred system-UI initialization.
        hw=[r for r in imports(image,base,parse_xex(raw))
            if library(r["library"])=="xboxkrnl" and int(r["ordinal"],16)==0x156]
        if len(hw)!=1 or 0x815F0480 not in hw[0]["value_slots"]:
            raise ValueError("XboxHardwareInfo import slot mismatch")
        for pc,reg,offset in ((0x816C9EB0,11,1152),(0x816C9EB4,11,0),
                              (0x816966F4,28,1152),(0x816966F8,11,0)):
            check(pc,kind="memory_load",base=reg,offset=offset,writes=11,width=4)
        for pc,dest,sense in ((0x816C9EBC,0x816C9EC8,4),(0x81696700,0x81696748,12)):
            w=struct.unpack_from(">I",image,pc-base)[0]
            check(pc,kind="conditional_branch",target=hx(dest))
            if ((w>>21)&31,(w>>16)&31)!=(sense,2):
                raise ValueError(f"Guide hardware conditional mismatch {pc:08X}")
        for pc in (0x816C9EB8,0x816966FC):
            check(pc,kind="rotate_mask",mask_start=22,mask_end=22,shift_or_reg=0,source=11,writes=11)
        for pc,dest in ((0x81696724,0x816CEBD8),(0x816CEC70,0x816BA6B0),(0x816CEB58,0x816F0F28)):
            if branch(pc,struct.unpack_from(">I",image,pc-base)[0])!=(dest,True):
                raise ValueError(f"Guide initialization edge mismatch {pc:08X}")
        hardware_gate={"import_slot":"815F0480","ordinal":"0156","tested_mask":"00000200",
                       "graphics_test":"816C9EB8","startup_test":"816966FC",
                       "startup_branch":"81696700","skip_target":"81696748",
                       "ui_registrar":"816CEBD8","ui_worker":"816CE8B0"}
        for pc in (0x816C9EB8,0x816966FC):mark(pc,"hw_gate","test")
        for pc in (0x816C9EC0,0x816C9EC8,0x81696704,0x81696748):
            mark(pc,"hw_gate_path","observed")
        # The original UI initializer registers a graphics callback and
        # opens a resource-only XEX before reaching the Guide worker.
        for site,name,expected_import in (
            (0x816CE980,"graphics_register","VdRegisterXamGraphicsNotification"),
            (0x816CEA04,"hud_skin_load","XexLoadImage")):
            b=branch(site,struct.unpack_from(">I",image,site-base)[0])
            if not b or not b[1] or thunks.get(b[0],{}).get("name")!=expected_import:
                raise ValueError("original Guide graphics/skin trace site mismatch")
            mark(site,name,"call")
            mark(site+4,name,"return")
        mark(0x816CBFD8,"graphics_notification_callback","entry")
        # Verify original halfword switch entries before instrumenting the
        # two independently observed producers. The callback event is r4.
        for event,target in ((1,0x816CC01C),(9,0x816CC358)):
            entry=struct.unpack_from(">H",image,0x815FA3F0-base+2*(event-1))[0]
            if 0x816CC01C+entry!=target:
                raise ValueError("original graphics switch case mismatch")
            mark(target,"graphics_notification_event_"+str(event),"entry")
        for pc in (0x816C9EA0,0x81696558,0x816CEBD8):
            mark(pc,"guide_boot_"+hx(pc),"entry")
        for pc in (0x81696714,0x81696724,0x816CEC28,0x816CEC38,0x816CEC70,0x816CEC78):
            mark(pc,"guide_boot_"+hx(pc),"call")
            mark(pc+4,"guide_boot_"+hx(pc),"return")
    for name,a in exports.items():mark(a,name,"entry")
    for a in SYSREQ_OWNERS|extra if label=="xam" else ():
        mark(a,"sysreq_"+hx(a),"entry")
    if label=="xam":
        for a in (0x816CE8B0,0x816F0F28,0x816F0E70,0x816F0DF0,0x816F0AE0,0x816F06E8,0x816F3C48,0x816F0400,0x816F0DE0,
                  0x816D8AA8,0x816F0E84,0x816F0E88,0x816F0EC8,0x816F0ED0,0x816F0E40,0x816F0E44,
                  0x816F0710,0x816F0724,0x816F0734,0x816F0760,0x816F0764,0x816F0794,0x816F0C8C,0x816F0C90,
                  0x816F0D08,0x816F0DAC,0x816F0DCC,0x816F03F0):
            mark(a,"guide_lifecycle_"+hx(a),"observed")
        for row in nonadjacent_refs:
            mark(int(row["owner"],16),"guide_init_registrar","entry")
            mark(int(row["site"],16),"guide_init_callback_materialized","observed")
        for row in startup_arguments:
            mark(int(row["site"],16),"startup_work_item","call")
            mark(int(row["site"],16)+4,"startup_work_item","return")
        # Live run 46033912824 entered this worker but did not reach the
        # hardware gate or registrar. Preserve earlier named gate markers.
        for pc,entry in deferred_trace_plan(bodies[hx(0x81696558)]["operands"]).items():
            trace.setdefault(pc,entry)
        # Verify the last observed import, and record a return only if the
        # original call actually returns. No key bytes or output are logged.
        site=0x8189956C
        b=branch(site,struct.unpack_from(">I",image,site-base)[0])
        if b and b[1] and thunks.get(b[0],{}).get("name")=="XeKeysExGetKey":
            mark(site,"deferred_key_service","call")
            mark(site+4,"deferred_key_service","return")
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
    for pc,entry in device_trace_plan(label,image,base,raw,thunks).items():trace.setdefault(pc,entry)
    return {"exports":{k:hx(v) for k,v in exports.items()},"sysreq_registrations":callbacks,
      "input_and_ui_calls":call_sites,"possible_guide_bit_tests":mask_sites,
      "export_address_references":pointer_refs,"lifecycle_refs":lifecycle_refs,"data_pointer_refs":data_refs,"computed_callback_refs":nonadjacent_refs,"startup_work_items":startup_arguments,"callback_candidates":[hx(a) for a in sorted(extra)],
      "reverse_graph":ancestors(roots,inbound,max_depth=3,max_nodes=1000),
      "forward_graph":{"nodes":{hx(a):n for a,n in chosen.items()},"truncated":truncated},
      "bodies":bodies,"trace_points":trace,"hardware_gate":hardware_gate}

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
        print("computed callback refs",row["computed_callback_refs"],"startup work items",row["startup_work_items"])
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
