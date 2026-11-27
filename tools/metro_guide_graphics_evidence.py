#!/usr/bin/env python3
"""Bounded original Guide graphics notification and HUD load evidence."""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context,variable_reference
from metro_xam_fault_evidence import bounded_entry,operand
from metro_stfs_abi_evidence import flow,render
from metro_live_slot_and_input_evidence import executable
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,sha,original
from stage_metro_xam_aot import HUD_SHA
from xex import parse as parse_xex

REGISTRATION=0x816CE980
CALLBACK=0x816CBFD8
INTEREST={"VdRegisterXamGraphicsNotification","VdRegisterGraphicsNotification",
          "VdCallGraphicsNotificationRoutines","VdGlobalXamDevice",
          "VdInitializeEngines","VdShutdownEngines","VdSetGraphicsInterruptCallback",
          "XexLoadImage","XexUnloadImage","XexGetProcedureAddress"}

def scan(label,raw,image,meta,catalog,stubs):
    base=meta["image_base"];pe=pe_info(image,base)
    funcs={a:n for a,n,_ in pe["functions"]}
    thunks={};variables={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);o=int(row["ordinal"],16)
        name,_=catalog.get((lib,o),("", "unknown"))
        d={"name":name,"library":lib,"ordinal":f"{o:04X}","sdk_stub":name in stubs}
        for a in row["thunk_slots"]:thunks[a]=d
        for a in row["value_slots"]:
            if not row["thunk_slots"]:variables[a]=d
    calls=[];refs=[];edges=collections.defaultdict(set)
    roots=set()
    if label=="xam":
        roots|={0x816CE8B0,CALLBACK,0x816CA748,0x816C9EA0}
        if not executable(pe,base,CALLBACK):raise ValueError("graphics callback outside code")
        # Independently recover the exact callback argument at the import.
        w=lambda a:struct.unpack_from(">I",image,a-base)[0]
        hi=operand(0x816CE968,w(0x816CE968))
        lo=operand(0x816CE978,w(0x816CE978))
        if hi.get("writes")!=11 or lo.get("writes")!=3 or lo.get("base")!=11 or ((hi["value"]+lo["value"])&0xffffffff)!=CALLBACK:
            raise ValueError("graphics callback address changed")
        b=branch(REGISTRATION,w(REGISTRATION))
        if not b or not b[1] or thunks.get(b[0],{}).get("name")!="VdRegisterXamGraphicsNotification":
            raise ValueError("registration import mismatch")
        # Actual UI worker's XexLoadImage path pointer.
        hi=operand(0x816CE9EC,w(0x816CE9EC))
        lo=operand(0x816CE9F8,w(0x816CE9F8))
        ptr=(hi["value"]+lo["value"])&0xffffffff
        if not base<=ptr<base+len(image):raise ValueError("HUD name outside original image")
        name=image[ptr-base:ptr-base+128].split(b"\0",1)[0].decode("ascii")
        if not name.lower().endswith(".xex"):raise ValueError("unexpected original UI image name")
        hud_load={"site":"816CEA04","path":name,"path_address":hx(ptr)}
        # The callback takes r4 as one-based event, r5 as payload. Decode
        # its actual halfword dispatch table instead of assuming enum names.
        table_hi=operand(0x816CBFF4,w(0x816CBFF4))
        table_lo=operand(0x816CBFFC,w(0x816CBFFC))
        target_hi=operand(0x816CC004,w(0x816CC004))
        target_lo=operand(0x816CC008,w(0x816CC008))
        table=(table_hi["value"]+table_lo["value"])&0xffffffff
        target_base=(target_hi["value"]+target_lo["value"])&0xffffffff
        if not base<=table<=base+len(image)-20:raise ValueError("graphics switch table bounds")
        dispatch={i+1:(target_base+struct.unpack_from(">H",image,table-base+i*2)[0])&0xffffffff for i in range(10)}
        if any(not executable(pe,base,a) for a in dispatch.values()):raise ValueError("graphics switch target outside code")
        print("GRAPHICS_SWITCH",json.dumps({"table":hx(table),"target_base":hx(target_base),
            "targets":{str(k):hx(v) for k,v in dispatch.items()}},sort_keys=True))
        # Print exact operands for the registration and both observed event
        # paths, stopping each at the first unconditional out-edge/return.
        for event in (1,9):
            start=dispatch[event];rows=[]
            for pc in range(start,start+256,4):
                d=operand(pc,w(pc));b=branch(pc,w(pc))
                if b and b[0] in thunks:d["import"]=thunks[b[0]]
                rows.append({"pc":hx(pc),**d})
                if d["kind"]=="return" or b and not b[1]:break
            print("GRAPHICS_CASE",event,json.dumps(rows,sort_keys=True))
        for start,end,tag in ((0x816CE940,0x816CE9B0,"registration"),
                              (0x816CE9EC,0x816CEA24,"skin_load")):
            print("GRAPHICS_OPERANDS",tag,json.dumps([{"pc":hx(pc),**operand(pc,w(pc))} for pc in range(start,end,4)],sort_keys=True))

    else:hud_load={}
    for a,n in sorted(funcs.items()):
        words=[w for w, in struct.iter_unpack(">I",image[a-base:a-base+n])]
        for i,w in enumerate(words):
            pc=a+i*4;b=branch(pc,w)
            if b:
                dest,linked=b
                if dest in funcs and dest!=a:edges[a].add(dest)
                d=thunks.get(dest)
                if d and d["name"] in INTEREST:
                    calls.append({"owner":hx(a),"site":hx(pc),"target":hx(dest),"linked":linked,"import":d,**context(words,i,linked)})
                    roots.add(a)
            if i:
                ref=variable_reference(words[i-1],w)
                if ref and ref[0] in variables and variables[ref[0]]["name"] in INTEREST:
                    refs.append({"owner":hx(a),"site":hx(pc-4),"slot":hx(ref[0]),"import":variables[ref[0]]})
                    roots.add(a)
    startup={}
    if label=="xam":
        # Last logged import on the actual deferred worker in run
        # 46033912824. Its position alone is not proof of failure.
        worker=0x81696558;site=0x8189956C
        b=branch(site,struct.unpack_from(">I",image,site-base)[0])
        if not b or not b[1] or thunks.get(b[0],{}).get("name")!="XeKeysExGetKey":
            raise ValueError("live startup import mismatch")
        owners=[a for a,n in funcs.items() if a<=site<a+n]
        if len(owners)!=1 or worker not in funcs:raise ValueError("startup owner ambiguity")
        owner=owners[0]
        # Reverse distance from the observed caller over bounded PDATA
        # direct edges. Show shortest paths separately for each original
        # top-level initialization call; no path implies no static proof.
        reverse=collections.defaultdict(set)
        for a,dests in edges.items():
            for d in dests:reverse[d].add(a)
        dist={owner:0};queue=collections.deque([owner])
        while queue:
            d=queue.popleft()
            for a in sorted(reverse[d]):
                if a not in dist:dist[a]=dist[d]+1;queue.append(a)
        paths=[]; selected={worker,owner}
        for pc in range(worker,worker+funcs[worker],4):
            b=branch(pc,struct.unpack_from(">I",image,pc-base)[0])
            if not b or not b[1]:continue
            d=b[0]
            if d not in dist:continue
            path=[d]
            while path[-1]!=owner:
                nxt=min(a for a in edges[path[-1]] if dist.get(a)==dist[path[-1]]-1)
                path.append(nxt)
            selected.update(path)
            paths.append({"worker_call":hx(pc),"path":[hx(a) for a in path]})
        # An empty direct path is not an absent runtime call. Find exact
        # references to the observed entry and its immediate PDATA callers.
        # PDATA unwind pointers are identified separately from data refs.
        candidates={owner}|reverse[owner]
        data_refs=[]
        for sec in pe["sections"]:
            if sec["flags"]&0x20000000:continue
            lo=sec["rva"];hi=lo+sec["loaded_bytes"]
            for off in range(lo,hi-3,4):
                v=struct.unpack_from(">I",image,off)[0]
                if v in candidates:
                    data_refs.append({"slot":hx(base+off),"target":hx(v),"section":sec["name"]})
        code_refs=[]
        for a,n in funcs.items():
            for i in range(4,n-3,4):
                prev,w=struct.unpack_from(">II",image,a-base+i-4)
                ref=variable_reference(prev,w)
                if ref and ref[0] in candidates:
                    code_refs.append({"owner":hx(a),"site":hx(a+i-4),"target":hx(ref[0]),"kind":ref[1]})
        print("DEFERRED_INDIRECT_CANDIDATES",json.dumps({"immediate_direct_callers":[hx(a) for a in sorted(reverse[owner])],
                    "data_refs":data_refs,"code_refs":code_refs},sort_keys=True))
        # Record exact entry extents and original return/status branches
        # along the shortest candidates; not cryptographic key material.
        startup={"worker":hx(worker),"last_observed_import_site":hx(site),
            "import_owner":hx(owner),"import":"XeKeysExGetKey",
            "direct_path_candidates":paths,"immediate_direct_callers":[hx(a) for a in sorted(reverse[owner])],
            "data_pointer_candidates":data_refs,"code_pointer_candidates":code_refs,
            "bodies":{hx(a):bounded_entry(image,base,pe,a,thunks,min(funcs[a],4096))
                      for a in sorted(selected)}}
        print("DEFERRED_STARTUP_PATHS",json.dumps({k:v for k,v in startup.items() if k!="bodies"},sort_keys=True))
        for a in sorted(selected):
            rows=startup["bodies"][hx(a)]["operands"]
            print("DEFERRED_STARTUP_CONTROL",hx(a),json.dumps([r for r in rows if r["kind"] in
                {"branch","conditional_branch","compare_immediate","return"}],sort_keys=True))
    if label=="xam":
        # Capture actual callback register consumption and downstream callees;
        # do not assume a notification code or payload layout.
        focus={CALLBACK};queue=collections.deque([(CALLBACK,0)])
        while queue and len(focus)<80:
            a,depth=queue.popleft()
            if depth==3:continue
            for d in sorted(edges[a]):
                if d not in focus:focus.add(d);queue.append((d,depth+1))
        roots|=focus
    bodies={hx(a):bounded_entry(image,base,pe,a,thunks,min(funcs.get(a,256),4096))
            for a in sorted(roots) if executable(pe,base,a)}
    for c in calls:
        a=int(c["owner"],16);pc=int(c["site"],16)
        words=[w for w, in struct.iter_unpack(">I",image[a-base:a-base+funcs[a]])]
        _,states=flow(words,a)
        regs=states.get(pc,({},{}))[0]
        c["arguments"]={f"r{k}":render(regs.get(k)) for k in range(3,8)}
        if c["import"]["name"]=="VdCallGraphicsNotificationRoutines":
            # Exact caller frame writes, including payload construction and
            # the post-call use (or non-use) of r3.
            start=max(a,pc-112);end=min(a+funcs[a],pc+24)
            print("GRAPHICS_PRODUCER",label,hx(pc),json.dumps([
                {"pc":hx(p),**operand(p,struct.unpack_from(">I",image,p-base)[0])}
                for p in range(start,end,4)],sort_keys=True))

    return {"registration_callback":hx(CALLBACK) if label=="xam" else None,
            "hud_load":hud_load,"calls":calls,"data_refs":refs,"bodies":bodies,"deferred_startup":startup}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("build output only")
    catalog,stubs=sdk_catalog(a.sdk);members=parse(original("pirs"))
    data={}
    for label,raw in (("xam",members["$flash_xam.xex"]["payload"]),("hud",members["$flash_hud.xex"]["payload"]),("dash",original("dash_basic"))):
        if label=="xam" and sha(raw)!=EXPECTED["xam_17559"] or label=="hud" and sha(raw)!=HUD_SHA:raise ValueError("original XEX identity")
        image,meta=decode(raw,a.lzx.resolve())
        if label in DIGESTS and meta["sha256"]!=DIGESTS[label]:raise ValueError("decoded image identity")
        data[label]=scan(label,raw,image,meta,catalog,stubs)
        print(label,"graphics-related calls",len(data[label]["calls"]),"data references",len(data[label]["data_refs"]),"bounded bodies",len(data[label]["bodies"]))
        if data[label]["hud_load"]:print("Original UI load:",data[label]["hud_load"])
    skin=members["$flash_huduiskin.xex"]["payload"]
    if sha(skin)!="fdbe68d20fa6b013282ce8f21cebddc34fe4e3a92a71c28983d63f288d2252cc":
        raise ValueError("HUD skin identity mismatch")
    image,meta=decode(skin,a.lzx.resolve())
    if meta["sha256"]!="d7cc1f96a9ac09853d325c9522ba257e5e23c43c819de5007f36fb49e33cedf4":
        raise ValueError("decoded HUD skin identity mismatch")
    header=parse_xex(skin)
    security=struct.unpack_from(">I",skin,16)[0]
    count=struct.unpack_from(">I",skin,security+0x180)[0]
    runs=[struct.unpack_from(">I",skin,security+0x184+24*i)[0] for i in range(count)]
    data["skin"]={"meta":meta,"header":header,"page_types":[v&15 for v in runs],
                  "page_counts":[v>>4 for v in runs]}
    print("HUD_SKIN_LAYOUT",json.dumps(data["skin"],sort_keys=True))
    for label in ("xam","hud","dash"):
        for call in data[label]["calls"]:
            if call["import"]["name"] in {"VdRegisterXamGraphicsNotification","VdRegisterGraphicsNotification","VdCallGraphicsNotificationRoutines"}:
                print("GRAPHICS_NOTIFY_CALL",label,json.dumps({k:call[k] for k in ("owner","site","import","arguments")},sort_keys=True))
    callback=data["xam"]["bodies"].get(hx(CALLBACK))
    if not callback:raise ValueError("original graphics callback body missing")
    print("GRAPHICS_NOTIFY_CALLBACK",json.dumps(callback["operands"][:64],sort_keys=True))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
