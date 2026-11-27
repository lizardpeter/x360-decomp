#!/usr/bin/env python3
"""Recover original XAM's storage boundary with bounded direct-call evidence.

No dynamic execution, account payload, credential decoding or signature
override. Direct branches are proven from the decoded original image.
Unresolved indirect edges and unknown extents remain explicit.
"""
import argparse
import bisect
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import branch,hx,library,sdk_catalog,context,indirect_call
from metro_profile_evidence import PROFILE,linear_export_extent
from metro_xam_fault_evidence import operand,conditional_details
from metro_startup_hardware_evidence import continuation
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from stage_metro_xam_aot import rows
from xex import parse as parse_xex

# The exact original XAM 17559 import records joined to the pinned SDK.
# These are not guesses at the original argument ABI.
STORAGE_ORDINALS={
    0x0032:"IoBuildSynchronousFsdRequest",
    0x0033:"IoCallDriver",
    0x0035:"IoCompleteRequest",
    0x0037:"IoCreateDevice",
    0x0039:"IoDeleteDevice",
    0x003B:"IoDismountVolume",
    0x003C:"IoDismountVolumeByFileHandle",
    0x003D:"IoDismountVolumeByName",
    0x0041:"IoInvalidDeviceRequest",
    0x004B:"IoSynchronousDeviceIoControlRequest",
    0x00D2:"NtCreateFile",
    0x00D9:"NtDeviceIoControlFile",
    0x00DF:"NtOpenFile",
    0x00E4:"NtQueryDirectoryFile",
    0x00E7:"NtQueryFullAttributesFile",
    0x00EF:"NtQueryVolumeInformationFile",
    0x020E:"DrvSetContentStorageCallback",
    0x0210:"DrvGetContentStorageNotification",
    0x0259:"StfsCreateDevice",
    0x025A:"StfsControlDevice",
}
PRIMARY={"StfsCreateDevice","StfsControlDevice","IoSynchronousDeviceIoControlRequest",
         "DrvSetContentStorageCallback","DrvGetContentStorageNotification",
         "IoCreateDevice","IoDeleteDevice","IoDismountVolume",
         "IoDismountVolumeByFileHandle","IoDismountVolumeByName"}

def executable_sections(pe,base):
    return [(base+s["rva"],base+s["rva"]+s["loaded_bytes"])
            for s in pe["sections"] if s["flags"]&0x20000000]

def graph(image,base,pe,thunks,exports):
    """Enumerate PDATA functions and only bounded direct leaf/tail wrappers."""
    funcs={a:s for a,s,_ in pe["functions"]}
    pdata=set(funcs);wrappers={};unknown=set()
    queued=collections.deque(sorted(funcs))
    for a in sorted(set(exports.values())-pdata):
        if extent:=linear_export_extent(image,base,pe,a):
            funcs[a]=extent[0];wrappers[a]=extent[1];queued.append(a)
    code=executable_sections(pe,base)
    def executable(a):
        return any(lo<=a and a+4<=hi for lo,hi in code)
    calls=collections.defaultdict(list);edges=collections.defaultdict(set)
    indirect=collections.Counter()
    while queued:
        a=queued.popleft()
        n=funcs[a]
        if n<=0 or n%4 or not executable(a) or not executable(a+n-4):
            raise ValueError("invalid verified function extent "+hx(a))
        words=[w for w, in struct.iter_unpack(">I",image[a-base:a-base+n])]
        for i,w in enumerate(words):
            pc=a+4*i
            if indirect_call(w):indirect[a]+=1
            b=branch(pc,w)
            if not b:continue
            dest,linked=b
            if dest in thunks:
                calls[a].append({"owner":hx(a),"site":hx(pc),"thunk":hx(dest),
                    "linked":linked,"import":thunks[dest],**context(words,i,linked)})
                continue
            if not linked and a<=dest<a+n:continue
            if dest==a:continue
            if dest not in funcs and dest not in unknown:
                if executable(dest) and (extent:=linear_export_extent(image,base,pe,dest)):
                    funcs[dest]=extent[0];wrappers[dest]=extent[1];queued.append(dest)
                else:unknown.add(dest)
            if dest in funcs:edges[a].add((dest,pc,linked))
    return funcs,wrappers,calls,edges,indirect,unknown

def shortest(roots,edges,limit=20000,depth=12):
    """A shortest direct call path, not a proof of runtime reachability."""
    reached={r:(None,None,0) for r in sorted(roots)}
    todo=collections.deque(sorted(roots));truncated=False
    while todo:
        a=todo.popleft()
        d=reached[a][2]
        for b,pc,linked in sorted(edges[a]):
            if b in reached:continue
            if d>=depth or len(reached)>=limit:
                truncated=True;continue
            reached[b]=(a,(pc,linked),d+1)
            todo.append(b)
    return reached,truncated

def path_to(a,reached):
    result=[]
    while reached[a][0] is not None:
        caller,(pc,linked),_=reached[a]
        result.append({"caller":hx(caller),"site":hx(pc),"callee":hx(a),"linked":linked})
        a=caller
    return list(reversed(result))

def operand_window(image,base,a,n,site):
    lo=max(a,site-64);hi=min(a+n,site+68)
    ops=[]
    for pc in range(lo,hi,4):
        w=struct.unpack_from(">I",image,pc-base)[0]
        row={"pc":hx(pc),**operand(pc,w)}
        if w>>26==16:row.update(conditional_details(pc,w))
        ops.append(row)
    return ops

def audit(raw,image,meta,catalog,stubs,exports):
    if sha(raw)!=EXPECTED["xam_17559"]:
        raise ValueError("unexpected original XAM bytes")
    base=meta["image_base"];pe=pe_info(image,base)
    thunks={};found={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);o=int(row["ordinal"],16)
        name,kind=catalog.get((lib,o),("", "unknown"))
        if lib=="xboxkrnl" and o in STORAGE_ORDINALS:
            if kind!="kFunction" or name!=STORAGE_ORDINALS[o] or len(row["thunk_slots"])!=1:
                raise ValueError("storage import identity differs "+name)
            found[o]=row["thunk_slots"][0]
        for a in row["thunk_slots"]:
            thunks[a]={"library":lib,"ordinal":f"{o:04X}","name":name,"sdk_explicit_stub":name in stubs}
    if set(found)!=set(STORAGE_ORDINALS):
        raise ValueError("incomplete original storage import census")
    funcs,wrappers,calls,edges,indirect,unknown=graph(image,base,pe,thunks,exports)
    boundary=collections.defaultdict(list);owners=set()
    for a,sites in calls.items():
        for site in sites:
            name=site["import"]["name"]
            if name not in STORAGE_ORDINALS.values():continue
            pc=int(site["site"],16)
            detail={**site}
            if name in PRIMARY:
                ops=operand_window(image,base,a,funcs[a],pc)
                detail["operand_window"]=ops
                detail["first_provable_return_use"]=continuation(
                    [o for o in ops if int(o["pc"],16)>pc]) if site["linked"] else {"kind":"tail"}
                owners.add(a)
            boundary[name].append(detail)
    per_api={}
    for name,a in sorted(exports.items()):
        if a not in funcs:
            per_api[name]={"entry":hx(a),"extent_unresolved":True};continue
        reached,truncated=shortest({a},edges)
        # Report one shortest path per storage-boundary owner, with all
        # proven call sites at that owner. No dynamic or guessed edges.
        paths=[]
        for storage,sites in sorted(boundary.items()):
            for site in sites:
                owner=int(site["owner"],16)
                if owner in reached:
                    paths.append({"storage_api":storage,"owner":site["owner"],"site":site["site"],
                                  "path":path_to(owner,reached)})
        per_api[name]={"entry":hx(a),"visited":len(reached),"truncated":truncated,
                       "indirect_sites_in_visited_functions":sum(indirect[r] for r in reached),
                       "storage_paths":paths}
    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "pdata_functions":len(pe["functions"]),"bounded_wrappers":len(wrappers),
            "unresolved_direct_targets":len(unknown),
            "storage_imports":{STORAGE_ORDINALS[o]:{"ordinal":f"{o:04X}","thunk":hx(a)}
                               for o,a in sorted(found.items())},
            "boundary_sites":{name:sites for name,sites in sorted(boundary.items())},
            "primary_owners":len(owners),"per_api":per_api,
            "scope":"Static direct-call paths to storage imports; indirect dispatch and runtime argument values are unresolved."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    catalog,stubs=sdk_catalog(a.sdk)
    exports={}
    for r in rows(ROOT/"analysis/xam_17559/exports.tsv"):
        n,k=catalog.get(("xam",int(r["ordinal"],16)),("", "unknown"))
        if k=="kFunction" and n in PROFILE:exports[n]=int(r["address"],16)
    raw=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!=json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text())["sha256"]:
        raise ValueError("wrong decoded XAM image")
    report=audit(raw,image,meta,catalog,stubs,exports)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("Storage census",len(report["storage_imports"]),"imports;",
          sum(map(len,report["boundary_sites"].values())),"direct sites;",
          report["primary_owners"],"primary owners;",report["bounded_wrappers"],"bounded wrappers")
    for name,sites in report["boundary_sites"].items():print(name,len(sites))
    for name,item in report["per_api"].items():
        print(name,"direct storage paths",len(item.get("storage_paths",[])),
              "visited",item.get("visited"),"truncated",item.get("truncated"))

if __name__=="__main__":main()
