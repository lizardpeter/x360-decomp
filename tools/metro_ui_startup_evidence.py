#!/usr/bin/env python3
"""Map original dashboard/XAM/HUD resource and scene initialization dependencies.

Only exact decoded metadata, references, operands and direct graph edges are
emitted. No resource or executable payload is included in the receipt.
"""
import argparse
import bisect
import collections
import hashlib
import json
import re
import struct
from pathlib import Path

from analyze_decoded import pe_info, imports, ordinal_exports
from decode_image import decode
from metro_import_contracts import DIGESTS, branch, context, hx, sdk_catalog, library, variable_reference
from metro_xam_fault_evidence import observed_call, bounded_entry
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from stage_metro_xam_aot import HUD_SHA
from xex import parse as parse_xex

# Exact kernel APIs that can identify/load original modules and resources.
KERNEL_APIS = {
    "XexGetModuleHandle", "XexGetModuleSection", "XexLoadImage",
    "XexUnloadImage", "XexGetProcedureAddress", "XexGetExecutionId",
    "NtOpenFile", "NtCreateFile", "NtQueryFullAttributesFile", "NtReadFile",
    "NtQueryInformationFile", "NtQueryDirectoryFile",
}
RESOURCE_TERMS = (
    "dashmain", "dashcomm", "dashuisk", "SharedUI", "controlp", "neon",
    "luaxbox", "soclua", "shrdres.xzp", "ThematicSkin", "VisionEffect",
    "DASHUSER:", "common://", "controlpack://", "sharedres://",
    "file://", "res://", "skin://", "xui://", "hud.xex", "huduiskin.xex",
    "signin.xex", "createprofile.xex", "gamerprofile.xex",
    "deviceselector.xex", "xstudio.xex", "ximecore.xex", "vk.xex",
    "minimediaplayer.xex", "XenonJKLatin", "SegoeXbox-Light",
    "MainScene", "MainMenu", "HomeScene", "DashboardScene",
    "XuiSceneCreate", "XuiSceneNavigateFirst", "XuiSceneNavigateForward",
    "XuiResourceLoadAll", "XuiResourceOpen", "XuiLoadVisualFromBinary",
)
TERM_PATTERN = re.compile(r"(?:^|[/\\:._-])(?:main|home|dash|guide|shell|signin|background)[^/\\: ]{0,48}\.xur$", re.I)

def ranges(pe, base, executable):
    return [(base+s["rva"],base+s["rva"]+s["loaded_bytes"])
            for s in pe["sections"] if bool(s["flags"]&0x20000000)==executable
            and (executable or s["name"] in (".rdata",".data"))]

def literal_sites(image,base,pe,resource_intervals):
    """Find only terms in data, excluding bytes belonging to packed resources."""
    result=collections.defaultdict(set)
    folded=image.lower()
    terms=tuple(sorted(set(RESOURCE_TERMS)))
    for lo,hi in ranges(pe,base,False):
        for term in terms:
            for encoding,unit in (("ascii",1),("utf-16-be",2),("utf-16-le",2)):
                needle=term.lower().encode(encoding)
                cursor=lo-base
                while (offset:=folded.find(needle,cursor,hi-base))!=-1:
                    cursor=offset+len(needle)
                    address=base+offset
                    if any(a<=address<b for a,b in resource_intervals):continue
                    if unit==2 and address%2:continue
                    # Preserve exact literal and its observed interior address;
                    # do not infer an enclosing string start or arbitrary bytes.
                    result[address].add(term)
        # Identify likely navigation scene names in complete ASCII strings.
        data=image[lo-base:hi-base]
        for match in re.finditer(rb"[\x20-\x7e]{5,128}\x00",data):
            address=lo+match.start()
            if any(a<=address<b for a,b in resource_intervals):continue
            candidate=match.group()[:-1].decode("ascii")
            if TERM_PATTERN.search(candidate):
                result[address].add(candidate)
    return result

def data_pointer_sites(image,base,pe,literals):
    result=collections.defaultdict(set)
    for lo,hi in ranges(pe,base,False):
        end=hi-(hi-lo)%4
        for i,(word,) in enumerate(struct.iter_unpack(">I",image[lo-base:end-base])):
            if word in literals:result[lo+i*4].update(literals[word])
    return result

def owner_index(pe):
    funcs={a:s for a,s,_ in pe["functions"]}
    starts=sorted(funcs)
    def owner(pc):
        i=bisect.bisect_right(starts,pc)-1
        return starts[i] if i>=0 and pc<starts[i]+funcs[starts[i]] else None
    return funcs,owner

def scan_code(image,base,pe,thunks,lookup,resource_names):
    funcs,owner=owner_index(pe)
    calls=[];references=[];inbound=collections.defaultdict(set)
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+i*4
            if i:
                found=variable_reference(words[i-1],w)
                if found:
                    addr,kind=found
                    if addr in lookup:
                        references.append({"owner":hx(start),"site":hx(pc-4),"address":hx(addr),
                                           "kind":kind,"labels":sorted(lookup[addr])})
            dest=branch(pc,w)
            if not dest:continue
            target,linked=dest
            if target in thunks:
                imp=thunks[target]
                if imp["name"] in KERNEL_APIS or (
                    imp["library"]=="xam" and any(s in imp["name"].lower()
                        for s in ("scene","resource","ui","signin","profile","launch"))):
                    calls.append({"owner":hx(start),"site":hx(pc),"target":hx(target),
                                  "linked":linked,"import":imp,**context(words,i,linked)})
            elif target in funcs and target!=start:
                inbound[target].add((start,pc,linked))
    return calls,references,inbound

def ancestors(roots,inbound,max_depth=3,max_nodes=3000):
    queue=collections.deque((a,0) for a in sorted(roots))
    depth={a:0 for a in roots}
    edges=set();truncated=False
    while queue:
        target,n=queue.popleft()
        if n>=max_depth:continue
        for caller,site,linked in sorted(inbound.get(target,())):
            if caller not in depth and len(depth)>=max_nodes:
                truncated=True
                continue
            edges.add((caller,site,target,linked))
            if caller not in depth:
                depth[caller]=n+1
                queue.append((caller,n+1))
    return {"nodes":[{"entry":hx(a),"reverse_depth":n} for a,n in sorted(depth.items())],
            "edges":[{"caller":hx(c),"site":hx(s),"target":hx(t),"linked":l}
                     for c,s,t,l in sorted(edges)],"truncated":truncated,"max_depth":max_depth}

def inventory(label,raw,image,meta,catalog,stubs,exports):
    base=meta["image_base"];pe=pe_info(image,base)
    resources=[];intervals=[];names=set()
    for r in parse_xex(raw)["resources"]:
        a=int(r["address"],16);size=r["bytes"]
        if not base<=a<=base+len(image)-size:raise ValueError("resource extent outside image")
        data=image[a-base:a-base+size]
        resources.append({"id":r["id"],"address":hx(a),"bytes":size,
                          "sha256":hashlib.sha256(data).hexdigest()})
        intervals.append((a,a+size));names.add(r["id"])
    # Cross-check the same original resource bytes already independently pinned.
    ident={"dash":"dash_17559","xam":"xam_17559","hud":"hud_17559"}[label]
    pin=json.loads((ROOT/"analysis"/ident/"resource_hashes.json").read_text())
    if {(r["id"],r["address"],r["bytes"],r["sha256"]) for r in pin}!={
        (r["id"],r["address"],r["bytes"],r["sha256"]) for r in resources}:
        raise ValueError("resource digest inventory differs: "+label)
    literal=literal_sites(image,base,pe,intervals)
    # Resource IDs are exact original names, including those not in the UI term set.
    for lo,hi in ranges(pe,base,False):
        for name in names:
            needle=name.encode("ascii")+b"\0"
            cursor=lo-base
            while (offset:=image.find(needle,cursor,hi-base))!=-1:
                cursor=offset+len(needle);a=base+offset
                if not any(x<=a<y for x,y in intervals):literal[a].add("resource:"+name)
    pointers=data_pointer_sites(image,base,pe,literal)
    lookup=collections.defaultdict(set)
    for source in (literal,pointers):
        for a,labels in source.items():lookup[a].update(labels)
    thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for a in row["thunk_slots"]:
            thunks[a]={"library":lib,"ordinal":f"{ordinal:04X}","name":name,
                       "sdk_stub":name in stubs,"retail_target":hx(exports[ordinal])
                       if lib=="xam" and ordinal in exports else None}
    calls,refs,inbound=scan_code(image,base,pe,thunks,lookup,names)
    focused={int(r["owner"],16) for r in refs}
    section_roots={int(c["owner"],16) for c in calls if c["import"]["name"] in
                   ("XexGetModuleSection","XexLoadImage","XexGetModuleHandle","XexGetProcedureAddress")}
    # Include original argument preparation and branch outcomes, not just
    # names and counts. Limit operand dumps to owners of actual resource calls.
    operands=[bounded_entry(image,base,pe,a,thunks,8192) for a in sorted(section_roots|focused)
              if a in section_roots or any(int(r["owner"],16)==a and any(
                  s.startswith("resource:") or s.endswith(".xur") for s in r["labels"]) for r in refs)]
    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],"resources":resources,
            "literal_sites":[{"address":hx(a),"labels":sorted(v)} for a,v in sorted(literal.items())],
            "pointer_sites":[{"address":hx(a),"labels":sorted(v)} for a,v in sorted(pointers.items())],
            "code_references":refs,"loader_calls":calls,"focused_functions":operands,
            "reverse_loader_graph":ancestors(section_roots|focused,inbound),
            "scope":"direct static references and PDATA-owned calls; indirect paths are not claimed"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):p.error("output under build only")
    members=parse_pirs(original("pirs"))
    raw={"dash":original("dash_basic"),"xam":members["$flash_xam.xex"]["payload"],
         "hud":members["$flash_hud.xex"]["payload"]}
    if sha(raw["xam"])!=EXPECTED["xam_17559"] or sha(raw["hud"])!=HUD_SHA:
        raise ValueError("original module identity")
    decoded={k:decode(v,a.lzx.resolve()) for k,v in raw.items()}
    for key in ("dash","xam"):
        if decoded[key][1]["sha256"]!=DIGESTS[key]:raise ValueError("decoded original mismatch")
    catalog,stubs=sdk_catalog(a.sdk)
    xi,xm=decoded["xam"];exports=dict(ordinal_exports(xi,xm["image_base"],raw["xam"]))
    result={"modules":{k:inventory(k,raw[k],*decoded[k],catalog,stubs,exports) for k in raw},
            "scope":"original image evidence; not a claim of successful scene navigation"}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    for k,v in result["modules"].items():
        print(k,len(v["resources"]),"resource digests",len(v["code_references"]),
              "code refs",len(v["loader_calls"]),"loader calls",
              len(v["focused_functions"]),"focused functions",
              len(v["reverse_loader_graph"]["nodes"]),"reverse nodes")
if __name__=="__main__":main()
