#!/usr/bin/env python3
"""Original offline profile and content enumeration call graph, metadata only."""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS,branch,hx,library,sdk_catalog,context
from metro_ui_font_graph import forward
from metro_ui_startup_evidence import ancestors
from metro_xam_fault_evidence import bounded_entry
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,original,sha
from stage_metro_xam_aot import rows
from xex import parse as parse_xex

# Explicit local enumeration, identity, settings and notification roots.
# No credential, account-secret, entitlement or online authentication roots.
PROFILE={
    "XamShowSigninUIp","XamNotifyCreateListenerInternal","XamNotifyCreateListenerRangeInternal",
    "XamContentCreateEnumeratorInternal","XamContentAggregateCreateEnumerator",
    "XamContentGetLocalizedDeviceData","XamContentResolveInternal",
    "XamUserGetIndexFromXUID","XamUserGetUserFlags","XamUserGetDeviceId",
    "XamUserReadUserPreference","XamUserCreateTitlesPlayedEnumerator",
    "XamGetCachedGamerTagW","XamShowCreateProfileUI","XamEnumerate",
    "XamShowDeviceSelectorUI","XamShowKeyboardUI",
    "XamUserGetXUID","XamUserGetGamerTag","XamUserGetName","XamUserGetSigninState",
    "XamUserGetSigninInfo","XamUserReadProfileSettings","XamUserReadProfileSettingsEx",
    "XamProfileCreateEnumerator","XamProfileEnumerate","XamProfileOpen","XamProfileClose",
    "XamContentCreateEnumerator","XamContentCreateDeviceEnumerator","XamContentGetDeviceData",
    "XamContentGetDeviceName","XamContentGetDeviceState","XamContentResolve",
    "XamContentGetDefaultDevice","XamContentGetDeviceVolumePath","XamNotifyCreateListener",
    "XamShowSigninUI","XamShowSigninUIEx","XamUserCreateAchievementEnumerator",
    "XamProfileGetLocalTitleCount",
}
def is_focus(name):
    return name in PROFILE
from stage_metro_profile_modules import SPECS
PROFILE_MODULES={name:spec[:2] for name,spec in SPECS.items()}
def grouped_paths(groups, edges, calls, limit=1000, depth=3):
    # A separate bounded traversal per API prevents high-frequency identity
    # calls from crowding out storage or notification paths in the union.
    result={}
    for name, roots in sorted(groups.items()):
        nodes,truncated=forward(roots,edges,limit=limit,depth=depth)
        imports=collections.Counter((c["import"]["library"],c["import"]["ordinal"],c["import"]["name"],c["import"]["sdk_stub"])
                                    for a in nodes for c in calls[a])
        result[name]={"roots":[hx(a) for a in sorted(roots)],
                      "nodes":[{"entry":hx(a),"depth":d} for a,d in sorted(nodes.items())],
                      "truncated":truncated,
                      "imports":[{"library":l,"ordinal":o,"name":n,"sdk_stub":s,"sites":count}
                                 for (l,o,n,s),count in sorted(imports.items())]}
    return result

def linear_export_extent(image,base,pe,address,limit=64):
    """Recognize only bounded, straight-line exact exported leaf/tail wrappers.

    PDATA interiors, conditional control flow and unknown indirect exits are not
    given a fabricated function extent. Even a recognized leaf is evidence,
    not a claim that the complete original call graph has been reconstructed.
    """
    if any(a<=address<a+n for a,n,_ in pe["functions"]):return None
    code=[(base+s["rva"],base+s["rva"]+s["loaded_bytes"])
          for s in pe["sections"] if s["flags"]&0x20000000]
    ends=[hi for lo,hi in code if lo<=address and address+4<=hi]
    if len(ends)!=1 or address&3:return None
    following=min((a for a,_,_ in pe["functions"] if a>address),default=address+limit)
    end=min(address+limit,following,ends[0])
    for pc in range(address,end,4):
        if pc+4>end:return None
        w=struct.unpack_from(">I",image,pc-base)[0]
        if not w:return None
        if w==0x4E800020:return (pc+4-address,"return")
        b=branch(pc,w)
        if b and not b[1]:
            if not any(lo<=b[0] and b[0]+4<=hi for lo,hi in code):return None
            return (pc+4-address,"direct_tail")
        if w>>26 in (16,17) or (w>>26==19 and ((w>>1)&1023) in (16,528,50)):
            return None
    return None

def audit(label,raw,image,meta,catalog,stubs,export_map):
    expected=DIGESTS[label] if label in DIGESTS else PROFILE_MODULES[label][1]
    if meta["sha256"]!=expected:raise ValueError("wrong original image")
    base=meta["image_base"];pe=pe_info(image,base);thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ord=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ord),("", "unknown"))
        for a in row["thunk_slots"]:thunks[a]={"name":name,"library":lib,"ordinal":f"{ord:04X}","sdk_stub":name in stubs}
    funcs={a:s for a,s,_ in pe["functions"]}
    wrapper_entries={}
    if label=="xam":
        for address in set(export_map.values())-funcs.keys():
            if extent:=linear_export_extent(image,base,pe,address):
                length,terminal=extent
                funcs[address]=length
                wrapper_entries[address]={"extent":length,"terminal":terminal}
    outgoing=collections.defaultdict(set);incoming=collections.defaultdict(set)
    calls=collections.defaultdict(list);sites=[];roots=set();groups=collections.defaultdict(set)
    if label=="xam":
        roots={a for a in export_map.values() if a in funcs}
        for name,address in export_map.items():
            if address in funcs:groups[name].add(address)
    for start,size in sorted(funcs.items()):
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+4*i;b=branch(pc,w)
            if not b:continue
            target,linked=b
            if target in thunks:
                item={"site":hx(pc),"import":thunks[target],"linked":linked,**context(words,i,linked)}
                calls[start].append(item)
                if is_focus(thunks[target]["name"]):
                    sites.append({"owner":hx(start),**item});roots.add(start)
                    groups[thunks[target]["name"]].add(start)
            elif target in funcs and target!=start:
                outgoing[start].add((target,pc,linked));incoming[target].add((start,pc,linked))
    nodes,truncated=forward(roots,outgoing,limit=1000,depth=3)
    reverse=ancestors(roots,incoming,max_depth=2,max_nodes=1500)
    # Exact public root body metadata only; not secret-bearing account data.
    report={"roots":[hx(a) for a in sorted(roots)],"direct_sites":sites,
            "export_roots":{n:hx(a) for n,a in export_map.items()} if label=="xam" else {},
            "unresolved_exports":[n for n,a in export_map.items() if a not in funcs] if label=="xam" else [],
            "linear_export_wrappers":[{"name":n,"address":hx(a),**wrapper_entries[a]} for n,a in sorted(export_map.items()) if a in wrapper_entries],
            "nodes":[{"entry":hx(a),"depth":d,"imports":calls[a]} for a,d in sorted(nodes.items())],
            "edges":[{"caller":hx(a),"callee":hx(t),"site":hx(pc),"linked":linked}
                for a in sorted(nodes) for t,pc,linked in sorted(outgoing[a]) if t in nodes],
            "reverse_graph":reverse,"truncated":truncated,
            "per_api":grouped_paths(groups,outgoing,calls),
            "original_xam_targets":[{"owner":s["owner"],"site":s["site"],
                "ordinal":s["import"]["ordinal"],"name":s["import"]["name"],
                "target":hx(export_map[s["import"]["name"]]) if s["import"]["name"] in export_map else None}
                for s in sites if s["import"]["library"]=="xam"],
            "root_bodies":{hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(roots)}}
    print(label,"profile roots",len(roots),"direct calls",len(sites),"descendants",len(nodes),
          "host import names",sorted({c["import"]["name"] for a in nodes for c in calls[a]}))
    if label=="xam":print("bounded exported leaf/tail wrappers",len(wrapper_entries),"unresolved",len(report["unresolved_exports"]))
    return report
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    catalog,stubs=sdk_catalog(a.sdk)
    export_map={}
    for r in rows(ROOT/"analysis/xam_17559/exports.tsv"):
        name,kind=catalog.get(("xam",int(r["ordinal"],16)),("", "unknown"))
        if kind=="kFunction" and is_focus(name):export_map[name]=int(r["address"],16)
    from instrument_metro_profile import verify_export_join
    verify_export_join(export_map)
    members=parse(original("pirs"))
    xam=members["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong XAM source")
    report={"modules":{},"scope":"Local profile/storage ABI graph only; no account packages, identity or credentials."}
    modules=[("dash",original("dash_basic")),("xam",xam)]
    for name,(source_hash,_) in PROFILE_MODULES.items():
        raw=members[f"$flash_{name}.xex"]["payload"]
        if sha(raw)!=source_hash:raise ValueError("wrong profile module source")
        modules.append((name,raw))
    for label,raw in modules:
        image,meta=decode(raw,a.lzx.resolve())
        report["modules"][label]=audit(label,raw,image,meta,catalog,stubs,export_map)
        row=report["modules"][label]
        print(label,"per API graphs",len(row["per_api"]),"capped API graphs",sum(p["truncated"] for p in row["per_api"].values()),"original XAM call joins",sum(bool(s["target"]) for s in row["original_xam_targets"]))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
