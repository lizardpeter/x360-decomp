#!/usr/bin/env python3
"""Original startup contract audit for live-observed display and input calls.

Match verified original image identities, reconstruct observed call sites
and enumerate direct callers. No guest code, assets, secrets or security
configuration are exported, and no guest runtime behavior is changed.
"""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports, pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS, branch, hx, library, sdk_catalog
from metro_xam_fault_evidence import bounded_entry, observed_call, operand, conditional_details
from metro_live_slot_and_input_evidence import read_word, executable
from pirs import parse
from prepare_recompilation import EXPECTED, ROOT, original, sha
from xex import parse as parse_xex

# Actual original return PCs observed in integrated boot 45971765588.
# Physical security/authentication exports intentionally excluded.
LIVE = {
    "dash": {
        0x921871CC:"VdSetStudioRGBMode",
        0x92370F8C:"VdSetStudioRGBMode",
        0x9217FF50:"HalGetCurrentAVPack",
    },
    "xam": {
        0x81696924:"DrvSetDeviceConfigChangeCallback",
        0x81696930:"DrvSetMicArrayStartCallback",
        0x8169693C:"DrvSetAudioLatencyCallback",
        0x81696948:"XInputdSetFailedConnectionOrBindCallback",
        0x816B9830:"KeSetPriorityClassThread",
        0x8167EE38:"DrvSetContentStorageCallback",
        0x816F4394:"XInputdGetFailedConnectionOrBind",
        0x816F25B4:"XInputdFFDeviceControl",
        0x816D8F34:"XInputdSetRingOfLight",
        0x819020A4:"XAudioSetDuckerLevel",
        0x8175E160:"NicGetLinkState",
        0x8174CC68:"NicGetLinkState",
        0x81760568:"NicSetUnicastAddress",
        0x81749AFC:"NicAttach",
        0x81749B18:"NicGetOpt",
    },
}
FOCUS = set().union(*(set(x.values()) for x in LIVE.values())) | {
    "XInputdNotify", "XInputdWriteState", "XInputdSetState",
    "VdQueryVideoMode","VdSwap","VdGetCurrentDisplayInformation",
    "VdSetDisplayMode","VdSetDisplayModeOverride",
}

def resolve_tail(image,base,pe,target,thunks):
    visited=set()
    while target not in thunks and len(visited)<8:
        if target in visited or not executable(pe,base,target):return None
        visited.add(target)
        dest=branch(target,read_word(image,base,target))
        if not dest or dest[1]:return None
        target=dest[0]
    return thunks.get(target)

def continuation(ops):
    """Classify first provable use of r3, stopping at unknown instructions.

    This intentionally under-classifies: branches, implicit writes and
    unsupported operations cannot prove the caller ignored a result.
    """
    for o in ops:
        kind=o["kind"]
        if kind in ("conditional_branch","branch","indirect_branch","return","unclassified"):
            return {"kind":"control_or_unknown","pc":o["pc"]}
        if (o.get("base")==3 or o.get("source")==3 or
            o.get("register")==3 and kind=="compare_immediate" or
            3 in o.get("inputs",[]) or o.get("index")==3):
            return {"kind":"reads_result","pc":o["pc"],"operation":kind}
        if o.get("writes")==3:
            return {"kind":"overwrites_result","pc":o["pc"],"operation":kind}
    return {"kind":"not_proven"}

def audit(label,raw,image,meta,catalog,stubs):
    if meta["sha256"]!=DIGESTS[label]:
        raise ValueError("decoded image identity differs")
    base=meta["image_base"];pe=pe_info(image,base)
    thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for a in row["thunk_slots"]:
            thunks[a]={"library":lib,"ordinal":f"{ordinal:04X}",
                       "name":name,"sdk_stub":name in stubs}
    observed=[]
    roots=set()
    for lr,name in LIVE[label].items():
        try:
            record=observed_call(image,base,pe,lr,name,thunks)
        except ValueError as e:
            record={"lr":hx(lr),"observed_export":name,"classification":"unresolved_owner",
                    "reason":str(e)}
        if "function" in record:
            roots.add(int(record["function"],16))
            record["first_provable_return_use"]=continuation(
                [o for o in record["operand_window"] if int(o["pc"],16)>=lr])
        observed.append(record)
    direct=collections.defaultdict(list)
    for start,size,_ in pe["functions"]:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+4*i
            edge=branch(pc,w)
            if not edge or edge[0]==start:continue
            imp=thunks.get(edge[0])
            if not imp:continue
            if imp["name"] not in FOCUS:continue
            if not edge[1]:continue
            post=[]
            for j in range(i+1,min(i+13,len(words))):
                p=start+j*4
                post.append({"pc":hx(p),**operand(p,words[j])})
            direct[imp["name"]].append({"owner":hx(start),"site":hx(pc),
                       "target":hx(edge[0]),"import":imp,
                       "first_provable_return_use":continuation(post)})
            # Only live-observed and stubbed owners receive bounded bodies.
            if imp["sdk_stub"] and imp["name"] in set(LIVE[label].values()):
                roots.add(start)
    focused={hx(a):bounded_entry(image,base,pe,a,thunks,4096) for a in sorted(roots)}
    return {"source_sha256":sha(raw),"decoded_sha256":meta["sha256"],
            "observed_calls":observed,"direct_call_sites":dict(direct),
            "focused_functions":focused,
            "scope":"Conservative static call and operand evidence; no claimed execution, ABI or hardware state."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    xam=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("XAM source differs")
    catalog,stubs=sdk_catalog(a.sdk)
    result={"source_run":45971765588,"modules":{}}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,meta=decode(raw,a.lzx.resolve())
        report=audit(label,raw,image,meta,catalog,stubs)
        result["modules"][label]=report
        print(label,"observed",len(report["observed_calls"]),"direct calls",
              sum(map(len,report["direct_call_sites"].values())),"focused original owners",len(report["focused_functions"]))
        for r in report["observed_calls"]:
            print(label,r["lr"],r["observed_export"],r["classification"],r.get("first_provable_return_use"))
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
