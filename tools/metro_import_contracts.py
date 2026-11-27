#!/usr/bin/env python3
"""Inventory original Metro/XAM call contracts; never export code or asset bytes."""
import argparse
import bisect
import collections
import json
import re
import struct
from pathlib import Path

from analyze_decoded import pe_info, imports, ordinal_exports
from decode_image import decode
from pirs import parse as parse_pirs
from prepare_recompilation import ROOT, EXPECTED, original, sha
from xex import parse as parse_xex

SDK_PIN = "a3e1d82678ca20d68d4837a8e9ee4652ff073745"
DIGESTS = {
    "dash": "06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9",
    "xam": "f9e44cd6f4b04875ddc5a3b8fd519785ba2b0488b1c4622f818b740ba4064313",
}
FOCUS = re.compile(r"^(XInputd|Drv|Hid|Usbd|XUsbcam|Etx|Vd|KeSetPriorityClassThread|NtDeviceIoControlFile|XboxKrnlBaseVersion|StfsDeviceErrorEvent)")
OBSERVED = {
    "EtxProducerRegister", "DrvSetUserBindingCallback", "DrvSetDeviceConfigChangeCallback",
    "DrvSetMicArrayStartCallback", "DrvSetAudioLatencyCallback",
    "XInputdSetFailedConnectionOrBindCallback", "KeSetPriorityClassThread",
    "DrvGetContentStorageNotification", "NtDeviceIoControlFile",
}
def hx(n):
    return f"{n:08X}"

def signed(n, width):
    return n - (1 << width) if n & (1 << (width - 1)) else n

def branch(pc, w):
    if w >> 26 != 18:
        return None
    d = signed(w & 0x03fffffc, 26)
    return ((d if w & 2 else pc+d) & 0xffffffff, bool(w & 1))

def registers(w):
    return ((w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31)

def indirect_call(w):
    return w >> 26 == 19 and ((w >> 1) & 1023) in (16, 528) and bool(w & 1)

def setup(w):
    """Recognize only a few operand forms; these are observations, not signatures."""
    op = w >> 26
    r, a, b = registers(w)
    low = signed(w & 65535, 16)
    if op in (14,15):
        return r, {"kind": "immediate" if not a else "register_offset", "base": a,
                   "value": low << (16 if op == 15 else 0)}
    if op == 24:
        return a, {"kind": "or_immediate", "source": r, "value": w & 65535}
    if op in (32,34,40,42,58):
        return r, {"kind": "memory_load", "base": a, "offset": low & ~3 if op == 58 else low,
                   "width": {32:4,34:1,40:2,42:2,58:8}[op]}
    if op == 31 and (w >> 1) & 1023 == 444 and r == b:
        return a, {"kind": "register_copy", "source": r}
    return None

def result_use(w):
    op = w >> 26
    r,a,b = registers(w)
    if op in (10,11) and a == 3:
        return "compare_r3_immediate"
    if op in (36,38,44,62) and r == 3:
        return "store_r3"
    if op in (14,15,32,34,40,42,58) and a == 3:
        return "use_r3_as_base"
    if op == 31 and (w >> 1) & 1023 == 444 and r == b == 3:
        return "copy_r3"
    if op in (20,21,23,24,25,26,27,28,29) and r == 3:
        return "bit_operation_on_r3"
    if op in (14,15) and r == 3 and a == 0:
        return "overwrite_r3_immediate"
    return "unknown"

def context(words, i, linked):
    # Stop at any control transfer. Do not claim that unrecognized instructions
    # leave registers unchanged; report nearby recognized writes individually.
    observed = []
    for j in range(i-1, max(-1,i-13), -1):
        w=words[j]
        if w >> 26 in (16,17,18,19):
            break
        s=setup(w)
        if s and 3 <= s[0] <= 10:
            observed.append({"register":s[0],"instructions_before":i-j,**s[1]})
    result = result_use(words[i+1]) if linked and i+1<len(words) else "not_observed"
    return {"nearby_argument_writes":observed,"immediate_return_use":result}

def variable_reference(previous,w):
    if previous >> 26 != 15 or (previous >> 16) & 31:
        return None
    r=(previous >> 21)&31
    op=w>>26
    rt,ra,_=registers(w)
    if op==24 and rt==r:
        return (((previous&65535)<<16)|(w&65535), "address_construction")
    if ra==r and op in (14,32,34,36,38,40,42,44,58,62):
        low=signed(w&65535,16)
        if op in (58,62):
            low &= ~3
        return ((((previous&65535)<<16)+low)&0xffffffff,
                "address_construction" if op==14 else "memory_access")
    return None

def sdk_catalog(sdk):
    names={}
    stubs=set()
    for lib in ("xboxkrnl","xam","xbdm"):
        directory=sdk/"src/kernel"/lib
        table=(directory/"export_table.inc").read_text()
        for l,o,n,k in re.findall(r"REX_EXPORT\(\s*(\w+),\s*(0x[0-9A-Fa-f]+),\s*(\w+),\s*(kFunction|kVariable)\s*\)",table):
            names[(l,int(o,16))]=(n,k)
    for f in (sdk/"src/kernel").rglob("*.cpp"):
        stubs.update(re.findall(r"REX_EXPORT_STUB(?:_[A-Z]+)?\s*\(\s*__imp__(\w+)",f.read_text(errors="replace")))
    if not names or not stubs:
        raise ValueError("SDK export/stub inventory missing")
    return names,stubs

def library(s):
    return s.lower().removesuffix(".exe").removesuffix(".xex").removesuffix(".dll")

def descriptor(row,catalog,stubs):
    lib=library(row["library"])
    ordinal=int(row["ordinal"],16)
    name,kind=catalog.get((lib,ordinal),("", "unknown"))
    return {"library":lib,"ordinal":f"{ordinal:04X}","name":name,"sdk_kind":kind,
            "sdk_explicit_stub":name in stubs}

def inspect(label, image, base, pe, rows, catalog, stubs):
    funcs=pe["functions"]
    starts=[a for a,_,_ in funcs]
    sizes={a:s for a,s,_ in funcs}
    def owner(pc):
        i=bisect.bisect_right(starts,pc)-1
        return starts[i] if i>=0 and pc<starts[i]+sizes[starts[i]] else None
    thunks={}
    variables={}
    for row in rows:
        d=descriptor(row,catalog,stubs)
        for a in row["thunk_slots"]:
            if a in thunks: raise ValueError("duplicate thunk")
            thunks[a]=d
        if not row["thunk_slots"]:
            for a in row["value_slots"]:
                variables[a]=d
    edges=collections.defaultdict(set)
    calls=collections.defaultdict(list)
    unknown=collections.Counter()
    indirect=collections.Counter()
    refs=[]
    for start,size,_ in funcs:
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        for i,w in enumerate(words):
            pc=start+4*i
            if indirect_call(w): indirect[start]+=1
            if i:
                ref=variable_reference(words[i-1],w)
                if ref:
                    a,kind=ref
                    if a in variables or 0x8e030000<=a<0x8e040000:
                        refs.append({"function":hx(start),"site":hx(pc-4),"address":hx(a),
                                     "kind":kind,"variable":variables.get(a)})
            b=branch(pc,w)
            if not b: continue
            target,linked=b
            if target in thunks:
                d=thunks[target]
                key=(d["library"],d["ordinal"])
                c={"function":hx(start),"site":hx(pc),"thunk":hx(target),
                   "kind":"call" if linked else "tail"}
                if FOCUS.match(d["name"]) or d["sdk_explicit_stub"]:
                    c.update(context(words,i,linked))
                calls[key].append(c)
            elif target in sizes and target!=start:
                edges[start].add(target)
            elif linked and owner(target)!=start:
                unknown[target]+=1
    return {"label":label,"entry":pe["entry_point"],"sizes":sizes,"edges":edges,
            "calls":calls,"thunks":thunks,"variable_refs":refs,"unknown":unknown,
            "indirect":indirect}

def reachable(modules, xam_exports, roots):
    """Direct intermodule graph. No indirect call, interior target or execution claims."""
    cross=collections.defaultdict(set)
    for (lib,o),sites in modules["dash"]["calls"].items():
        if lib=="xam":
            dest=xam_exports.get(int(o,16))
            if dest:
                for c in sites:cross[int(c["function"],16)].add(dest)
    seen={}
    queue=collections.deque((label,a,0) for label,a in roots)
    unresolved=set()
    while queue:
        label,a,depth=queue.popleft()
        key=(label,a)
        if key in seen:continue
        m=modules[label]
        if a not in m["sizes"]:
            unresolved.add((label,a))
            continue
        seen[key]=depth
        queue.extend((label,target,depth+1) for target in m["edges"][a])
        if label=="dash":
            queue.extend(("xam",dest,depth+1) for dest in cross[a])
    return seen,unresolved

def report(modules, exports, catalog, stubs):
    seen,unresolved=reachable(modules,exports,[(l,m["entry"]) for l,m in modules.items()])
    reports={}
    for label,m in modules.items():
        dmap={(d["library"],d["ordinal"]):d for d in m["thunks"].values()}
        rows=[]
        for key,d in sorted(dmap.items()):
            sites=m["calls"][key]
            depths=[seen[(label,int(c["function"],16))] for c in sites
                    if (label,int(c["function"],16)) in seen]
            row={**d,"direct_sites":len(sites),"startup_graph_sites":len(depths),
                 "minimum_graph_depth":min(depths) if depths else None,
                 "observed_previous_boot":d["name"] in OBSERVED}
            if FOCUS.match(d["name"]) or d["sdk_explicit_stub"]:
                row["sites"]=sites
            rows.append(row)
        reports[label]={"entry":hx(m["entry"]),"pdata_functions":len(m["sizes"]),
                        "reachable_functions":sum(l==label for l,a in seen),
                        "direct_edges":sum(map(len,m["edges"].values())),
                        "indirect_call_sites":sum(m["indirect"].values()),
                        "unclassified_link_targets":{hx(a):n for a,n in m["unknown"].most_common()},
                        "imports":rows,"variable_and_fixed_page_references":m["variable_refs"]}
    return {"sdk_pin":SDK_PIN,"scope":"static PDATA direct graph; not runtime reachability or inferred ABI",
            "unresolved_cross_module_entries":[{"module":l,"address":hx(a)} for l,a in sorted(unresolved)],
            "modules":reports}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to((ROOT/"build").resolve()):
        p.error("write report only under build/")
    catalog,stubs=sdk_catalog(a.sdk)
    xam=parse_pirs(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("XAM source mismatch")
    modules={};exports={}
    for label,raw in (("dash",original("dash_basic")),("xam",xam)):
        image,info=decode(raw,a.lzx.resolve())
        if info["sha256"]!=DIGESTS[label]:raise ValueError("image identity mismatch")
        base=info["image_base"]
        pe=pe_info(image,base)
        rows=imports(image,base,parse_xex(raw))
        modules[label]=inspect(label,image,base,pe,rows,catalog,stubs)
        if label=="xam":exports=dict(ordinal_exports(image,base,raw))
    result=report(modules,exports,catalog,stubs)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    for l,m in result["modules"].items():
        print(l,"PDATA",m["pdata_functions"],"startup direct-graph",m["reachable_functions"],
              "indirect call sites",m["indirect_call_sites"])
        for row in m["imports"]:
            if row["observed_previous_boot"] or (row["startup_graph_sites"] and FOCUS.match(row["name"])):
                print(l,row["ordinal"],row["name"],"sites",row["direct_sites"],
                      "reachable",row["startup_graph_sites"],"stub",row["sdk_explicit_stub"])
                if row["observed_previous_boot"]:
                    for c in row.get("sites",[])[:8]:print(json.dumps(c,sort_keys=True))
if __name__=="__main__":main()
