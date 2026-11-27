#!/usr/bin/env python3
"""Map original XAM XUI text APIs to their statically linked dashboard twins.

Only normalized instruction signatures, verified addresses and call edges
are exported. Exact normalized equality is a candidate, not semantic proof.
"""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path

EXPORTS={0x336:"set_bounds",0x344:"lookup_string",0x350:"backbuffer_size",
         0x363:"set_text",0x366:"get_text",0x36e:"copy_string",
         0x37b:"property_string",0x397:"lookup_string_by_index",
         0x837:"measure_text",0x3a8:"begin_render",0x3a9:"end_render"}
KNOWN={0x817B8D30:0x921D8188,0x817B9340:0x921D8798,0x817B9EB8:0x921D9480,
       0x81795B68:0x9222F2A0,0x817962E8:0x9222FA20}

def signed(n,bits):return n-(1<<bits) if n&(1<<(bits-1)) else n

def normalize(words,start,base,size):
    out=list(words)
    end=start+4*len(words)
    for i,w in enumerate(words):
        pc=start+4*i
        op=w>>26
        if op==18:
            target=((0 if w&2 else pc)+signed(w&0x03fffffc,26))&0xffffffff
            if not start<=target<end:
                out[i]=w&0xfc000003
        elif op==16 and w&2:
            # Rare absolute conditional branch, external only.
            target=signed(w&0xfffc,16)&0xffffffff
            if not start<=target<end:out[i]=w&0xffff0003
        if op==15 and not (w>>16)&31:
            reg=(w>>21)&31
            hi=(w&65535)<<16
            # A lis plus addi/ori/load pair addressing a verified mapped image.
            # Stop at calls or at a redefinition of the base register.
            for j in range(i+1,min(i+5,len(words))):
                v=words[j];vop=v>>26;rt=(v>>21)&31;ra=(v>>16)&31
                if vop in (16,18,19):break
                if ra==reg and vop in (14,32,34,36,38,40,42,44,48,50,52,54,58,62):
                    addr=(hi+signed(v&65535,16))&0xffffffff
                    if base<=addr<base+size:
                        out[i]=w&0xffff0000
                        out[j]=v&0xffff0000
                    break
                if vop==24 and rt==reg:
                    addr=hi|(v&65535)
                    if base<=addr<base+size:
                        out[i]=w&0xffff0000
                        out[j]=v&0xffff0000
                    break
                if rt==reg:break
    return tuple(out)

def signature(words):
    return hashlib.sha256(struct.pack(">"+"I"*len(words),*words)).hexdigest()

def read_words(image,base,start,size):
    p=start-base
    if size<=0 or size%4 or p<0 or p+size>len(image):raise ValueError("bad original extent")
    return struct.unpack_from(">"+"I"*(size//4),image,p)

def inventory(image,base,funcs):
    from metro_import_contracts import branch
    rows={};by_sig=collections.defaultdict(list);by_len=collections.defaultdict(list)
    for start,size in sorted(funcs.items()):
        if size>16384:continue
        words=read_words(image,base,start,size)
        norm=normalize(words,start,base,len(image))
        calls=[]
        for i,w in enumerate(words):
            pc=start+i*4
            b=branch(pc,w)
            if b and b[0] in funcs and b[0]!=start and (b[1] or not start<=b[0]<start+size):
                calls.append((pc,b[0],b[1]))
        rows[start]={"words":words,"norm":norm,"calls":calls}
        by_sig[norm].append(start)
        by_len[len(norm)].append(start)
    return rows,by_sig,by_len

def candidates(row,other,by_sig,by_len):
    norm=row["norm"]
    exact=by_sig.get(norm,[])
    if exact:return {"kind":"exact_normalized","addresses":exact}
    # Register/constant differences may prevent exact matching. For longer
    # routines report only very close same-length candidates, with no claim.
    if len(norm)<12:return {"kind":"none","addresses":[]}
    close=[]
    for address in by_len.get(len(norm),[]):
        n=other[address]["norm"]
        equal=sum(a==b for a,b in zip(norm,n))
        if equal*100>=len(norm)*88:
            close.append((equal,address))
    close.sort(reverse=True)
    return {"kind":"near_normalized" if close else "none",
            "addresses":[a for _,a in close[:8]],
            "equal_words":[n for n,_ in close[:8]]}

def main():
    from prepare_recompilation import ROOT,original,sha,EXPECTED
    from decode_image import decode
    from pirs import parse
    from xex import parse as parse_xex
    from analyze_decoded import pe_info,ordinal_exports,imports
    from metro_import_contracts import DIGESTS,branch,hx
    from metro_xam_fault_evidence import bounded_entry
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    xam=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(xam)!=EXPECTED["xam_17559"]:raise ValueError("wrong XAM source")
    raw={"dash":original("dash_basic"),"xam":xam}
    modules={}
    for label,data in raw.items():
        image,meta=decode(data,a.lzx.resolve())
        if meta["sha256"]!=DIGESTS[label]:raise ValueError("wrong decoded identity")
        base=meta["image_base"];pe=pe_info(image,base)
        funcs={entry:size for entry,size,_ in pe["functions"]}
        rows,by_sig,by_len=inventory(image,base,funcs)
        modules[label]={"image":image,"base":base,"pe":pe,"funcs":funcs,
                        "rows":rows,"by_sig":by_sig,"by_len":by_len}
    x,d=modules["xam"],modules["dash"]
    exports=dict(ordinal_exports(x["image"],x["base"],xam))
    # The documented named functions are actual ordinal entries, not guessed
    # absolute addresses. Include their internal direct callees up to depth 3.
    roots={exports[o]:name for o,name in EXPORTS.items() if o in exports}
    if len(roots)!=len(EXPORTS):raise ValueError("missing original export")
    depth={entry:0 for entry in roots};queue=collections.deque(sorted(roots))
    # Include independently matched font wrapper pairs as normalization controls.
    for entry in KNOWN:
        if entry not in x["rows"]:raise ValueError("missing control function")
    while queue:
        entry=queue.popleft()
        if depth[entry]>=3:continue
        for _,callee,_ in x["rows"].get(entry,{}).get("calls",[]):
            if callee not in depth and len(depth)<400:
                depth[callee]=depth[entry]+1;queue.append(callee)
    report={"exports":{},"controls":{},"nodes":{},"scope":"Original normalized PPC comparison; ambiguous matches are not function identities."}
    matches={}
    for entry in sorted(set(depth)|set(KNOWN)):
        row=x["rows"].get(entry)
        if not row:continue
        c=candidates(row,d["rows"],d["by_sig"],d["by_len"])
        matches[entry]=c
    for entry,name in roots.items():
        c=matches.get(entry,{"kind":"missing","addresses":[]})
        report["exports"][name]={"xam":hx(entry),"kind":c["kind"],"dashboard":[hx(v) for v in c["addresses"]]}
    for xam_entry,dash_entry in KNOWN.items():
        c=matches[xam_entry]
        report["controls"][hx(xam_entry)]={"expected":hx(dash_entry),"kind":c["kind"],
                                           "found":dash_entry in c["addresses"]}
    for entry,dep in sorted(depth.items()):
        row=x["rows"].get(entry)
        if not row:continue
        c=matches[entry]
        item={"depth":dep,"words":len(row["norm"]),"hash":signature(row["norm"]),
              "kind":c["kind"],"dashboard":[hx(v) for v in c["addresses"]],
              "calls":[{"site":hx(pc),"target":hx(target),"linked":linked}
                       for pc,target,linked in row["calls"]]}
        if "equal_words" in c:item["equal_words"]=c["equal_words"]
        # Compare corresponding direct call positions in unique exact matches.
        if c["kind"]=="exact_normalized" and len(c["addresses"])==1:
            target=c["addresses"][0];dr=d["rows"][target]
            by_offset={pc-target:(callee,linked) for pc,callee,linked in dr["calls"]}
            item["paired_calls"]=[{"xam_site":hx(pc),"xam_target":hx(callee),
                                   "dash_site":hx(target+pc-entry),"dash_target":hx(by_offset[pc-entry][0]),
                                   "linked":linked}
                                   for pc,callee,linked in row["calls"] if pc-entry in by_offset and by_offset[pc-entry][1]==linked]
            if dep<=1 or len(row["norm"])<=128:
                item["xam_operands"]=bounded_entry(x["image"],x["base"],x["pe"],entry,{},4096)["operands"]
                item["dashboard_operands"]=bounded_entry(d["image"],d["base"],d["pe"],target,{},4096)["operands"]
        report["nodes"][hx(entry)]=item
    report["counts"]={"nodes":len(report["nodes"]),"unique_exact":sum(v["kind"]=="exact_normalized" and len(v["dashboard"])==1 for v in report["nodes"].values()),
                      "ambiguous_exact":sum(v["kind"]=="exact_normalized" and len(v["dashboard"])>1 for v in report["nodes"].values()),
                      "near":sum(v["kind"]=="near_normalized" for v in report["nodes"].values())}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("XUI cross-module",report["counts"],"controls",report["controls"])
    print("XUI exports",report["exports"])
if __name__=="__main__":main()
