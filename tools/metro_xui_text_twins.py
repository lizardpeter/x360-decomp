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

# Original lower-level font measurement callees observed at exact paired
# direct-call offsets in run 46068603654. These are paired call targets,
# not claims that the entire callee bodies are equivalent.
MEASURE_FOCUS={0x81790D30:0x92225430,0x817937D8:0x92228030,0x81793640:0x92227E98,
               0x817945A0:0x92228DF8,0x81794880:0x922290D8,
               0x817A9310:0x921EB708,0x817EBFD0:0x92211650,
               0x81730DD0:0x9219A160}

def incoming_calls(rows,targets):
    result={target:[] for target in targets}
    for owner,row in sorted(rows.items()):
        for pc,target,linked in row["calls"]:
            if target in result:result[target].append((owner,pc,linked))
    return result

def fp_measurement(words,start):
    """Expose scalar FP instructions and exact adjacent stack bit transfers."""
    from metro_bootanim_evidence import phase_fp_instruction
    from metro_import_contracts import hx
    from metro_xam_fault_evidence import operand
    fp=[phase_fp_instruction(word) for word in words]
    operations=[{"pc":hx(start+i*4),**dec} for i,dec in enumerate(fp) if dec]
    bridges=[]
    for i in range(len(words)-1):
        a,b=fp[i],fp[i+1]
        if a and a["op"]=="stfd" and a["base"]==1:
            nxt=operand(start+(i+1)*4,words[i+1])
            if nxt.get("kind")=="memory_load" and nxt.get("base")==1:
                width=nxt["width"];offset=nxt["offset"]-a["offset"]
                if (width,offset) in ((4,0),(4,4),(8,0)):
                    bridges.append({"kind":"fpr_bits_to_gpr","store":hx(start+i*4),
                        "load":hx(start+(i+1)*4),"fpr":a["fpr"],"gpr":nxt["writes"],
                        "stack_offset":a["offset"],"load_byte_offset":offset,"width":width})
        if b and b["op"]=="lfd" and b["base"]==1:
            prev=operand(start+i*4,words[i])
            if (prev.get("kind"),prev.get("base"),prev.get("offset"),prev.get("width"))==(
                    "memory_store",1,b["offset"],8) and (words[i]>>26)==62:
                bridges.append({"kind":"gpr_bits_to_fpr","store":hx(start+i*4),
                    "load":hx(start+(i+1)*4),"gpr":prev["source"],"fpr":b["fpr"],
                    "stack_offset":b["offset"],"width":8})
    return {"operations":operations,"counts":dict(collections.Counter(x["op"] for x in operations)),
            "adjacent_stack_transfers":bridges}

def focus_report(modules):
    from metro_import_contracts import hx
    from metro_xam_fault_evidence import bounded_entry,operand
    result={}
    for label,targets in (("xam",MEASURE_FOCUS.keys()),("dash",MEASURE_FOCUS.values())):
        m=modules[label];incoming=incoming_calls(m["rows"],targets)
        report={}
        for target in targets:
            if target not in m["rows"]:
                # The paired scalar helper may be a leaf without PDATA.
                # Verify the two real incoming calls and inspect only a
                # bounded executable prefix, never assert a guessed extent.
                from metro_import_contracts import branch
                owner,sites=({"xam":(0x81790D30,(0x81790D50,0x81790D7C)),
                              "dash":(0x92225430,(0x92225450,0x9222547C))})[label]
                if target!={"xam":0x81730DD0,"dash":0x9219A160}[label]:
                    raise ValueError("missing measured text target "+hx(target))
                for site in sites:
                    if branch(site,read_words(m["image"],m["base"],site,4)[0])!=(target,True):
                        raise ValueError("original scalar helper call differs")
                body=bounded_entry(m["image"],m["base"],m["pe"],target,{},256)
                words=read_words(m["image"],m["base"],target,body["bounded_length"])
                report[hx(target)]={"body":body,"direct_callers":[
                    {"caller":hx(owner),"site":hx(site),"linked":True} for site in sites],
                    "caller_scope":"two verified call sites; no full incoming census",
                    "floating_point":fp_measurement(words,target)}
                continue
            rows=[]
            for owner,pc,linked in incoming[target]:
                words=m["rows"][owner]["words"];i=(pc-owner)//4
                rows.append({"caller":hx(owner),"site":hx(pc),"linked":linked,
                             "operands":[{"pc":hx(owner+j*4),**operand(owner+j*4,words[j])}
                                for j in range(max(0,i-12),min(len(words),i+9))]})
            report[hx(target)]={"body":bounded_entry(m["image"],m["base"],m["pe"],target,{},min(m["funcs"][target],16384)),
                                "direct_callers":rows,
                                "floating_point":fp_measurement(m["rows"][target]["words"],target)}
        result[label]={"targets":report,"inventory_functions":len(m["rows"]),
                       "omitted_large_functions":len(m["funcs"])-len(m["rows"])}
    # Compare the actual original FP operation sequences at corresponding
    # offsets. Preserve differing operands rather than normalizing them away.
    result["paired_floating_point"]={}
    for x,d in MEASURE_FOCUS.items():
        lhs=result["xam"]["targets"][hx(x)]["floating_point"]["operations"]
        rhs=result["dash"]["targets"][hx(d)]["floating_point"]["operations"]
        def relative(ops,base):
            return [{"offset":int(o["pc"],16)-base,**{k:v for k,v in o.items() if k!="pc"}}
                    for o in ops]
        result["paired_floating_point"][hx(x)]={"dash":hx(d),"xam_ops":len(lhs),
            "dash_ops":len(rhs),"identical_relative_operands":(
                relative(lhs,x)==relative(rhs,d) if
                result["xam"]["targets"][hx(x)]["body"]["extent_verified"] and
                result["dash"]["targets"][hx(d)]["body"]["extent_verified"] else None)}
    return result

def verify_extent_contract(modules):
    # This is the rounding wrapper's scalar, signed contract, independent
    # of a font object or XUI initialization. Prove the actual instruction
    # and constants before interpreting the native fixture's result.
    from metro_import_contracts import hx,branch
    from metro_bootanim_evidence import phase_fp_instruction
    from metro_xam_fault_evidence import executable
    result={}
    for label,wrapper,helper in (("xam",0x81790D30,0x81730DD0),
                                 ("dash",0x92225430,0x9219A160)):
        m=modules[label];image,base,pe=m["image"],m["base"],m["pe"]
        def word(pc):return read_words(image,base,pc,4)[0]
        def fp(pc):return phase_fp_instruction(word(pc))
        # fsel operands follow the PPC FRC if nonnegative, FRB otherwise.
        expected={0:{"op":"fctidz","dest":12,"src":1},
            8:{"op":"fabs","dest":11,"src":1},
            24:{"op":"fcfid","dest":12,"src":12},
            28:{"op":"fsub","dest":0,"a":0,"b":11},
            32:{"op":"fneg","dest":11,"src":11},
            36:{"op":"fsub","dest":10,"a":12,"b":1},
            40:{"op":"fadd","dest":13,"a":12,"b":13},
            44:{"op":"fsel","dest":13,"a":10,"b":13,"c":12},
            48:{"op":"fsel","dest":0,"a":0,"b":1,"c":13},
            52:{"op":"fsel","dest":1,"a":11,"b":0,"c":1}}
        if any(fp(helper+off)!=v for off,v in expected.items()) or word(helper+56)!=0x4e800020:
            raise ValueError("original scalar helper instruction contract")
        constants=[]
        for hi_off,load_off,reg in ((4,16,11),(12,20,10)):
            w=word(helper+hi_off);load=fp(helper+load_off)
            if w>>26!=15 or ((w>>16)&31)!=0 or ((w>>21)&31)!=reg or load["op"]!="lfd" or load["base"]!=reg:
                raise ValueError("scalar constant operands")
            address=(((w&65535)<<16)+load["offset"])&0xffffffff
            if not base<=address<=base+len(image)-8 or executable(pe,base,address):
                raise ValueError("scalar constant outside original data")
            constants.append((address,struct.unpack_from(">d",image,address-base)[0]))
        if constants[0][1]!=1.0 or constants[1][1] < 2**52 or constants[1][1]>2**63:
            raise ValueError("unexpected rounding constants")
        for off in (32,76):
            if branch(wrapper+off,word(wrapper+off))!=(helper,True):
                raise ValueError("scalar wrapper call mismatch")
        # neg r11,r11; cmpw cr6,r31,r11; bge cr6,second rounding call.
        if (word(wrapper+52)&0xfffffffe)!=0x7d6b00d0 or word(wrapper+56)!=0x7f1f5800:
            raise ValueError("original signed extent comparison")
        result[label]={"wrapper":hx(wrapper),"helper":hx(helper),
            "helper_linear_bytes":60,"constants":[{"address":hx(a),"value":v} for a,v in constants],
            "fixture_domain":"finite small f32 offsets; signed extents; max(0, extent+ceil(offset))"}
    return result

def verify_new_header_boundaries(modules):
    from metro_import_contracts import branch,hx
    from metro_xam_fault_evidence import operand
    from instrument_metro_ui import HEADER_POINTS
    # Exact paired wrapper entry and continuation. Validate actual argument
    # setup and copied pointer field rather than relying on a guessed ABI.
    checks={"xam":(0x817A9310,0x817A9350,0x817A9378,0x8172F2A8,
                   0x817BE0D8,0x817BE100,0x817EBFD0,0x817EC090),
            "dash":(0x921EB708,0x921EB748,0x921EB770,0x92198D90,
                    0x921E0428,0x921E0450,0x92211650,0x92211710)}
    result={}
    for label,(prop,store,copy,copy_target,lookup,lookup_call,lookup_target,pointer_load) in checks.items():
        m=modules[label];image=m["image"];base=m["base"]
        def word(pc):return struct.unpack_from(">I",image,pc-base)[0]
        def op(pc):return operand(pc,word(pc))
        if prop not in m["rows"] or lookup not in m["rows"]:raise ValueError("missing text wrapper")
        if branch(copy,word(copy))!=(copy_target,True) or branch(lookup_call,word(lookup_call))!=(lookup_target,True):
            raise ValueError("changed original text call")
        o=op(store)
        if (o.get("kind"),o.get("base"),o.get("offset"),o.get("source"),o.get("width"))!=("memory_store",31,4,3,4):
            raise ValueError("changed property destination")
        o=op(pointer_load)
        if (o.get("kind"),o.get("base"),o.get("offset"),o.get("writes"),o.get("width"))!=("memory_load",11,4,3,4):
            raise ValueError("changed resource pointer result")
        module="generated" if label=="dash" else "generated_xam"
        probes=HEADER_POINTS[module]
        if any(probes[pc][2]!=reg for pc,reg in ((prop,4),(copy+4,31),(lookup_call+4,3))):
            raise ValueError("changed header trace plan")
        result[label]={"property_entry":hx(prop),"property_pointer_store":hx(store),
                       "property_post_copy":hx(copy+4),"lookup_post_call":hx(lookup_call+4),
                       "lookup_pointer_load":hx(pointer_load)}
    return result

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
    report["measurement_focus"]=focus_report(modules)
    report["header_boundaries"]=verify_new_header_boundaries(modules)
    report["extent_contract"]=verify_extent_contract(modules)
    print("Verified original scalar extent contract",report["extent_contract"])
    print("Verified original header boundaries",report["header_boundaries"])
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("XUI cross-module",report["counts"],"controls",report["controls"])
    print("XUI exports",report["exports"])
if __name__=="__main__":main()
