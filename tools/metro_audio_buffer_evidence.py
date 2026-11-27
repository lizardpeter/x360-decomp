#!/usr/bin/env python3
"""Recover the original XAM audio processor buffer constructors and virtual getters.

Only addresses, operand descriptions and bounded direct-call evidence are emitted.
No patched guest code, original executable or resource payload is exported.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

from analyze_decoded import imports, pe_info
from decode_image import decode
from metro_import_contracts import DIGESTS, branch, hx, library, sdk_catalog, variable_reference
from metro_xam_fault_evidence import bounded_entry, operand
from metro_live_slot_and_input_evidence import executable, read_word
from pirs import parse
from prepare_recompilation import EXPECTED, ROOT, original, sha
from xex import parse as parse_xex

GLOBAL = 0x81B5B5E4
CALLBACK = 0x819AE4E8
GETTER_CALL = 0x819AF988
ROUTE_CALL = 0x819AF9F4
ROUTE = 0x819A7918
ENGINE_RANGE = (0x819A4000, 0x819BA000)
MASK = 0xffffffff

# Expression: object identity (or None), constant offset, coefficient of
# the guest processor byte. This never substitutes a concrete host address.
# Registers whose meaning is not proven in this basic block stay unknown.
def add(a,b):
    if a is None or b is None or (a[0] is not None and b[0] is not None):
        return None
    return (a[0] or b[0],(a[1]+b[1])&MASK,a[2]+b[2])

def scaled_cpu(a,shift,begin,end):
    if a is None or a[0] is not None or a[1] or not a[2]:
        return None
    # CPU range is 0..5. The original rotate/mask must act exactly as
    # multiplication throughout that domain, not merely for CPU 0.
    mask=sum(1<<(31-i) for i in range(32)
             if (begin<=i<=end if begin<=end else i>=begin or i<=end))
    for cpu in range(6):
        val=(a[2]*cpu)&MASK
        rot=((val<<shift)|(val>>(32-shift)))&MASK if shift else val
        if rot&mask != a[2]*cpu*(1<<shift):
            return None
    return (None,0,a[2]*(1<<shift))

def expr_json(x):
    return {"object":x[0],"constant":hx(x[1]),"processor_multiplier":x[2]} if x else None

def local_accesses(words,start,slot=GLOBAL):
    """Block-local proof of absolute, processor-indexed, and object accesses.

    Start new blocks with no inherited volatile values. A call preserves only
    nonvolatile GPRs, as specified by the PPC ABI; its returned pointer remains
    an opaque call-site value. No cross-branch or heap alias is assumed.
    """
    targets=set()
    for i,w in enumerate(words):
        pc=start+4*i
        d=branch(pc,w)
        if d and not d[1]:targets.add(d[0])
        elif w>>26==16:
            raw=w&0xfffc
            if raw&0x8000:raw-=0x10000
            targets.add(((0 if w&2 else pc)+raw)&MASK)
    regs={13:("pcr",0,0),**{i:(f"arg{i}",0,0) for i in range(3,11)}}
    records=[]
    for i,w in enumerate(words):
        pc=start+4*i;op=w>>26
        if i and pc in targets:regs={13:("pcr",0,0)}
        d=operand(pc,w);kind=d["kind"]
        if kind in ("memory_load","memory_store","indexed_load","indexed_store"):
            base=d["base"];a=regs.get(base) if base else (None,0,0)
            address=add(a,regs.get(d["index"]) if "index" in d else (None,d["offset"],0))
            load=kind.endswith("load")
            val=None
            if address==(None,slot,0) and load and d["width"]==4:
                val=("audio_global_object",0,0)
            elif address==("pcr",268,0) and load and d["width"]==1:
                val=(None,0,1)
            if address is not None and (address==(None,slot,0) or address[0]=="audio_global_object" or
                    (address[0] and address[0].startswith(("arg","return@")) and
                    (address[2] or (not load and address[1] in range(12,60,4))))):
                records.append({"pc":hx(pc),"access":kind,"width":d["width"],
                                "address":expr_json(address),
                                "source":expr_json(regs.get(d.get("source"))) if not load else None})
            if load:
                if val is None:regs.pop(d["writes"],None)
                else:regs[d["writes"]]=val
            if d.get("update"):regs.pop(base,None)
            continue
        if op in (16,17,18,19):
            if op==18 and w&1 or kind=="indirect_branch" and d.get("linked"):
                regs={r:v for r,v in regs.items() if r in (1,2,13) or r>=14}
                regs[3]=(f"return@{hx(pc)}",0,0)
            else:regs={13:("pcr",0,0)}
            continue
        dst=d.get("writes");val=None
        if kind=="immediate":val=(None,d["value"]&MASK,0)
        elif kind=="register_offset":val=add(regs.get(d["base"]),(None,d["value"],0))
        elif kind=="register_copy":val=regs.get(d["source"])
        elif kind=="or_immediate":
            prev=regs.get(d["source"])
            if prev is not None and prev[0] is None and not prev[2]:
                val=(None,prev[1]|d["value"],0)
        elif kind=="arithmetic" and d["operation"]=="add":
            val=add(*(regs.get(r) for r in d["inputs"]))
        elif kind=="rotate_mask" and op==21:
            val=scaled_cpu(regs.get(d["source"]),d["shift_or_reg"],d["mask_start"],d["mask_end"])
        if dst is not None:
            if val is None:regs.pop(dst,None)
            else:regs[dst]=val
        elif kind not in ("compare_immediate","compare_register") and not (kind=="special_register" and d["operation"]=="write"):
            if kind=="special_register" and d["operation"]=="read":
                regs.pop(d["register"],None)
            else:
                regs={13:("pcr",0,0)}
    return records

def collect_functions(image,base,pe,thunks):
    functions={a:n for a,n,_ in pe["functions"]}
    incoming=collections.defaultdict(list);outgoing=collections.defaultdict(list)
    globals_by_owner={};audio_accesses={};table_materializations=collections.defaultdict(list)
    candidate_loads=[]
    for start,size in functions.items():
        words=[w for w, in struct.iter_unpack(">I",image[start-base:start-base+size])]
        in_audio=ENGINE_RANGE[0]<=start<ENGINE_RANGE[1]
        may_reference_global=any(w>>26==15 and not (w>>16)&31 and w&65535 in (0x81b5,0x81b6) for w in words)
        for i,w in enumerate(words):
            pc=start+4*i;dest=branch(pc,w)
            if dest:
                target,linked=dest
                if target in thunks or (target in functions and target!=start):
                    edge={"owner":hx(start),"site":hx(pc),"target":hx(target),"linked":linked}
                    if target in thunks:edge["import"]=thunks[target]
                    else:incoming[target].append(edge)
                    outgoing[start].append(edge)
            if i:
                ref=variable_reference(words[i-1],w)
                if ref and ref[1]=="address_construction" and base<=ref[0]<base+len(image):
                    table_materializations[ref[0]].append({"owner":hx(start),"site":hx(pc-4)})
                    if ref[0]==CALLBACK:candidate_loads.append({"owner":hx(start),"site":hx(pc-4)})
        if in_audio or may_reference_global:
            accesses=local_accesses(words,start)
            exact=[r for r in accesses if r["address"]["object"]=="audio_global_object" or
                   r["address"]=={"object":None,"constant":hx(GLOBAL),"processor_multiplier":0}]
            if exact:globals_by_owner[start]=exact
            if in_audio and accesses:audio_accesses[start]=accesses
    return functions,incoming,outgoing,globals_by_owner,audio_accesses,table_materializations,candidate_loads

def vtable_candidates(image,base,pe,materializations):
    # A table base must be a materialized original data address, not an
    # arbitrary sliding window of function pointers. The two slots must be
    # executable and part of a dense original audio method table.
    code_ranges=[(base+s["rva"],base+s["rva"]+s["loaded_bytes"]) for s in pe["sections"] if s["flags"]&0x20000000]
    data_ranges=[(base+s["rva"],base+s["rva"]+s["loaded_bytes"]) for s in pe["sections"]
                 if not s["flags"]&0x20000000 and s["name"] in (".rdata",".data")]
    is_code=lambda pc:any(a<=pc<b for a,b in code_ranges)
    rows=[]
    for addr,refs in sorted(materializations.items()):
        if addr%4 or not any(a<=addr and addr+88<=b for a,b in data_ranges):continue
        ptrs=[read_word(image,base,addr+4*i) for i in range(22)]
        if sum(is_code(p) for p in ptrs)<16:continue
        getter,route=ptrs[18],ptrs[21]
        if not all(is_code(x) for x in (getter,route)):continue
        if not any(ENGINE_RANGE[0]<=p<ENGINE_RANGE[1] for p in (getter,route)):continue
        rows.append({"candidate_table":hx(addr),"getter_slot_72":hx(getter),"route_slot_84":hx(route),
                     "executable_slots":sum(is_code(p) for p in ptrs),"materialized_by":refs,
                     "slot_targets":[hx(p) if is_code(p) else None for p in ptrs]})
    return rows

def graph(roots,outgoing,functions,max_depth=3,limit=220):
    queue=collections.deque((a,0) for a in sorted(set(roots)));seen={}
    edges=[]
    while queue and len(seen)<limit:
        a,depth=queue.popleft()
        if a in seen or a not in functions:continue
        seen[a]=depth
        for edge in outgoing[a]:
            edges.append(edge)
            target=int(edge["target"],16)
            if depth<max_depth and "import" not in edge:queue.append((target,depth+1))
    return seen,edges,bool(queue)

def audit(raw,lzx,sdk):
    image,meta=decode(raw,lzx)
    if sha(raw)!=EXPECTED["xam_17559"] or meta["sha256"]!=DIGESTS["xam"]:
        raise ValueError("original XAM identity differs")
    base=meta["image_base"];pe=pe_info(image,base)
    catalog,stubs=sdk_catalog(sdk);thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,_=catalog.get((lib,ordinal),("", "unknown"))
        for addr in row["thunk_slots"]:
            thunks[addr]={"library":lib,"ordinal":f"{ordinal:04X}","name":name,"sdk_stub":name in stubs}
    funcs,incoming,outgoing,globals_,audio,materializations,callback_refs=collect_functions(image,base,pe,thunks)
    tables=vtable_candidates(image,base,pe,materializations)
    global_writers={a for a,rows in globals_.items() if any(r["address"]["object"] is None and r["access"]=="memory_store" for r in rows)}
    exact_object_writers={a for a,rows in globals_.items() if any(r["address"]["object"]=="audio_global_object" and r["access"].endswith("store") for r in rows)}
    roots={CALLBACK,0x819AC540,0x819AF968,ROUTE,0x819AFF80,0x819A5878,
           0x819A5A98,0x819A5E40,0x819A4570,0x819A44E0,0x819AE908,
           0x819A56B8,0x819A5780,0x819A7658}|global_writers|exact_object_writers
    for t in tables:
        roots.update(int(t[k],16) for k in ("getter_slot_72","route_slot_84"))
        roots.update(int(r["owner"],16) for r in t["materialized_by"])
    roots.update(int(r["owner"],16) for r in callback_refs)
    seen,edges,truncated=graph(roots,outgoing,funcs)
    # Extract original bodies only for evidence-backed roots and likely
    # processor-indexed fields, not the entire recursively linked library.
    focused=roots|{a for a in seen if a in audio and any(r["address"]["processor_multiplier"] for r in audio[a])}
    bodies={hx(a):bounded_entry(image,base,pe,a,thunks,2048) for a in sorted(focused) if executable(pe,base,a)}
    pointer_sites=[]
    for sec in pe["sections"]:
        if sec["flags"]&0x20000000:continue
        for off in range(sec["rva"],sec["rva"]+sec["loaded_bytes"]-3,4):
            word=read_word(image,base,base+off)
            if word in (CALLBACK,ROUTE,0x819AE6D0,0x819AF968):
                pointer_sites.append({"address":hx(base+off),"target":hx(word),"section":sec["name"]})
    getter=operand(GETTER_CALL,read_word(image,base,GETTER_CALL))
    route=operand(ROUTE_CALL,read_word(image,base,ROUTE_CALL))
    if any(x["kind"]!="indirect_branch" or not x["linked"] for x in (getter,route)):
        raise ValueError("observed virtual call identity differs")
    # Validate exact original constructor calls and output-slot arithmetic.
    def op_at(pc):
        return operand(pc,read_word(image,base,pc))
    for site,target in ((0x819A5C98,0x819A4570),(0x819A5DC4,0x819A44E0)):
        if branch(site,read_word(image,base,site))!=(target,True):
            raise ValueError("original processor initialization edge changed")
    checks={
        0x819A5D94:{"kind":"register_offset","writes":11,"base":1,"value":98},
        0x819A5D98:{"kind":"indexed_load","writes":11,"base":28,"index":11,"width":1},
        0x819A5DB0:{"kind":"arithmetic","operation":"add","writes":11,"inputs":[30,31]},
        0x819A5DBC:{"kind":"rotate_mask","writes":11,"source":11,"shift_or_reg":2,"mask_start":0,"mask_end":29},
        0x819A5DC0:{"kind":"arithmetic","operation":"add","writes":5,"inputs":[11,29]},
        0x819A5DD8:{"kind":"register_offset","writes":30,"base":30,"value":2},
        0x819A5DDC:{"kind":"register_offset","writes":28,"base":28,"value":1},
    }
    for site,expected in checks.items():
        if op_at(site)!=expected:
            raise ValueError("processor buffer argument changed at "+hx(site))
    wrapper=[op_at(CALLBACK+4*j) for j in range(3)]
    if not (wrapper[0].get("writes")==11 and wrapper[0].get("kind")=="immediate" and
            wrapper[1].get("kind")=="memory_load" and wrapper[1].get("writes")==3 and
            wrapper[1].get("base")==11 and (wrapper[0]["value"]+wrapper[1]["offset"])&MASK==GLOBAL and
            branch(CALLBACK+8,read_word(image,base,CALLBACK+8))==(0x819A5878,False)):
        raise ValueError("registered callback wrapper changed")
    proof={"constructor":"819A5A98","configuration_helper":"819A4570",
           "configuration_call":"819A5C98","processor_flags_stack_offset":98,
           "processor_count":6,"buffer_count_per_enabled_processor":2,
           "buffer_allocator":"819A44E0","buffer_allocator_call":"819A5DC4",
           "output_slot_formula":"engine + 12 + 8 * processor + 4 * pair",
           "output_slot_offsets":[[12+8*j,16+8*j] for j in range(6)],
           "wrapper_loads_global_and_tail_calls":"819A5878",
           "verified_operand_sites":[hx(x) for x in checks],
           "configuration_selection_is_runtime_dependent":True}
    return {"source_runs":[45963619361,45965406811],"processor_buffer_construction":proof,"module_sha256":sha(raw),
            "decoded_sha256":meta["sha256"],"global_slot":hx(GLOBAL),
            "initial_word":hx(read_word(image,base,GLOBAL)),
            "registered_callback":hx(CALLBACK),"getter_call":hx(GETTER_CALL),
            "route_call":hx(ROUTE_CALL),"absolute_and_object_references":{hx(a):v for a,v in globals_.items()},
            "global_writer_entries":[hx(a) for a in sorted(global_writers)],
            "global_object_writer_entries":[hx(a) for a in sorted(exact_object_writers)],
            "processor_indexed_accesses":{hx(a):[r for r in rows if r["address"]["processor_multiplier"]]
                for a,rows in audio.items() if any(r["address"]["processor_multiplier"] for r in rows)},
            "callback_address_constructions":callback_refs,"original_pointer_sites":pointer_sites,
            "candidate_vtables":tables,"focused_functions":bodies,
            "incoming_edges":[e for a in sorted(roots) for e in incoming[a]],
            "construction_graph_nodes":{hx(a):d for a,d in seen.items()},"construction_graph_edges":edges,
            "graph_truncated":truncated,
            "scope":"Conservative block-local expressions, actual static references and candidate vtables. No proof of live aliasing or runtime callback processor policy."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    raw=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    d=audit(raw,a.lzx.resolve(),a.sdk)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(d,indent=2,sort_keys=True)+"\n")
    for k in ("global_writer_entries","global_object_writer_entries","processor_indexed_accesses","candidate_vtables","focused_functions","construction_graph_nodes","callback_address_constructions"):
        print(k,len(d[k]))
    print("Global writer entries:",d["global_writer_entries"])
    print("Verified processor-buffer construction:",d["processor_buffer_construction"])
    print("Getter candidates:",[(r["candidate_table"],r["getter_slot_72"],r["route_slot_84"]) for r in d["candidate_vtables"]])
if __name__=="__main__":main()
