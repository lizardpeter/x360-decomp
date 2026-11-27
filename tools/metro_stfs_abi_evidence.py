#!/usr/bin/env python3
"""Recover original STFS request accesses and control argument contracts.

Static evidence only: does not mount a profile or infer secret-bearing
account contents. A small conservative PPC register/stack provenance pass
keeps only equal facts at joins, and forgets volatile facts across calls.
Unrecognized instructions/paths do not become assumed valid ABI fields.
"""
import argparse
import collections
import json
import struct
from pathlib import Path
from analyze_decoded import imports,pe_info
from decode_image import decode
from metro_import_contracts import branch,hx,library,sdk_catalog,registers
from metro_xam_fault_evidence import operand,conditional_details,bounded_entry
from metro_storage_boundary import STORAGE_ORDINALS
from pirs import parse
from prepare_recompilation import ROOT,EXPECTED,sha,original
from xex import parse as parse_xex

CREATE={
    0x81680A74:(0x816808C8,176),
    0x816871B8:(0x81686DA0,160),
    0x8192B598:(0x8192B4B8,128),
}
CONTROL={
    0x8167C1F4:(0x8167C198,5),
    0x8167C678:(0x8167C628,0),
    0x8167C7EC:(0x8167C628,1),
    0x81680EA4:(0x81680E60,0),
    0x81680EB4:(0x81680E60,2),
    0x81680ECC:(0x81680E60,3),
    0x81680F64:(0x81680E60,4),
    0x81680FA4:(0x81680E60,1),
    0x8192B5D0:(0x8192B4B8,3),
    0x8192BDDC:(0x8192BDB8,0),
    0x8192BDEC:(0x8192BDB8,2),
    0x8192BE18:(0x8192BDB8,3),
    0x8192BE8C:(0x8192BDB8,4),
    0x8192BE9C:(0x8192BDB8,1),
}
REQUEST_SIZE=88
VOLATILE={0,*range(3,13)}
MAX_OPS=16384
MASK=0xffffffff

def value(kind,*args):
    return (kind,*args)

def add(a,delta):
    if not a:return None
    if a[0]=="const":return value("const",(a[1]+delta)&MASK)
    if a[0]=="stack":return value("stack",a[1]+delta)
    if a[0]=="offset":
        return value("offset",a[1],a[2]+delta) if abs(a[2]+delta)<1<<24 else None
    if a[0] in ("argument","load","return"):
        return value("offset",a,delta) if delta else a
    return None

def mem(base,offset,width):
    address=add(base,offset)
    if not address:return None
    # Limit expression depth to avoid a changing value in an original loop
    # growing without bound. Stack load is distinct from a known stored value.
    def depth(v):
        return 1+max((depth(x) for x in v[1:] if isinstance(x,tuple)),default=0)
    return value("load",address,width) if depth(address)<4 else None

def render(v):
    if not v:return None
    k=v[0]
    if k=="const":return {"kind":k,"value":v[1]}
    if k=="stack":return {"kind":k,"entry_sp_offset":v[1]}
    if k=="argument":return {"kind":k,"register":v[1]}
    if k=="return":return {"kind":k,"callsite":hx(v[1]),"target":hx(v[2]) if v[2] else None}
    if k=="offset":return {"kind":k,"base":render(v[1]),"offset":v[2]}
    if k=="load":return {"kind":k,"address":render(v[1]),"width":v[2]}
    raise ValueError(k)

def successors(pc,word,start,end):
    op=word>>26
    def inside(a):return start<=a<end and a%4==0
    dest=branch(pc,word)
    if dest:
        target,link=dest
        return [pc+4] if link and inside(pc+4) else [target] if not link and inside(target) else []
    if op==16:
        detail=conditional_details(pc,word)
        # Conditional link is not an unconditional call. Retain both possible
        # control-flow paths where they stay within the bounded body.
        return sorted({a for a in (pc+4,int(detail["target"],16)) if inside(a)})
    if op==19 and (word>>1)&1023 in (16,528,50):
        return [pc+4] if word&1 and inside(pc+4) else []
    return [pc+4] if inside(pc+4) else []

def transfer(state,pc,word):
    regs,spills=state
    regs=dict(regs);spills=dict(spills)
    row=operand(pc,word);k=row["kind"];op=word>>26
    r,a,b=registers(word)
    def setreg(reg,v):
        if v is None:regs.pop(reg,None)
        else:regs[reg]=v
    def flush_range(offset,width):
        for key in list(spills):
            if key[0]<offset+width and offset<key[0]+key[1]:del spills[key]
    def addr(reg,offset):
        return add(regs.get(reg),offset) if reg else value("const",offset&MASK)
    if k=="immediate":
        setreg(row["writes"],value("const",row["value"]&MASK))
    elif k=="register_offset":
        setreg(row["writes"],add(regs.get(row["base"]),row["value"]))
    elif k=="register_copy":
        setreg(row["writes"],regs.get(row["source"]))
    elif k=="memory_load":
        address=addr(row["base"],row["offset"])
        v=spills.get((address[1],row["width"])) if address and address[0]=="stack" else None
        setreg(row["writes"],v or mem(regs.get(row["base"]),row["offset"],row["width"]))
        # ld/lwa update forms cannot be treated as non-updating loads.
        if op==58 and word&3==1:setreg(row["base"],address)
    elif k=="memory_store":
        address=addr(row["base"],row["offset"])
        if address and address[0]=="stack":
            flush_range(address[1],row["width"])
            if (v:=regs.get(row["source"])) is not None:
                spills[(address[1],row["width"])]=v
        elif not address or address[0]!="const":
            # An unproved alias might write an escaped stack slot.
            spills.clear()
        if row.get("update"):setreg(row["base"],address)
    elif k=="indexed_load":
        index=regs.get(row["index"])
        effective=addr(row["base"],index[1]) if index and index[0]=="const" else None
        setreg(row["writes"],mem(effective,0,row["width"]))
        if (word>>1)&1023 in (55,119,311,375,53):setreg(row["base"],effective)
    elif k=="indexed_store":
        spills.clear()
        if (word>>1)&1023 in (183,247,439,181):setreg(row["base"],None)
    elif k=="or_immediate":
        v=regs.get(row["source"])
        setreg(row["writes"],value("const",v[1]|row["value"]) if v and v[0]=="const" else None)
    elif op in (25,26,27,28,29):
        v=regs.get(r);imm=(word&65535)<<(16 if op in (25,27,29) else 0)
        if v and v[0]=="const":
            n=v[1]|imm if op==25 else v[1]^imm if op in (26,27) else v[1]&imm
            setreg(a,value("const",n&MASK))
        else:setreg(a,None)
    elif k=="arithmetic":
        x,y=(regs.get(i) for i in row["inputs"])
        v=None
        if row["operation"]=="add":
            if y and y[0]=="const":v=add(x,y[1] if y[1]<1<<31 else y[1]-(1<<32))
            elif x and x[0]=="const":v=add(y,x[1] if x[1]<1<<31 else x[1]-(1<<32))
        setreg(row["writes"],v)
    elif k in ("rotate_mask","logical","arithmetic_shift_right_immediate"):
        setreg(row["writes"],None)
    elif k=="special_register":
        if row["operation"]=="read":setreg(row["register"],None)
    elif k in ("branch","indirect_branch","conditional_branch"):
        linked=bool(word&1)
        if linked:
            for reg in VOLATILE:regs.pop(reg,None)
            dest=branch(pc,word)
            # Unknown calls may mutate escaped stack storage, so discard
            # spilled-value facts, even though direct access evidence survives.
            spills.clear()
            if k=="branch":regs[3]=value("return",pc,dest[0] if dest else None)
    elif k in ("compare_immediate","compare_register","return"):
        pass
    elif op==30:
        setreg(a,None) # 64-bit rotate/mask forms
    elif op in (7,8,12,13,33,35,41,43):
        setreg(r,None)
        if op in (33,35,41,43):setreg(a,None)
    elif op in (48,49,50,51): # Floating loads do not write integer registers except update.
        if op in (49,51):setreg(a,None)
    elif k=="unclassified":
        # Unknown primary form: no positive claims about nonvolatile values.
        keep=regs.get(1) if 1 not in (r,a,b) else None
        regs.clear();spills.clear()
        if keep:regs[1]=keep
    return regs,spills

def merge(a,b):
    return tuple({k:v for k,v in left.items() if right.get(k)==v}
                 for left,right in zip(a,b))

def flow(words,start):
    end=start+len(words)*4
    if len(words)>MAX_OPS:raise ValueError("oversized original ABI body")
    graph={start+i*4:successors(start+i*4,w,start,end) for i,w in enumerate(words)}
    states={start:({1:value("stack",0),**{r:value("argument",r) for r in range(3,11)}},{})}
    todo=collections.deque([start]);queued={start};iterations=0
    while todo:
        pc=todo.popleft();queued.remove(pc);iterations+=1
        if iterations>MAX_OPS*64:raise ValueError("ABI fixed point did not converge")
        state=transfer(states[pc],pc,words[(pc-start)//4])
        for nxt in graph[pc]:
            new=state if nxt not in states else merge(states[nxt],state)
            if nxt not in states or new!=states[nxt]:
                states[nxt]=new
                if nxt not in queued:todo.append(nxt);queued.add(nxt)
    return graph,states

def reachable(graph,root,stop=None):
    seen=set();todo=collections.deque([root])
    while todo:
        pc=todo.popleft()
        if pc in seen or pc==stop or pc not in graph:continue
        seen.add(pc);todo.extend(graph[pc])
    return seen

def owner_data(image,base,pe,entry,thunks):
    lengths=[s for a,s,_ in pe["functions"] if a==entry]
    if len(lengths)!=1 or lengths[0]%4:raise ValueError("expected exact original function owner")
    n=lengths[0];words=[w for w, in struct.iter_unpack(">I",image[entry-base:entry-base+n])]
    if len(words)*4!=n:raise ValueError("truncated original function")
    graph,states=flow(words,entry)
    # Existing operand decoder and original import annotation. Keep every
    # bounded owner rather than only a 16-instruction preceding window.
    body=bounded_entry(image,base,pe,entry,thunks,n)
    return words,graph,states,body

def prove_create(site,frame,entry,words,graph,states,body,thunks):
    def word(pc):return words[(pc-entry)//4]
    def op(pc):return operand(pc,word(pc))
    # Exact nearby r3=sp+offset and r4=88 writes in each original caller.
    previous=[op(pc) for pc in range(site-16,site,4)]
    p3=[o for o in previous if o.get("writes")==3]
    p4=[o for o in previous if o.get("writes")==4]
    if not p3 or p3[-1]!={"kind":"register_offset","writes":3,"base":1,"value":frame}:
        raise ValueError("request pointer proof differs "+hx(site))
    if not p4 or p4[-1].get("kind")!="immediate" or p4[-1].get("value")!=REQUEST_SIZE:
        raise ValueError("request extent proof differs "+hx(site))
    compare=op(site+4)
    if compare.get("kind")!="compare_immediate" or compare["register"]!=3 or compare["value"]!=0 or compare["unsigned"]:
        raise ValueError("signed create status test differs")
    gate=conditional_details(site+8,word(site+8))
    if gate["cr_test"] not in ({"field":0,"bit":"lt","sense":"set"},{"field":0,"bit":"lt","sense":"clear"}):
        raise ValueError("create status branch differs")
    target=int(gate["target"],16);fall=site+12
    success=fall if gate["cr_test"]["sense"]=="set" else target
    failure=target if success==fall else fall
    reverse=collections.defaultdict(list)
    for pc,edges in graph.items():
        for nxt in edges:reverse[nxt].append(pc)
    incoming=reachable(reverse,site) if site in reverse else set()
    success_nodes=reachable(graph,success,stop=site)
    failure_nodes=reachable(graph,failure,stop=site)
    writes=[];reads=[];escapes=[]
    req_sp=states.get(site,({},{}))[0].get(1)
    req=add(req_sp,frame)
    for i,w in enumerate(words):
        pc=entry+i*4
        if pc not in states:continue
        row=operand(pc,w);regs=states[pc][0]
        phase=("before" if pc in incoming and pc<site else
               "success_only" if pc in success_nodes and pc not in failure_nodes else
               "failure_only" if pc in failure_nodes and pc not in success_nodes else
               "post_join" if pc in success_nodes and pc in failure_nodes else None)
        if not phase:continue
        if row["kind"] in ("memory_load","memory_store"):
            address=add(regs.get(row["base"]),row["offset"])
            rel=None
            if req and address and req[0]==address[0]=="stack":rel=address[1]-req[1]
            # Direct frame-displacement evidence is kept separate from
            # dataflow-confirmed effective addresses.
            if rel is None and row["base"]==1:rel=row["offset"]-frame
            if rel is None or not 0<=rel<REQUEST_SIZE or rel+row["width"]>REQUEST_SIZE:continue
            item={"pc":hx(pc),"offset":rel,"width":row["width"],"phase":phase,
                  "effective_stack_proven":bool(req and address and req[0]==address[0]=="stack"),
                  "register":row.get("source",row.get("writes"))}
            if row["kind"]=="memory_store":
                item["source_provenance"]=render(regs.get(row["source"]))
                writes.append(item)
            else:reads.append(item)
        if (b:=branch(pc,w)) and b[1] and req and req[0]=="stack":
            for r in range(3,11):
                v=regs.get(r)
                if v and v[0]=="stack" and 0<=v[1]-req[1]<REQUEST_SIZE:
                    escapes.append({"pc":hx(pc),"target":hx(b[0]),"argument_register":r,
                                    "request_offset":v[1]-req[1],"phase":phase,
                                    "arguments":{f"r{k}":render(regs.get(k)) for k in range(3,9)}})
    outputs=[o for o in reads if o["phase"]=="success_only" and o["offset"] in (72,76)]
    if not any(o["offset"]==72 and o["width"]==4 for o in outputs):
        raise ValueError("original success path output +72 not found "+hx(site))
    return {"site":hx(site),"owner":hx(entry),"request_bytes":REQUEST_SIZE,
            "frame_displacement":frame,"call_arguments":{f"r{k}":render(states.get(site,({},{}))[0].get(k)) for k in range(3,9)},
            "negative_status_target":hx(failure),"nonnegative_status_target":hx(success),
            "field_writes":writes,"field_reads":reads,"request_pointer_calls":escapes,
            "success_output_reads":outputs}

def prove_control(site,entry,command,words,graph,states):
    def word(pc):return words[(pc-entry)//4]
    # Independent nearest register writes in the actual local call block.
    local=[]
    for pc in range(site-4,max(entry-4,site-52),-4):
        w=word(pc)
        if w>>26 in (16,17,18,19):break
        local.append((pc,operand(pc,w)))
    r4=next((o for _,o in local if o.get("writes")==4),{})
    if r4.get("kind")!="immediate" or r4.get("value")!=command:
        raise ValueError("control command proof differs "+hx(site))
    regs=states.get(site,({},{}))[0]
    return {"site":hx(site),"owner":hx(entry),"command":command,
            "arguments":{f"r{k}":render(regs.get(k)) for k in range(3,9)},
            "local_argument_writes":[{"pc":hx(pc),**o} for pc,o in reversed(local) if 3<=o.get("writes",0)<=8],
            "continuation":[{"pc":hx(pc),**operand(pc,word(pc))} for pc in range(site+4,min(site+52,entry+len(words)*4),4)]}

def audit(image,meta,raw,catalog):
    base=meta["image_base"];pe=pe_info(image,base);thunks={}
    for row in imports(image,base,parse_xex(raw)):
        lib=library(row["library"]);o=int(row["ordinal"],16)
        name,kind=catalog.get((lib,o),("", "unknown"))
        for a in row["thunk_slots"]:thunks[a]={"name":name,"library":lib,"ordinal":f"{o:04X}"}
    entries={a for a,_ in CREATE.values()}|{a for a,_ in CONTROL.values()}
    entries|={0x816B2520,0x816B2688}
    data={entry:owner_data(image,base,pe,entry,thunks) for entry in sorted(entries)}
    def verify_site(site,entry,name):
        words=data[entry][0];dest=branch(site,words[(site-entry)//4])
        if not dest or not dest[1] or thunks.get(dest[0],{}).get("name")!=name:
            raise ValueError("original import branch differs "+hx(site))
    create=[];control=[]
    for site,(entry,frame) in sorted(CREATE.items()):
        verify_site(site,entry,"StfsCreateDevice")
        create.append(prove_create(site,frame,entry,*data[entry],thunks))
    for site,(entry,command) in sorted(CONTROL.items()):
        verify_site(site,entry,"StfsControlDevice")
        control.append(prove_control(site,entry,command,*data[entry][:3]))
    verify_site(0x816B255C,0x816B2520,"IoCreateDevice")
    verify_site(0x816B26C8,0x816B2688,"IoDeleteDevice")
    return {"create_sites":create,"control_sites":control,
            "bounded_owner_bodies":{hx(entry):item[3] for entry,item in data.items()},
            "scope":"Original static bounded CFG/provenance, exact instruction identities; no dynamic execution or assumed complete request field semantics."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk",type=Path,required=True)
    p.add_argument("--lzx",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    if not a.output.resolve().is_relative_to(ROOT/"build"):p.error("output under build only")
    raw=parse(original("pirs"))["$flash_xam.xex"]["payload"]
    if sha(raw)!=EXPECTED["xam_17559"]:raise ValueError("original XAM source")
    image,meta=decode(raw,a.lzx.resolve())
    if meta["sha256"]!=json.loads((ROOT/"analysis/xam_17559/decoded.json").read_text())["sha256"]:
        raise ValueError("decoded XAM identity")
    catalog,_=sdk_catalog(a.sdk)
    result=audit(image,meta,raw,catalog)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print("Original STFS create",len(result["create_sites"]),"control",len(result["control_sites"]),
          "bounded owners",len(result["bounded_owner_bodies"]))
    for r in result["create_sites"]:
        print(r["site"],"request",r["request_bytes"],"field writes",len(r["field_writes"]),
              "reads",len(r["field_reads"]),"pointer calls",len(r["request_pointer_calls"]))
    print("Original control command counts",dict(collections.Counter(r["command"] for r in result["control_sites"])))
if __name__=="__main__":main()
