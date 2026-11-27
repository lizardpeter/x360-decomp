#!/usr/bin/env python3
"""Map original Metro's system and title lifecycle dependency paths.

Only bounded original instruction operands, literal argument evidence,
and direct call graph paths are exported. Indirect targets are not guessed.
"""
from collections import defaultdict, deque
from metro_import_contracts import branch, hx, library, setup
from metro_live_slot_and_input_evidence import read_word, local_values

HEAP_TARGETS={
    0x816E6618:"system_heap_initialization",
    0x816E6518:"descriptor_initialization",
    0x816E6218:"backed_heap_construction",
    0x816E62F0:"other_heap_construction",
    0x816E6C78:"object_allocator",
    0x816A17B8:"system_object_initialization",
}
LIFECYCLE_IMPORTS={
    "ExCreateThread","ExTerminateThread","ExRegisterTitleTerminateNotification",
    "KeTlsAlloc","KeTlsFree","KeTlsGetValue","KeTlsSetValue",
    "KeGetCurrentProcessType","KeSetCurrentProcessType","ObDereferenceObject",
    "XexLoadExecutable","XexStartExecutable","XexUnloadTitleModules",
    "XexSendDeferredNotifications","XamLoaderLaunchTitleEx",
    "XamLoaderRegisterLaunchRequestCallback","XamLoaderTerminateTitle",
    "XamLoaderLaunchTitleForReason","XamAlloc","XamAllocEx","XamFree",
    "XMsgInProcessCall","XMsgSystemProcessCall",
}
ENTRY_NAMES={"dash":"dashboard_entry","xam":"system_xam_entry"}

def shortest_paths(edges, roots):
    """Shortest graph paths with actual call site and target per edge."""
    parents={}
    queue=deque()
    for root in roots:
        parents[root]=None
        queue.append(root)
    while queue:
        a=queue.popleft()
        for target,site,linked in edges.get(a,()):
            if target in parents:continue
            parents[target]=(a,site,linked)
            queue.append(target)
    return parents

def path_to(parents,target,limit=64):
    if target not in parents:return None
    path=[]
    while parents[target] is not None:
        source,site,linked=parents[target]
        path.append({"module":source[0],"entry":hx(source[1]),"site":hx(site),
                     "target_module":target[0],"target":hx(target[1]),"linked":linked})
        if len(path)>limit:return None
        target=source
    return list(reversed(path))

def collect_module(label,image,base,pe,rows,catalog,stubs,exports):
    entries={a:size for a,size,_ in pe["functions"]}
    thunks={}
    for row in rows:
        lib=library(row["library"]);ordinal=int(row["ordinal"],16)
        name,kind=catalog.get((lib,ordinal),("", "unknown"))
        for target in row["thunk_slots"]:
            thunks[target]={"library":lib,"ordinal":f"{ordinal:04X}","name":name,
                            "sdk_kind":kind,"sdk_stub":name in stubs}
    edges=defaultdict(list);sites=[];direct_targets=[];indirect=0
    for start,size,_ in pe["functions"]:
        for pc in range(start,start+size,4):
            word=read_word(image,base,pc)
            if word>>26==19 and (word>>1)&1023 in (16,528) and word&1:
                indirect+=1
            dest=branch(pc,word)
            if not dest:continue
            target,linked=dest
            imp=thunks.get(target)
            if imp:
                if label=="dash" and imp["library"]=="xam":
                    real=exports.get(int(imp["ordinal"],16))
                    if real:
                        edges[(label,start)].append((("xam",real),pc,linked))
                if imp["name"] in LIFECYCLE_IMPORTS:
                    values=local_values(image,base,max(start,pc-160),pc)
                    sites.append({"module":label,"owner":hx(start),"site":hx(pc),
                                  "target":hx(target),"linked":linked,"import":imp,
                                  "literal_arguments":{f"r{k}":hx(v) for k,v in values.items() if 3<=k<=10}})
            elif target in entries and target!=start:
                edges[(label,start)].append(((label,target),pc,linked))
            if label=="xam" and target in HEAP_TARGETS:
                values=local_values(image,base,max(start,pc-160),pc)
                direct_targets.append({"module":label,"owner":hx(start),"site":hx(pc),
                    "target":hx(target),"purpose":HEAP_TARGETS[target],"linked":linked,
                    "literal_arguments":{f"r{k}":hx(v) for k,v in values.items() if 3<=k<=10}})
    return edges,sites,direct_targets,indirect

def lifecycle_report(modules,exports,catalog,stubs,operand_description):
    edges=defaultdict(list);sites=[];direct_targets=[];indirect={}
    for label,(image,base,pe,rows) in modules.items():
        e,s,t,i=collect_module(label,image,base,pe,rows,catalog,stubs,exports)
        for key,values in e.items():edges[key].extend(values)
        sites.extend(s);direct_targets.extend(t);indirect[label]=i
    roots={label:(label,pe["entry_point"]) for label,(_,_,pe,_) in modules.items()}
    parents={name:shortest_paths(edges,[root]) for name,root in roots.items()}
    # Direct paths are a structural upper bound; an original conditional
    # branch can make a path unreachable for a particular attach reason.
    for row in sites+direct_targets:
        key=(row["module"],int(row["owner"],16))
        row["root_paths"]={name:path_to(p,key) for name,p in parents.items()}
    image,base,pe,rows=modules["xam"]
    entry=roots["xam"][1]
    root_operands=operand_description(image,base,pe,entry)
    descriptor0=[row for row in direct_targets if row["purpose"]=="descriptor_initialization"
                 and row["literal_arguments"].get("r3")=="00000000"]
    return {"scope":"exact original direct calls and conservative nearby literal values, not dynamic execution",
            "roots":{name:{"module":r[0],"entry":hx(r[1])} for name,r in roots.items()},
            "xam_entry_operands":root_operands,
            "graph_nodes":len(edges),"graph_edges":sum(map(len,edges.values())),
            "indirect_calls_unresolved":indirect,
            "heap_constructor_calls":direct_targets,
            "literal_descriptor_zero_constructors":descriptor0,
            "lifecycle_import_calls":sites,
            "direct_root_reachability":{name:len(p) for name,p in parents.items()}}
