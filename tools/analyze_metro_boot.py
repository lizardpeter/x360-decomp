#!/usr/bin/env python3
"""Join live Metro observations to original function metadata."""
import argparse
import bisect
import collections
import json
import re
from pathlib import Path
from prepare_recompilation import ROOT
from stage_metro_xam_aot import rows

STUB=re.compile(r"METRO_STUB name=(\w+) lr=0x([0-9a-fA-F]+) r3=0x([0-9a-fA-F]+) r4=0x([0-9a-fA-F]+) r5=0x([0-9a-fA-F]+) r6=0x([0-9a-fA-F]+)")
PAD=re.compile(r"METRO_PAD user=(\d+) buttons=0x([0-9a-fA-F]+)")
GUEST_PAD=re.compile(r"METRO_GUEST_PAD context=([0-9a-fA-F]+) user=(\d+) packet=(\d+) buttons=0x([0-9a-fA-F]+)")
HEAP=re.compile(r"METRO_HEAP pc=([0-9A-Fa-f]+) stage=(\w+) r3=([0-9A-Fa-f]+) r4=([0-9A-Fa-f]+) r5=([0-9A-Fa-f]+) r6=([0-9A-Fa-f]+) r7=([0-9A-Fa-f]+) r8=([0-9A-Fa-f]+)")
VM=re.compile(r"METRO_VM (\w+) lr=([0-9a-fA-F]+) region=(\d+) base=([0-9a-fA-F]+) size=([0-9a-fA-F]+) flags=([0-9a-fA-F]+) protect=([0-9a-fA-F]+) status=([0-9a-fA-F]+)")
UI=re.compile(r"METRO_UI pc=([0-9A-Fa-f]+) label=(\w+) phase=(\w+) count=(\d+) r3=([0-9A-Fa-f]+) r4=([0-9A-Fa-f]+) r5=([0-9A-Fa-f]+) r6=([0-9A-Fa-f]+) r7=([0-9A-Fa-f]+) r8=([0-9A-Fa-f]+)")
TEXT=re.compile(r"METRO_TEXT pc=([0-9A-Fa-f]+) label=(\w+) phase=(\w+) count=(\d+) kind=(\w+) result=(\w+)")
FONT=re.compile(r"METRO_FONT pc=([0-9A-Fa-f]+) label=(\w+) kind=(\w+) status=([0-9A-Fa-f]+) path=(\w+) units=(\d+) detail=([0-9A-Fa-f]+|unmapped)")
RESOURCE_READ=re.compile(r"METRO_UI_FILE name=(\S+) size=(\d+) offset=(\d+) requested=(\d+) actual=(\d+) status=([0-9A-Fa-f]+) count=(\d+)")
RESOURCE_OPEN=re.compile(r"METRO_UI_OPEN name=(\S+) status=([0-9A-Fa-f]+) handle=([0-9A-Fa-f]+) count=(\d+) share=([0-9A-Fa-f]+) options=([0-9A-Fa-f]+)")
FRAME=re.compile(r"^METRO_BOOT frames (\d+)$")
BASELINE=re.compile(r"^METRO_BOOT dashboard_frame_baseline (\d+)$")
RESET=re.compile(r"^METRO_BOOT dashboard_frame_reset (\d+)$")
INTRO_FRAME=re.compile(r"^METRO_INTRO frames (\d+)$")
HANDOFF_FRAME=re.compile(r"^METRO_INTRO post_handoff_frames (\d+)$")
VAR=re.compile(r"METRO_KERNEL_VAR module=(\w+) ordinal=0x([0-9a-fA-F]+).* state=(\w+)")

def functions(module):
    return [(int(r["address"],16),int(r["size"])) for r in rows(ROOT/"analysis"/module/"functions.tsv")]

def summarize(lines, inventories):
    starts={module:[a for a,_ in funcs] for module,funcs in inventories.items()}
    def locate(lr):
        pc=lr-4
        for module,funcs in inventories.items():
            i=bisect.bisect_right(starts[module],pc)-1
            if i>=0:
                a,size=funcs[i]
                if a<=pc<a+size:return module,f"{a:08X}"
        return "unclassified",None
    gates=[];stubs=collections.Counter();sites={};pad=[];guest_pad=[];frames=[];variables=[];errors=[];heap=[];vm=[];failed_paths=collections.Counter()
    ui={};baseline=None;counter_resets=[];intro_frames=[];handoff_frames=[]
    fonts=[];resource_reads=[];resource_opens=[];gpu_cancellations=0;text_traces={}
    for line in lines:
        if "METRO_GPU packet_stream_cancelled during shutdown" in line:gpu_cancellations+=1
        if m:=RESOURCE_OPEN.search(line):
            if len(resource_opens)<512:resource_opens.append({"name":m[1],"status":m[2].upper(),
                "handle":m[3].upper(),"count":int(m[4]),"share":m[5].upper(),"options":m[6].upper()})
        if m:=TEXT.search(line):
            key=(m[1].upper(),m[2],m[3])
            record=text_traces.setdefault(key,{"pc":key[0],"label":key[1],"phase":key[2],
                "kind":m[5],"count_lower_bound":0,"observed_categories":{},"sample_counts":{}})
            record["count_lower_bound"]=max(record["count_lower_bound"],int(m[4]))
            record["observed_categories"][m[6]]=max(record["observed_categories"].get(m[6],0),int(m[4]))
            record["sample_counts"][m[6]]=record["sample_counts"].get(m[6],0)+1
        if m:=FONT.search(line):
            if len(fonts)<512:fonts.append({"pc":m[1].upper(),"label":m[2],"kind":m[3],
                "status":m[4].upper(),"path":m[5],"units":int(m[6]),"detail":m[7]})
        if m:=RESOURCE_READ.search(line):
            if len(resource_reads)<512:resource_reads.append({"name":m[1],"size":int(m[2]),
                "offset":int(m[3]),"requested":int(m[4]),"actual":int(m[5]),"status":m[6].upper(),"count":int(m[7])})
        if m:=UI.search(line):
            key=(m[1].upper(),m[2],m[3])
            record=ui.setdefault(key,{"pc":key[0],"label":key[1],"phase":key[2],"count_lower_bound":0,"samples":[]})
            record["count_lower_bound"]=max(record["count_lower_bound"],int(m[4]))
            if len(record["samples"])<8:record["samples"].append({f"r{i}":m[i+2].upper() for i in range(3,9)})
        if m:=STUB.search(line):
            name=m[1];lr=int(m[2],16);module,caller=locate(lr)
            stubs[name]+=1
            key=(name,lr)
            sites.setdefault(key,{"symbol":name,"lr":f"{lr:08X}","module":module,"pdata_caller":caller,"samples":[]})
            if len(sites[key]["samples"])<4:
                sites[key]["samples"].append([f"{int(x,16):08X}" for x in m.groups()[2:]])
        if m:=PAD.search(line):
            pad.append({"user":int(m[1]),"buttons":int(m[2],16)})
        if m:=GUEST_PAD.search(line):
            guest_pad.append({"context":m[1].upper(),"user":int(m[2]),"packet":int(m[3]),"buttons":int(m[4],16)})
        if m:=HEAP.search(line):
            heap.append({"pc":m[1].upper(),"stage":m[2],
                         **{f"r{i}":m[i].upper() for i in range(3,9)}})
        if m:=VM.search(line):
            vm.append({"name":m[1],"lr":m[2].upper(),"region":int(m[3]),
                       **{key:m[i].upper() for i,key in enumerate(("base","size","flags","protect","status"),4)}})
        if m:=BASELINE.fullmatch(line):baseline=int(m[1])
        if m:=RESET.fullmatch(line):counter_resets.append(int(m[1]))
        if m:=INTRO_FRAME.fullmatch(line):intro_frames.append(int(m[1]))
        if m:=HANDOFF_FRAME.fullmatch(line):handoff_frames.append(int(m[1]))
        if m:=FRAME.fullmatch(line):frames.append(int(m[1]))
        if m:=VAR.search(line):
            variables.append({"module":m[1],"ordinal":m[2].upper(),"state":m[3]})
        if line.startswith("METRO_BOOT "):gates.append(line)
        if m:=re.search(r"no mount covers '([^']+)'",line):
            failed_paths[m[1]]+=1
        if any(x in line for x in ("Assertion failed","exception: SIG","unimplemented:","Unresolved import","invalid or unregistered function")):
            if len(errors)<100:errors.append(line[:512])
    # The original register wrapper returns HRESULT, while validate/insert
    # are boolean helpers. Keep separate observations, never conflate r3
    # at descriptor entry with a return status.
    font_results={}
    for record in ui.values():
        label=record["label"]
        if record["phase"]=="return" and label.startswith("dash_font_"):
            font_results[label]={"count_lower_bound":record["count_lower_bound"],
                                 "observed_r3":[x["r3"] for x in record["samples"]]}
    return {"boot_markers":gates,"observed_stub_counts":dict(stubs),"stub_call_sites":list(sites.values()),
            "pad_transitions":pad,"guest_pad_transitions":guest_pad,"frame_counts":frames,"kernel_variables":variables,
            "missing_mount_paths":dict(failed_paths),"errors":errors,
            "frame_counter_baseline":baseline,"frame_counter_resets":counter_resets,
            "intro_frame_counts":intro_frames,"post_handoff_frame_counts":handoff_frames,
            "frame_count_excludes_intro":baseline is not None,
            "font_probes":fonts,"resource_reads":resource_reads,"resource_opens":resource_opens,
            "font_call_results":font_results,"gpu_shutdown_cancellations":gpu_cancellations,
            "text_trace_results":list(text_traces.values()),
            "heap_probes":heap,"ui_probes":list(ui.values()),"virtual_memory_calls":vm,
            "virtual_memory_failures":[v for v in vm if int(v["status"],16)&0x80000000],
            "menu_visually_verified":False,"navigation_visually_verified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("log",type=Path)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    result=summarize(a.log.read_text(errors="replace").splitlines(),
                     {m:functions(m) for m in ("dash_17559","xam_17559")})
    a.output.write_text(json.dumps(result,indent=2)+"\n")
    print("Boot evidence:",len(result["stub_call_sites"]),"stub sites,",len(result["pad_transitions"]),
          "host pad transitions,",len(result["guest_pad_transitions"]),"guest pad transitions,",len(result["frame_counts"]),"frame reports")
if __name__=="__main__":main()
