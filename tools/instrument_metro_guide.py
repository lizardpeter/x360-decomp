#!/usr/bin/env python3
"""Install bounded original Guide path probes from independently decoded evidence."""
import argparse
import collections
import json
import re
from pathlib import Path
from prepare_recompilation import ROOT
from metro_guide_evidence import GUIDE_EXPORTS,SYSREQ_OWNERS
MARKER=re.compile(r"^(\s*)// METRO_GUEST_PC ([0-9A-Fa-f]{8})\s*$")
STAMP="/* METRO_GUIDE_TRACE_INSERTED */"
# These PCs are original post-call status/branch sites, not account data.
STATUS={"816F0E88","816F0E44","816F0764","816F0C90"}
INIT_OBJECT={"816F0EC8"}
MANDATORY={"816F0E70","816F0E84","816F0E88","816F0EC8","816F0DF0",
           "816F0E40","816F0E44","816F0E54","816F06E8","816F0368",
           "816F0AE0","816F03F0","816F09E8","816F0DB8","816F0DCC"}

def insert(source,module,plan):
    if STAMP in source:raise ValueError("Guide trace already installed")
    out=[];hits=collections.Counter()
    for line in source.splitlines(keepends=True):
        out.append(line)
        m=MARKER.fullmatch(line.rstrip("\r\n"))
        if not m:continue
        pc=m[2].upper()
        if pc not in plan:continue
        p=m[1];entry=plan[pc];hits[pc]+=1
        name,phase=entry["name"],entry["phase"]
        if not re.fullmatch(r"[A-Za-z0-9_]+",name) or not re.fullmatch(r"[A-Za-z0-9_]+",phase):
            raise ValueError("invalid guide trace metadata")
        result='"observed"'
        if pc in STATUS or (phase=='return' and name.startswith(('ui_init_','guide_boot_'))):result='(ctx.r3.u32==0?"zero":(ctx.r3.u32&0x80000000u?"negative":"positive"))'
        if name=="hw_gate":result='((ctx.r11.u32&0x200u)?"bit_set":"bit_clear")'
        if pc in INIT_OBJECT:result='(ctx.r3.u32?"nonzero_object":"null_object")'
        out.extend([p+'if (std::getenv("X360_METRO_GUIDE_TRACE")) {\n',
          p+'  static std::atomic<unsigned> metro_guide_count{0};\n',
          p+'  auto count=metro_guide_count.fetch_add(1,std::memory_order_relaxed)+1;\n',
          p+'  if (count<=8 || (count&(count-1))==0)\n',
          p+f'    std::fprintf(stderr,"METRO_GUIDE_TRACE module={module} pc={pc} name={name} phase={phase} count=%u result=%s\\n",count,{result});\n',
          p+'}\n'])
    return (STAMP+"\n#include <atomic>\n#include <cstdio>\n#include <cstdlib>\n"+"".join(out),hits) if hits else (source,hits)

def instrument(folder,evidence):
    reports={};pending={}
    for label,directory in (("xam","generated_xam"),("hud","generated_hud"),("dash","generated")):
        row=evidence["modules"][label];plan=row["trace_points"]
        if label=="xam":
            if row["exports"]!={k:f"{v:08X}" for k,v in GUIDE_EXPORTS.items()}:
                raise ValueError("Guide export identity")
            if {int(x["owner"],16) for x in row["sysreq_registrations"]}!=SYSREQ_OWNERS:
                raise ValueError("Guide registration identities")
        hits=collections.Counter()
        for p in sorted((folder/directory).rglob("*.cpp")):
            if p.is_symlink():raise ValueError("generated symlink")
            new,h=insert(p.read_text(),label,plan)
            if h:pending[p]=new;hits.update(h)
        if not hits:raise ValueError("no original Guide trace markers for "+label)
        missing=sorted(set(plan)-hits.keys())
        mandatory=sorted(MANDATORY-hits.keys()) if label=="xam" else []
        reports[label]={"planned":len(plan),"covered":len(hits),"missing":missing,
                        "missing_mandatory":mandatory,"points":[{"pc":pc,**entry,"occurrences":hits[pc]}
                        for pc,entry in sorted(plan.items())]}
    for p,s in pending.items():p.write_text(s)
    return reports

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--evidence",type=Path,required=True)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if any(not x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.evidence,a.receipt)):
        p.error("generated paths only")
    report=instrument(a.folder,json.loads(a.evidence.read_text()))
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("Original Guide trace coverage",{k:(v["covered"],v["planned"],v["missing_mandatory"]) for k,v in report.items()})
    # Missing original markers are recorded instead of inventing code. We
    # can still observe the live startup and determine which AOT roots need
    # independent hints. No claim of successful callback delivery.
if __name__=="__main__":main()
