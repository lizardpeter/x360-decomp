#!/usr/bin/env python3
"""Instrument only original offline-profile/UI entry and storage status markers.

The original code remains authoritative. No account data, pointers, arguments,
gamertags, keys, credentials or package contents are logged.
"""
import argparse
import collections
import json
import re
from pathlib import Path
from prepare_recompilation import ROOT
from stage_metro_profile_modules import SPECS

# Independently joined original XAM export addresses (run 46026155953).
EXPORTS={
    "XamContentAggregateCreateEnumerator":0x816EEDB8,
    "XamContentCreateDeviceEnumerator":0x816EEE58,
    "XamContentCreateEnumerator":0x816EFE38,
    "XamContentCreateEnumeratorInternal":0x816EECF8,
    "XamContentGetDefaultDevice":0x816EF1B0,
    "XamContentGetDeviceData":0x816EEF60,
    "XamContentGetDeviceName":0x816EF0E0,
    "XamContentGetDeviceState":0x816EEEF8,
    "XamContentGetDeviceVolumePath":0x816EF218,
    "XamContentGetLocalizedDeviceData":0x816EF020,
    "XamContentResolve":0x816EE8C0,
    "XamContentResolveInternal":0x816EE8E0,
    "XamEnumerate":0x816F1070,
    "XamGetCachedGamerTagW":0x81690800,
    "XamNotifyCreateListener":0x816A9378,
    "XamNotifyCreateListenerInternal":0x816A8E50,
    "XamNotifyCreateListenerRangeInternal":0x816A8BF8,
    "XamProfileClose":0x816D7898,
    "XamProfileCreateEnumerator":0x816DB860,
    "XamProfileEnumerate":0x816D7860,
    "XamProfileGetLocalTitleCount":0x816B1CF8,
    "XamProfileOpen":0x816DBC60,
    "XamShowCreateProfileUI":0x816C5A78,
    "XamShowDeviceSelectorUI":0x816C5300,
    "XamShowKeyboardUI":0x816C1F38,
    "XamShowSigninUI":0x816C3CD8,
    "XamShowSigninUIEx":0x816C1A18,
    "XamShowSigninUIp":0x816C19C8,
    "XamUserCreateAchievementEnumerator":0x81670190,
    "XamUserCreateTitlesPlayedEnumerator":0x81670460,
    "XamUserGetDeviceId":0x816D85C8,
    "XamUserGetGamerTag":0x816D86A8,
    "XamUserGetIndexFromXUID":0x816D8698,
    "XamUserGetName":0x816DD040,
    "XamUserGetSigninInfo":0x816DDB20,
    "XamUserGetSigninState":0x816DD118,
    "XamUserGetUserFlags":0x816DAB28,
    "XamUserGetXUID":0x816D8590,
    "XamUserReadProfileSettings":0x816B1F28,
    "XamUserReadProfileSettingsEx":0x816B16A8,
    "XamUserReadUserPreference":0x816B1F68,
}
# Verify these actual original call/continuation pairs in storage audit.
STORAGE_CALLS={
    0x81680A74:"StfsCreateDevice",
    0x816871B8:"StfsCreateDevice",
    0x8192B598:"StfsCreateDevice",
    0x8167C1F4:"StfsControlDevice",
    0x8167C678:"StfsControlDevice",
    0x8167C7EC:"StfsControlDevice",
    0x81680EA4:"StfsControlDevice",
    0x81680EB4:"StfsControlDevice",
    0x81680ECC:"StfsControlDevice",
    0x81680F64:"StfsControlDevice",
    0x81680FA4:"StfsControlDevice",
    0x8192B5D0:"StfsControlDevice",
    0x8192BDDC:"StfsControlDevice",
    0x8192BDEC:"StfsControlDevice",
    0x8192BE18:"StfsControlDevice",
    0x8192BE8C:"StfsControlDevice",
    0x8192BE9C:"StfsControlDevice",
    0x816B255C:"IoCreateDevice",
    0x81680E2C:"IoDeleteDevice",
    0x81681124:"IoDeleteDevice",
    0x816B26C8:"IoDeleteDevice",
    0x8167EB90:"DrvGetContentStorageNotification",
    0x8167ED40:"DrvGetContentStorageNotification",
    0x8167EE34:"DrvSetContentStorageCallback",
}
STATUS={"StfsCreateDevice","StfsControlDevice","IoCreateDevice","DrvGetContentStorageNotification"}
MARKER=re.compile(r"^(\s*)// METRO_GUEST_PC ([0-9A-Fa-f]{8})\s*$")
STAMP="/* METRO_PROFILE_TRACE_INSERTED */"

def points():
    xam={a:(name,"entry") for name,a in EXPORTS.items()}
    for a,name in STORAGE_CALLS.items():
        if a in xam or a+4 in xam:raise ValueError("duplicate original trace")
        xam[a]=(name,"call")
        if name in STATUS:xam[a+4]=(name,"return")
    return {"generated_xam":xam,"generated_hud":{0x913F8D00:("hud","entry")},
            **{"generated_"+name:{s[4]:(name,"entry")} for name,s in SPECS.items()}}

def verify_export_join(original):
    if original!=EXPORTS:raise ValueError("original offline profile export join differs")

def verify_storage_join(report):
    actual={(int(x["site"],16),name) for name,items in report["boundary_sites"].items()
            for x in items if x["linked"]}
    if not set(STORAGE_CALLS.items())<=actual:raise ValueError("original storage trace plan differs")

def insert(source,module,plan):
    if STAMP in source:raise ValueError("duplicate profile trace")
    out=[];hits=collections.Counter()
    for line in source.splitlines(keepends=True):
        out.append(line)
        m=MARKER.fullmatch(line.rstrip("\r\n"))
        if not m:continue
        a=int(m[2],16)
        if a not in plan:continue
        name,phase=plan[a];hits[a]+=1
        p=m[1]
        # For return markers only classify the already-produced r3 status.
        # This does not access guest addresses, buffers or argument values.
        result='(ctx.r3.u32==0?"zero":(ctx.r3.u32&0x80000000u?"negative":"positive"))' if phase=="return" else '"observed"'
        out.extend([
            p+'if (std::getenv("X360_METRO_PROFILE_TRACE")) {\n',
            p+'  static std::atomic<unsigned> metro_profile_samples{0};\n',
            p+'  const auto metro_profile_n=metro_profile_samples.fetch_add(1,std::memory_order_relaxed)+1;\n',
            p+'  if (metro_profile_n<=8 || (metro_profile_n&(metro_profile_n-1))==0)\n',
            p+f'    std::fprintf(stderr,"METRO_PROFILE_TRACE module={module} pc={a:08X} api={name} phase={phase} count=%u result=%s\\n",metro_profile_n,{result});\n',
            p+'}\n'])
    return (STAMP+"\n#include <atomic>\n#include <cstdio>\n#include <cstdlib>\n"+"".join(out),hits) if hits else (source,hits)

def instrument(folder):
    report={};pending={}
    for module,plan in points().items():
        total=collections.Counter()
        directory=folder/module
        if not directory.is_dir():raise ValueError("missing native profile directory "+module)
        for path in sorted(directory.rglob("*.cpp")):
            if path.is_symlink():raise ValueError("generated symlink")
            source,hits=insert(path.read_text(),module,plan)
            if hits:pending[path]=source;total.update(hits)
        report[module]={"expected":len(plan),"covered":len(total),
                        "points":[{"pc":f"{a:08X}","api":n,"phase":p,"occurrences":total[a]}
                                  for a,(n,p) in sorted(plan.items())]}
        if not total:raise ValueError("no actual profile trace markers "+module)
    for path,source in pending.items():path.write_text(source)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("folder",type=Path)
    p.add_argument("--receipt",type=Path,required=True)
    a=p.parse_args()
    if not all(x.resolve().is_relative_to(ROOT/"build") for x in (a.folder,a.receipt)):p.error("generated paths only")
    report=instrument(a.folder)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(report,indent=2)+"\n")
    print("Original offline profile trace coverage",{k:(v["covered"],v["expected"]) for k,v in report.items()})
if __name__=="__main__":main()
