#!/usr/bin/env python3
"""Compare the settled Home frame on the two native 720p primitive paths.

A result is evidence about these captures only, not a text repair or proof
that other scenes, fonts or GPU states are equivalent.
"""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from metro_720p_text_probe import analyze_file

SETTINGS={"guest_mode":"1280x720","render_scale":"1x1",
          "async_shader_compilation":"false","placeholder_draw_frames":"0"}
SAMPLE=re.compile(r"^sample=(candidate-\d+\.png) guest_frames=(\d+) width=1280 height=720 colors=\d+$")
HASH=re.compile(r"^([0-9a-f]{64})  (candidate-\d+\.png)$")

def decode(path):
    size=subprocess.check_output(["identify","-format","%w %h",str(path)],text=True).strip()
    if size!="1280 720":raise ValueError("not 1280x720")
    pixels=subprocess.check_output(["convert",str(path),"-alpha","off","-depth","8","rgb:-"])
    if len(pixels)!=1280*720*3:raise ValueError("unexpected RGB extent")
    return hashlib.sha256(pixels).hexdigest(),analyze_file(path)

def inspect(directory,variant,decoder=decode):
    receipt=directory/"receipt.txt"
    if not receipt.is_file():return {"status":"unavailable","reason":"missing receipt"}
    lines=receipt.read_text().splitlines()
    expected={**SETTINGS,"variant":variant,"quad_conversion":"true" if variant=="quad" else "false"}
    for k,v in expected.items():
        values=[line.split("=",1)[1] for line in lines if line.startswith(k+"=")]
        if values!=[v]:return {"status":"unavailable","reason":"invalid "+k}
    startup={}
    for k in ("profile_probe","guide_ui"):
        values=[line.split("=",1)[1] for line in lines if line.startswith(k+"=")]
        if len(values)!=1 or values[0] not in ("0","1"):
            return {"status":"unavailable","reason":"invalid "+k}
        startup[k]=values[0]
    if "METRO_BOOT pass dashboard_entry" not in lines:
        return {"status":"unavailable","reason":"no dashboard entry"}
    samples={}; hashes={}
    for line in lines:
        m=SAMPLE.fullmatch(line)
        if m:
            name,frame=m.groups()
            if name in samples:return {"status":"unavailable","reason":"duplicate sample"}
            samples[name]=int(frame)
        m=HASH.fullmatch(line)
        if m:
            digest,name=m.groups()
            if name in hashes:return {"status":"unavailable","reason":"duplicate hash"}
            hashes[name]=digest
    if set(samples)!=set(hashes):
        return {"status":"unavailable","reason":"unpaired sample/hash"}
    observed=[]
    for name,frame in samples.items():
        path=directory/name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=hashes[name]:
            return {"status":"unavailable","reason":"missing or changed sample"}
        try:digest,projection=decoder(path)
        except (ValueError,OSError,subprocess.CalledProcessError):
            return {"status":"unavailable","reason":"image decode failed"}
        observed.append({"name":name,"guest_frame":frame,"rgb_sha256":digest,
                         "home_signature":projection.get("home_header_signature",False),
                         "text_projection":projection["status"]})
    # Require at least two consecutive, pixel-identical Home frames with
    # strictly advancing guest frame counters, rather than matching a splash.
    stable=[]
    for item in observed:
        if not item["home_signature"]:stable=[];continue
        if stable and (item["rgb_sha256"]!=stable[-1]["rgb_sha256"] or
                       item["guest_frame"]<=stable[-1]["guest_frame"]):stable=[]
        stable.append(item)
    return {"status":"settled" if len(stable)>=2 else "unavailable",
            "observed":observed,"stable":stable,"startup":startup}

def compare(baseline,quad,decoder=decode):
    left=inspect(baseline,"baseline",decoder); right=inspect(quad,"quad",decoder)
    report={"scope":"two settled Home capture paths only","baseline":left,"quad":right,
            "status":"unavailable","visually_verified":False,"repair_verified":False}
    if left["status"]==right["status"]=="settled":
        if left["startup"]!=right["startup"]:
            report["reason"]="different startup settings"
            return report
        same=left["stable"][-1]["rgb_sha256"]==right["stable"][-1]["rgb_sha256"]
        report["status"]="identical_settled_pixels" if same else "different_settled_pixels"
        report["both_suspected_missing_terminal_glyph"]=all(
            side["stable"][-1]["text_projection"]=="suspected_missing_terminal_glyph"
            for side in (left,right))
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("baseline",type=Path);p.add_argument("quad",type=Path)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    report=compare(a.baseline,a.quad)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
    print("720p native path comparison:",report["status"])

if __name__=="__main__":main()
