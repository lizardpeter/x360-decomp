#!/usr/bin/env python3
"""Conservative 720p home-header pixel projection, not OCR or layout repair."""
import argparse
import json
import statistics
import subprocess
from pathlib import Path

WIDTH,HEIGHT=1280,720
# Coordinates independently observed in settled home capture 46064158830.
REGIONS={"home":(150,250),"social":(270,370),"games":(385,490),
         "movies":(520,700),"apps":(710,810),"settings":(820,940)}
EXPECTED={"home":4,"social":6,"games":5,"movies":9,"apps":4,"settings":8}

def runs(columns):
    result=[]
    for x in columns:
        if result and x==result[-1][1]:
            result[-1][1]+=1
        else:
            result.append([x,x+1])
    return result

def analyze(raw):
    if len(raw)!=WIDTH*HEIGHT:raise ValueError("not 1280x720 grayscale")
    background={y:statistics.median(raw[y*WIDTH+1100:y*WIDTH+1150]) for y in range(120,163)}
    def region(bounds):
        left,right=bounds
        maxima=[max(raw[y*WIDTH+x]-background[y] for y in range(120,163)) for x in range(left,right)]
        return {"runs":runs([left+i for i,n in enumerate(maxima) if n>12]),
                "peak":max(maxima),"ink_columns":sum(n>12 for n in maxima)}
    labels={key:region(value) for key,value in REGIONS.items()}
    # Do not mistake splash, a different tab position, or a modal for Home.
    matches=(labels["home"]["peak"]>80 and labels["home"]["peak"]>labels["social"]["peak"]+20
             and all(len(labels[k]["runs"])==EXPECTED[k] for k in ("home","social","games","apps","settings")))
    count=len(labels["movies"]["runs"])
    status="unclassified"
    if matches and count==8:status="suspected_missing_terminal_glyph"
    elif matches and count==9:status="nine_separate_ink_runs"
    return {"status":status,"home_header_signature":matches,"labels":labels,
            "visually_verified":False}

def analyze_file(path):
    size=subprocess.check_output(["identify","-format","%w %h",str(path)],text=True).strip()
    if size!="1280 720":return {"status":"other_dimensions","size":size}
    raw=subprocess.check_output(["convert",str(path),"-colorspace","Gray","-depth","8","gray:-"])
    return analyze(raw)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory",type=Path)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    frames={}
    for path in sorted(args.directory.glob("*.png")):
        if not (path.name.startswith("candidate-") or path.name.endswith("-settled.png") or path.name.startswith("input-tab-")):continue
        try:frames[path.name]=analyze_file(path)
        except (ValueError,subprocess.CalledProcessError) as error:frames[path.name]={"status":"error","detail":str(error)}
    report={"scope":"Home-selected 720p header projection only; no OCR or proof of repair",
            "frames":frames,"visually_verified":False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print("720p text projection:",{k:v["status"] for k,v in frames.items()})
if __name__=="__main__":main()
