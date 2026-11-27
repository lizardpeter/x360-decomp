#!/usr/bin/env python3
"""Measure captured host PCM without retaining or publishing original audio."""
import argparse
import array
import json
import math
import sys
from pathlib import Path

RATE=48000
CHANNELS=2
WINDOW=RATE//10
EPS=1e-5

def analyze(data,boot_exit):
    if len(data)%(4*CHANNELS):
        raise ValueError("partial stereo PCM frame")
    samples=array.array("f")
    samples.frombytes(data)
    if sys.byteorder!="little":samples.byteswap()
    frames=len(samples)//CHANNELS
    finite=all(math.isfinite(v) for v in samples)
    if not finite:
        return {"sample_rate":RATE,"channels":CHANNELS,"frames":frames,
                "finite_samples":False,"baseline_silent":False,
                "non_silent_output":False,"boot_exit":boot_exit}
    baseline=min(frames,RATE//2)
    baseline_peak=max((abs(v) for v in samples[:baseline*CHANNELS]),default=0)
    windows=[]
    for start in range(0,frames,WINDOW):
        part=samples[start*CHANNELS:min(start+WINDOW,frames)*CHANNELS]
        peak=max(map(abs,part),default=0)
        rms=math.sqrt(sum(v*v for v in part)/max(len(part),1))
        windows.append({"start_seconds":round(start/RATE,3),"peak":round(peak,8),
                        "rms":round(rms,8)})
    # Require sustained measurable activity, not a lone click or rounding
    # noise. The null sink baseline must contain at least half a second.
    active=[w for w in windows if w["start_seconds"]>=.5 and w["rms"]>=EPS]
    return {"sample_rate":RATE,"channels":CHANNELS,"frames":frames,
            "duration_seconds":round(frames/RATE,3),"finite_samples":True,
            "baseline_peak":baseline_peak,"baseline_silent":baseline==RATE//2 and baseline_peak<EPS,
            "non_silent_output":len(active)>=3,
            "active_windows":len(active),"first_active_seconds":active[0]["start_seconds"] if active else None,
            "last_active_seconds":active[-1]["start_seconds"] if active else None,
            "peak":max((w["peak"] for w in windows),default=0),
            "windows":windows,"boot_exit":boot_exit,"audible_fidelity_verified":False,
            "scope":"Actual native host sink output; not reference-decoded or substituted audio."}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("pcm",type=Path)
    p.add_argument("--boot-exit",type=int,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    # CI records no more than about a minute. Refuse unbounded input.
    if a.pcm.stat().st_size>RATE*CHANNELS*4*90:raise ValueError("PCM capture exceeded bound")
    report=analyze(a.pcm.read_bytes(),a.boot_exit)
    a.output.write_text(json.dumps(report,indent=2)+"\n")
if __name__=="__main__":main()
