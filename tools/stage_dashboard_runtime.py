#!/usr/bin/env python3
"""Stage a hash-verified, local-only Metro runtime resource tree."""
import argparse
import hashlib
import json
from pathlib import Path
from fetch_originals import ROOT, config, check, acquire
from prepare_recompilation import original, EXPECTED
from pirs import parse as parse_pirs

# Explicit diagnostic host layout. This is not a retail flash filesystem
# mount; modules must still be registered with the actual host runtime.
LAYOUT = {
    "$flash_dash.xex": "dash.xex",
    "$flash_bootanim.xex": "bootanim.xex",
    "$flash_xam.xex": "system/xam.xex",
    "$flash_createprofile.xex": "system/createprofile.xex",
    "$flash_deviceselector.xex": "system/deviceselector.xex",
    "$flash_gamerprofile.xex": "system/gamerprofile.xex",
    "$flash_hud.xex": "system/hud.xex",
    "$flash_huduiskin.xex": "system/huduiskin.xex",
    "$flash_minimediaplayer.xex": "system/minimediaplayer.xex",
    "$flash_signin.xex": "system/signin.xex",
    "$flash_vk.xex": "system/vk.xex",
    "$flash_ximecore.xex": "system/ximecore.xex",
    "$flash_SegoeXbox-Light.xtt": "SegoeXbox-Light.xtt",
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def verify_members(members, census):
    actual={name:{k:v for k,v in member.items() if k!="payload"} for name,member in members.items()}
    if actual!=census:
        raise ValueError("PIRS member metadata differs from verified census")
    if members["$flash_dash.xex"]["sha256"]!=EXPECTED["dash_17559"] or members["$flash_xam.xex"]["sha256"]!=EXPECTED["xam_17559"]:
        raise ValueError("runtime module identity differs from AOT inputs")

def put(destination, relative, data):
    path=destination/relative
    if not path.resolve().is_relative_to(destination.resolve()):
        raise ValueError("unsafe runtime destination")
    if path.is_symlink() or any(p.is_symlink() for p in path.parents if p!=destination.parent and p.is_relative_to(destination)):
        raise ValueError("symlink in runtime destination")
    if path.exists():
        if not path.is_file() or path.read_bytes()!=data:
            raise ValueError(f"refusing to overwrite different runtime file: {relative}")
    else:
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)
    return {"path":relative,"bytes":len(data),"sha256":digest(data)}

def acquire_font_complements(destination, cfg, downloader=acquire):
    """Only retrieve existing pinned complements from the configured owner archive."""
    destination.mkdir(parents=True, exist_ok=True)
    for spec in cfg.get("local_resource", []):
        if "key" not in spec:
            raise ValueError("no configured source for "+spec["name"])
        path=downloader(spec|{"id":spec["name"]}, ROOT/"originals", cfg["r2_public"])
        check(path,spec|{"id":spec["name"]})
        put(destination,spec["name"],path.read_bytes())
    return destination

def stage(destination, members, census, shared, font_dir=None, require_fonts=False, include_flash=False):
    verify_members(members,census)
    entries=[]
    fonts=config().get("local_resource",[])
    missing=[]
    font_payloads={}
    for spec in fonts:
        name=spec["name"]
        source=font_dir/name if font_dir else None
        staged=destination/name
        if source is None or not source.is_file():
            source=staged if staged.is_file() else None
        if source is None:
            missing.append(name)
            continue
        check(source,spec|{"id":name})
        font_payloads[name]=source.read_bytes()
    if missing and require_fonts:
        raise ValueError("missing exact local font complements: "+", ".join(missing))
    for name,path in LAYOUT.items():
        entries.append(put(destination,path,members[name]["payload"]))
    entries.append(put(destination,"shrdres.xzp",shared))
    for name,payload in font_payloads.items():
        entries.append(put(destination,name,payload))
    if include_flash:
        # PIRS names explicitly designate flash files. Stage only selected
        # runtime files, never manufacturing/update modules or patch payloads.
        for name in LAYOUT:
            entries.append(put(destination, "flash/"+name.removeprefix("$flash_"),
                               members[name]["payload"]))
        entries.append(put(destination, "flash/shrdres.xzp", shared))
        for name,payload in font_payloads.items():
            entries.append(put(destination, "flash/"+name, payload))
    return {"files":sorted(entries,key=lambda x:x["path"]),
            "file_count":len(entries),"total_bytes":sum(r["bytes"] for r in entries),
            "missing_local_fonts":missing,"guest_boot_verified":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,default=ROOT/"build/aot-host/dash_17559/inputs")
    p.add_argument("--receipt",type=Path,default=ROOT/"build/dashboard-runtime-receipt.json")
    p.add_argument("--font-dir",type=Path)
    p.add_argument("--fetch-fonts",action="store_true",help="retrieve exact pinned complements from the configured owner archive")
    p.add_argument("--require-fonts",action="store_true")
    p.add_argument("--flash-tree",action="store_true",help="also stage read-only flash mount inputs")
    a=p.parse_args()
    for path in (a.output,a.receipt):
        if not path.resolve().is_relative_to((ROOT/"build").resolve()):
            p.error("runtime tree and receipt must remain under ignored build/")
    census=json.loads((ROOT/"analysis/pirs_17559/members.json").read_text())
    members=parse_pirs(original("pirs"))
    if a.fetch_fonts and a.font_dir:
        p.error("--fetch-fonts and --font-dir are mutually exclusive")
    fonts=acquire_font_complements(ROOT/"build/metro-font-complements",config()) if a.fetch_fonts else a.font_dir
    result=stage(a.output.resolve(),members,census,original("shared_resources"),fonts,a.require_fonts,a.flash_tree)
    a.receipt.parent.mkdir(parents=True,exist_ok=True)
    a.receipt.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items() if k!="files"}))
if __name__=="__main__":main()
