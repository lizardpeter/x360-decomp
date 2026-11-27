#!/usr/bin/env python3
"""Resolve Linux crash-report file offsets against the exact native ELF segments."""
import argparse
import functools
import hashlib
import re
import struct
import subprocess
from pathlib import Path

MODULE=re.compile(r"\(([A-Za-z0-9_.-]+)\+0x([0-9a-fA-F]+)\)")
PC_MARKER=re.compile(r"^\s*// METRO_GUEST_PC ([0-9A-Fa-f]{8})$")
FUNC=re.compile(r"^\s*DEFINE_REX_FUNC\(([^)]+)\)")
LOCATION=re.compile(r"^(.*):([0-9]+)(?: \(discriminator \d+\))?$")

def executable_segments(path):
    # The pinned Linux native CI builds ELF64 little-endian files.
    # Read only the ELF and program headers, not the entire title DSO.
    with path.open("rb") as f:
        header=f.read(64)
        if len(header)!=64 or header[:6]!=b"\x7fELF\x02\x01":
            raise ValueError("expected ELF64 little-endian")
        phoff=struct.unpack_from("<Q",header,32)[0]
        entsize,count=struct.unpack_from("<HH",header,54)
        if entsize!=56 or not 0<count<=1024:
            raise ValueError("invalid ELF program-header table")
        if phoff+entsize*count>path.stat().st_size:
            raise ValueError("truncated program-header table")
        f.seek(phoff)
        result=[]
        for _ in range(count):
            kind,flags,offset,vaddr,physical,filesz,memsz,align=struct.unpack("<II6Q",f.read(56))
            if kind==1 and flags&1:
                if filesz>memsz or offset+filesz>path.stat().st_size:
                    raise ValueError("invalid executable segment")
                result.append((offset,vaddr,filesz))
        if not result:raise ValueError("missing executable load segment")
        return result

def virtual_address(segments,offset):
    matches=[vaddr+offset-start for start,vaddr,size in segments if start<=offset<start+size]
    if len(matches)!=1:raise ValueError("file offset not uniquely in an executable load segment")
    return matches[0]

@functools.lru_cache(maxsize=128)
def source_lines(path):
    return path.read_text(errors="replace").splitlines()

def guest_pc(location,expected):
    m=LOCATION.match(location)
    if not m:return None
    path,line=Path(m[1]),int(m[2])
    if not path.is_file() or path.suffix!=".cpp":return None
    if not any(x in path.parts for x in ("generated","generated_xam","generated_hud")):return None
    lines=source_lines(path)
    if not 1<=line<=len(lines):return None
    candidate=None
    for i in range(line-1,-1,-1):
        text=lines[i]
        if candidate is None and (mark:=PC_MARKER.match(text)):
            candidate=int(mark[1],16)
        if func:=FUNC.match(text):
            # Never attribute an instruction from an adjacent function,
            # and never treat prologue/epilogue line information as exact.
            if expected not in (func[1],"__imp__"+func[1]):return None
            return candidate
    return None

def choose_file(name,roots):
    files=set()
    for root in roots:
        direct=root/name
        if direct.is_file():files.add(direct.resolve())
        else:files.update(x.resolve() for x in root.rglob(name) if x.is_file())
    if not files:
        raise ValueError("no matching file")
    if len(files)>1:
        digests=set()
        for path in files:
            with path.open("rb") as f:digests.add(hashlib.file_digest(f,"sha256").hexdigest())
        if len(digests)!=1:
            raise ValueError(f"ambiguous nonidentical matching files ({len(files)})")
    return sorted(files)[0]

def resolve(path,offset):
    va=virtual_address(executable_segments(path),offset)
    call=subprocess.run(["addr2line","-C","-f","-i","-e",str(path),hex(va)],
                        check=True,capture_output=True,text=True)
    lines=call.stdout.splitlines()
    frames=[]
    for i in range(0,len(lines)-1,2):
        symbol,location=lines[i:i+2]
        pc=guest_pc(location,symbol)
        frames.append((symbol,location,pc))
    return va,frames

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("log",type=Path)
    p.add_argument("roots",nargs="+",type=Path)
    a=p.parse_args()
    seen=set()
    for line in a.log.read_text(errors="replace").splitlines():
        # Distinguish the actual fault and unwind from speculative stack words.
        category="fault" if "exception:" in line else "unwind" if re.search(r"\[\s*\d+\]",line) else "stack_candidate"
        for name,raw in MODULE.findall(line):
            key=(category,name,raw)
            if key in seen:continue
            seen.add(key)
            if not (name.startswith(("librex","libdash")) or name=="dash_17559"):continue
            try:
                path=choose_file(name,a.roots)
                offset=int(raw,16)
                va,frames=resolve(path,offset)
                print(f"{category} {name}+0x{raw}: ELF VA=0x{va:x}")
                for symbol,location,pc in frames:
                    hint="" if pc is None else f" guest_pc_candidate=0x{pc:08X}"
                    print(f"  {symbol} | {location}{hint}")
                # A fault in the middle of an x86 instruction would be a
                # decoder error. Disassemble from the symbol start, with
                # the exact fault offset annotated by objdump.
                if category=="fault":
                    call=subprocess.run(["objdump","-d","--no-show-raw-insn",
                        "--start-address="+hex(va),"--stop-address="+hex(va+24),str(path)],
                        check=True,capture_output=True,text=True)
                    print(call.stdout.strip())
            except (OSError,ValueError,subprocess.CalledProcessError) as e:
                print(f"{category} {name}+0x{raw}: unresolved ({e})")
if __name__=="__main__":main()
