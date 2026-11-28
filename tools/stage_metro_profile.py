#!/usr/bin/env python3
"""Stage a user-owned Xbox 360 CON profile package, unchanged, for offline testing.

No credentials are decoded, no signatures are modified, and no network
authentication is attempted. Header checks establish format, not authenticity.
"""
import argparse
import hashlib
import os
import re
import struct
import tempfile
from pathlib import Path

ID=re.compile(r"E[0-9A-F]{15}\Z")
MIN_HEADER=0x971A
MAX_BYTES=256*1024*1024
def inspect_header(data,size):
    if len(data)<MIN_HEADER or not MIN_HEADER<=size<=MAX_BYTES:
        raise ValueError("profile package size outside supported range")
    if data[:4]!=b"CON ":raise ValueError("expected console CON package")
    header,kind,version=struct.unpack_from(">III",data,0x340)
    if not MIN_HEADER<=header<=size or (header+0xfff)&~0xfff>size:
        raise ValueError("invalid package header size")
    if kind!=0x00010000 or version not in (1,2):
        raise ValueError("not an Xbox 360 profile content package")
    title=struct.unpack_from(">I",data,0x360)[0]
    if title!=0xFFFE07D1:raise ValueError("not a dashboard profile package")
    profile=struct.unpack_from(">Q",data,0x371)[0]
    # XContentMetadata.profile_id is a stored profile identifier, not a
    # verified online XUID. Zero is allowed; the original name identifies
    # the selected local package in that case.
    if data[0x379]!=0x24:raise ValueError("invalid STFS volume descriptor")
    if struct.unpack_from(">I",data,0x3A9)[0]!=0:raise ValueError("not an STFS volume")
    return profile

def safe_root(root):
    root=root.absolute()
    for part in (root,*root.parents):
        if part.is_symlink() or (part.exists() and getattr(part,"is_junction",lambda:False)()):
            raise ValueError("refusing linked profile storage path")
    return root

def stage(source,root):
    if source.is_symlink() or not source.is_file():raise ValueError("expected a regular local profile file")
    name=source.name.upper()
    if not ID.fullmatch(name):raise ValueError("use the original E-prefixed 16-hex profile filename")
    root=safe_root(root)
    target=root/"Content"/name/"FFFE07D1"/"00010000"/name
    safe_root(target)
    size=source.stat().st_size
    with source.open("rb") as f:
        profile=inspect_header(f.read(MIN_HEADER),size)
        if profile and profile!=int(name,16):raise ValueError("profile header and original filename disagree")
        f.seek(0)
        target.parent.mkdir(parents=True,exist_ok=True)
        # Create a fresh copy in the isolated profile tree. Never overwrite
        # a previous profile, including one changed by the dashboard itself.
        temp=None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent,prefix=".profile-",delete=False) as out:
                temp=Path(out.name)
                h=hashlib.sha256()
                remaining=size
                while remaining:
                    b=f.read(min(1024*1024,remaining))
                    if not b:raise ValueError("source changed during copy")
                    h.update(b);out.write(b);remaining-=len(b)
                if f.read(1):raise ValueError("source changed during copy")
                out.flush();os.fsync(out.fileno())
            with temp.open("rb") as verify:
                digest=hashlib.file_digest(verify,"sha256").digest()
                verify.seek(0)
                copied_profile=inspect_header(verify.read(MIN_HEADER),size)
            if digest!=h.digest() or copied_profile!=profile:
                raise ValueError("copy verification failed")
            safe_root(target)
            # Same-directory hard-link publication is atomic and exclusive.
            # The original dashboard can enumerate while this import runs;
            # it must never observe a partly copied package under its name.
            # A filesystem without hard-link support fails without publishing
            # anything, rather than falling back to a visible partial file.
            try:
                os.link(temp,target)
            except FileExistsError:
                raise FileExistsError("profile already staged; refusing overwrite") from None
        finally:
            if temp:temp.unlink(missing_ok=True)
    return size

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("source",type=Path)
    p.add_argument("--storage-root",required=True,type=Path,
                   help="isolated metro-17559/profile-storage directory under the launcher's user root")
    a=p.parse_args()
    n=stage(a.source,a.storage_root)
    print(f"Staged {n} bytes; SHA-256 copy verified. Profile identity not logged. Original sign-in not yet verified.")
if __name__=="__main__":main()
