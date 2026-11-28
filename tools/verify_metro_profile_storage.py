#!/usr/bin/env python3
"""Exercise the packaged native profile preflight with synthetic SDK fixtures.

No real profiles, credentials, signatures or account services are involved.
The fixture only tests filesystem routing and structural validation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

NAME = "E000000000000001"
def profile_fixture(raw):
    data = bytearray(raw)
    if len(data) != 65536 or data[:4] != b"CON ":
        raise ValueError("unexpected pinned synthetic STFS fixture")
    header_size = struct.unpack_from(">I",data,0x340)[0]
    if not 0x971a <= header_size <= len(data):
        raise ValueError("unexpected fixture header extent")
    struct.pack_into(">II",data,0x344,0x10000,2)
    struct.pack_into(">I",data,0x360,0xfffe07d1)
    struct.pack_into(">Q",data,0x371,int(NAME,16))
    if data[0x379] != 0x24 or struct.unpack_from(">I",data,0x3a9)[0] != 0:
        raise ValueError("unexpected synthetic STFS descriptor")
    return bytes(data)

def verify(host, inputs, fixture, output):
    host=host.resolve()
    inputs=inputs.resolve()
    raw=fixture.read_bytes()
    data=profile_fixture(raw)
    results=[]
    env=os.environ.copy()
    for key in ("X360_METRO_BOOT","X360_METRO_INTRO","X360_METRO_PROFILE_MODULE_PREFLIGHT","X360_METRO_TEXT_PREFLIGHT"):
        env.pop(key,None)
    env["X360_METRO_PROFILE_STORAGE_PREFLIGHT"]="2"
    bad_identity=bytearray(data)
    struct.pack_into(">Q",bad_identity,0x371,int(NAME,16)+1)
    bad_header=bytearray(data)
    struct.pack_into(">I",bad_header,0x340,0xffffffff)
    for label,payload,expected in (
        ("empty",None,(0,0,0)),
        ("valid_structure",data,(1,1,0)),
        ("wrong_identity",bytes(bad_identity),(1,0,1)),
        ("invalid_extent",bytes(bad_header),(1,0,1)),
        ("truncated",data[:0x1000],(1,0,1)),
    ):
        with tempfile.TemporaryDirectory(prefix="metro-profile-ci-") as tmp:
            root=Path(tmp)
            path=root/"metro-17559"/"profile-storage"/"Content"/NAME/"FFFE07D1"/"00010000"/NAME
            if payload is not None:
                path.parent.mkdir(parents=True)
                path.write_bytes(payload)
            p=subprocess.run([str(host),f"--title.game_root={inputs}","--title.entry=dash.xex",
                              f"--app.user_root={root}"],cwd=host.parent,env=env,
                             stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
            log=p.stdout.decode("utf-8",errors="replace").splitlines()
            receipt=f"METRO_PROFILE_STORAGE candidates={expected[0]} parsed={expected[1]} failed={expected[2]} sign_in_verified=false"
            should_pass=label=="valid_structure"
            unchanged=not path.exists() if payload is None else path.is_file() and path.read_bytes()==payload
            passed=(receipt in log and (p.returncode==0)==should_pass and unchanged and
                    ("METRO_PREFLIGHT pass local_profile_storage" in log)==should_pass and
                    not any(x.startswith("METRO_BOOT pass dashboard_entry") for x in log))
            results.append({"case":label,"exit_code":p.returncode,"expected_counts":list(expected),
                            "receipt_matched":receipt in log,"unchanged":unchanged,"passed":passed})
            if not passed:
                print("Synthetic profile preflight failed:",label)
                for line in log:
                    if line.startswith(("METRO_PROFILE_STORAGE ","METRO_PREFLIGHT ")):print(line)
    report={"fixture_sha256":hashlib.sha256(raw).hexdigest(),"cases":results,
            "passed":all(x["passed"] for x in results),"sign_in_verified":False}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))
    return report["passed"]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ("host","inputs","fixture","output"):p.add_argument("--"+k,type=Path,required=True)
    a=p.parse_args()
    raise SystemExit(0 if verify(a.host,a.inputs,a.fixture,a.output) else 1)

if __name__=="__main__":main()
