#!/usr/bin/env python3
"""Independent Lua 5.1 fixture and original-prototype differential audit."""
import argparse
import math
import resource
import subprocess
import tempfile
from pathlib import Path
from verify_xui_resources import source
from decode_image import decode
from xex import parse

XBOX=bytes([27,76,117,97,0x51,0,0,4,4,4,8,0])

def transcode(data,target):
    """Translate only the serialized Lua 5.1 ABI, preserving words/number bits."""
    src=data[:12]
    for h in (src,target):
        assert h[:6]==XBOX[:6] and h[6] in (0,1) and h[7]==4 and h[8] in (4,8)
        assert h[9:]==bytes([4,8,0])
    order=lambda h:"little" if h[6] else "big"
    pos=12
    out=bytearray(target)
    def take(n):
        nonlocal pos
        assert 0<=n<=len(data)-pos
        v=data[pos:pos+n];pos+=n;return v
    def number(n,m=None):
        v=int.from_bytes(take(n),order(src))
        out.extend(v.to_bytes(m or n,order(target)))
        return v
    def string():
        n=number(src[8],target[8])
        if n:
            v=take(n);assert v[-1]==0;out.extend(v)
    def proto(depth=0):
        assert depth<65
        string();number(4);number(4)
        out.extend(take(4))
        for _ in range(number(4)):number(4)
        for _ in range(number(4)):
            kind=take(1);out.extend(kind)
            if kind==b"\0":pass
            elif kind==b"\1":out.extend(take(1))
            elif kind==b"\3":number(8)
            elif kind==b"\4":string()
            else:raise AssertionError("constant type")
        for _ in range(number(4)):proto(depth+1)
        for _ in range(number(4)):number(4)
        for _ in range(number(4)):string();number(4);number(4)
        for _ in range(number(4)):string()
    proto()
    assert pos==len(data)
    return bytes(out)

def restricted():
    # This is an independent local reference process, never a guest host
    # library. Bound CPU/address space even on pathological original inputs.
    resource.setrlimit(resource.RLIMIT_CPU,(2,2))
    resource.setrlimit(resource.RLIMIT_AS,(128*1024*1024,128*1024*1024))

def invoke(cmd):
    try:
        return subprocess.check_output(cmd,text=True,timeout=4,preexec_fn=restricted).splitlines()
    except (subprocess.TimeoutExpired,subprocess.CalledProcessError):
        return ["process_limit"]

def equal(a,b):
    if len(a)!=len(b) or not a or a[0]!=b[0]:return False
    for x,y in zip(a[1:],b[1:]):
        if x.startswith("d") and y.startswith("d"):
            try:
                u,v=float(x[1:]),float(y[1:])
            except ValueError:return False
            if math.isnan(u) and math.isnan(v):continue
            if u==v:continue
            if not (math.isfinite(u) and math.isfinite(v) and math.isclose(u,v,rel_tol=1e-14,abs_tol=1e-300)):return False
        elif x!=y:return False
    return True

FIXTURES=[
("closures", """local function outer(x)
 local function add(n) x=x+n; return x end
 local function read() return x end
 return add,read
 end
 local a,b=outer(10);return a(2),b(),a(4),b()"""),
("close", """local f={}
 for i=1,5 do local x=i*2; f[i]=function(n) return x+n end end
 return f[1](1),f[5](2)"""),
("vararg", """local function id(...) return ... end
 local function tail(...) return id(...) end
 local a,b,c,d=tail(1,nil,3)
 return a,b,c,d,select("#",id(1,nil,3))"""),
("tail-recursion", """local function f(n,x) if n==0 then return x end return f(n-1,x+n) end
 return f(300,0)"""),
("globals", """counter=12;function inc(a) counter=counter+a;return counter end
 return inc(4),inc(5),_G.counter"""),
("table-and-method", """local t={v=5};function t:f(x) self.v=self.v+x;return self.v end
 local a=t;return t:f(4),a.v,rawequal==nil,t==a"""),
("iteration", """local t={3,5,7,11};local total=0
 for i,v in ipairs(t) do total=total+i*v end
 local sum=0;for k,v in pairs({x=4,y=8,z=16}) do sum=sum+v end
 return total,sum,#t"""),
("numeric", """local sum=0;for i="1",5 do sum=sum+i end
 local n=0;for j=5,1,-2 do n=n+j end
 return sum,n,-5%3,5%-3,2^8,1/0,0/0"""),
("comparison", """local a,b,c=nil,false,0
 return a or 12,b and 3,c and 4,not a,not b,not c,"a"<"b","a"<= "a",1=="1" """),
("binary", """local a="a\\000b";return #a,a.."c",12.5 .."x",tonumber("  -0x10 "),tonumber("bad"),type(a)"""),
("unpack", """local t={4,8,15,16};return unpack(t,2,4)"""),
("setlist-many", "local t={"+",".join(map(str,range(1,151)))+"};return #t,t[1],t[50],t[51],t[150]"),
("setlist-open", """local function f() return 8,9,10 end
 local t={1,2,f()};return #t,t[3],t[4],t[5]"""),
("open-call", """local function a() return 3,4,5 end
 local function b(x,y,z) return x+y+z end
 return b(a())"""),
("shared-table", """local t={};local key={};t[key]=2;t[false]=4;t[1]=5;t[1]=nil
 return t[key],t[false],t[1],type(key)"""),
("fixed-call", """local function f() return 1,nil,3 end
 local a,b=f();local c,d,e,g=f();return a,b,c,d,e,g"""),
("rk", """local t={a=12};return t.a+3,3*t.a,t.a~=9"""),
("expected-error", """local t={};return t+1"""),
]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("probe",type=Path)
    p.add_argument("--original",action="store_true")
    a=p.parse_args()
    probe=str(a.probe.resolve())
    reference=str(Path(__file__).with_name("lua51_reference.lua").resolve())
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);native=root/"native.luac";xbox=root/"xbox.lub";script=root/"fixture.lua"
        header=None
        for name,code in FIXTURES:
            script.write_text(code)
            subprocess.check_call(["luac5.1","-o",str(native),str(script)])
            data=native.read_bytes();header=data[:12]
            original=transcode(data,XBOX);xbox.write_bytes(original)
            assert transcode(original,header)==data,name
            expected=invoke(["lua5.1",reference,str(native)])
            observed=invoke([probe,"run",str(xbox)])
            assert equal(expected,observed),(name,expected,observed)
        print(f"Lua 5.1 independent differential: {len(FIXTURES)} compiled source fixtures matched",flush=True)
        if not a.original:return
        raw=source("dash_basic");image,info=decode(raw)
        assert info["sha256"]=="06a8446849184331dc1b513a894c08ad3f160dcec8473f70cdcae9f54b7c86f9"
        (root/"image").write_bytes(image)
        (root/"manifest").write_text("".join(f"{r['id']} {int(r['address'],16)-info['image_base']} {r['bytes']}\n"
            for r in parse(raw)["resources"]))
        candidates=root/"originals"
        n=int(subprocess.check_output([probe,"extract",str(root/"image"),str(root/"manifest"),str(candidates)],text=True))
        counts={"scalar_match":0,"error_match":0,"non_scalar":0,"unsupported_or_limit":0,"difference":0}
        examples=[]
        for item in sorted(candidates.glob("*.lub"),key=lambda p:int(p.stem.split("-")[0])):
            params=int(item.stem.split("-")[1])
            native.write_bytes(transcode(item.read_bytes(),header))
            for value in ("n","f","t","d0","d1","d-1","d2","s","s31","s616263"):
                args=[value]*params
                expected=invoke(["lua5.1",reference,str(native),*args])
                observed=invoke([probe,"run",str(item),*args])
                if equal(expected,observed):
                    if expected[0].startswith("ok "):
                        key="non_scalar" if any(v.startswith("x") for v in expected[1:]) else "scalar_match"
                    elif expected[0]=="error":key="error_match"
                    else:key="unsupported_or_limit"
                elif observed and observed[0] in ("unsupported","budget","process_limit") or expected and expected[0] in ("budget","process_limit"):
                    key="unsupported_or_limit"
                else:
                    key="difference"
                    if len(examples)<20:examples.append((item.stem,value,expected[0] if expected else "empty",observed[0] if observed else "empty"))
                counts[key]+=1
                if not params:break
        assert counts["scalar_match"]>0 and n>0
        print("Original isolated Lua candidates:",n,counts)
        print("First differing case identifiers (no original strings or return values):",examples)
        # Original corpus exploration is diagnostic: retain differences rather
        # than selecting only matching functions or asserting full XAM parity.
        # The older pinned scalar audit remains a separate strict gate.

if __name__=="__main__":main()
