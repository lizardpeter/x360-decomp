#!/usr/bin/env python3
"""Bounded original-image evaluation of the scalar XAM heap-selection path.

This is analysis of original instructions under explicit input scenarios, not a
new allocator, firmware dump, runtime bypass, or replacement for guest code.
Unknown operations, registers and call results fail closed.
"""
MASK=0xffffffff

def signed32(x):
    x &= MASK
    return x-(1<<32) if x&0x80000000 else x

def sext(x,bits):
    x &= (1<<bits)-1
    return x-(1<<bits) if x&(1<<(bits-1)) else x

def rotate(x,n):
    n &= 31
    x &= MASK
    return ((x<<n)|(x>>(32-n if n else 32)))&MASK

def ppc_mask(first,last):
    result=0
    for i in range(32):
        if (first<=last and first<=i<=last) or (first>last and (i>=first or i<=last)):
            result |= 1<<(31-i)
    return result

def evaluate(read,start,stops,initial,returns=None,limit=256):
    """Evaluate a deliberately restricted 32-bit scalar instruction subset.

    Memory instructions, non-CR/CTR branches, and unmodeled calls are rejected.
    Caller-return assumptions are explicit. A call invalidates volatile GPRs
    and CR fields; the evaluator will reject any later use of unknown state.
    """
    r={k:v&MASK for k,v in initial.items()}
    cr={};ca=None;pc=start;steps=0;calls=[];path=[]
    returns=returns or {}
    def get(n):
        if n not in r:raise ValueError(f"unknown r{n} at {pc:08X}")
        return r[n]
    def put(n,v):r[n]=v&MASK
    def compare(field,x,y,unsigned=False):
        if not unsigned:x,y=signed32(x),signed32(y)
        cr[field]=(x<y,x>y,x==y,False)
    def record(v):compare(0,v,0)
    def condition(bo,bi):
        if not bo&4:raise ValueError(f"CTR branch outside scalar subset at {pc:08X}")
        if bo&16:return True
        if bi%4==3:raise ValueError(f"SO branch outside scalar subset at {pc:08X}")
        if bi//4 not in cr:raise ValueError(f"unknown CR{bi//4} at {pc:08X}")
        return cr[bi//4][bi%4]==bool(bo&8)
    while pc not in stops:
        if steps>=limit:raise ValueError("scalar path exceeded bound")
        steps+=1;path.append(pc)
        w=read(pc);op=w>>26
        d=(w>>21)&31;a=(w>>16)&31;b=(w>>11)&31;imm=w&65535
        following=pc+4
        if op in (10,11):
            if w&(1<<21):raise ValueError("64-bit compare outside scalar subset")
            compare((w>>23)&7,get(a),imm if op==10 else sext(imm,16),op==10)
        elif op in (14,15):
            put(d,(get(a) if a else 0)+(sext(imm,16)<<(16 if op==15 else 0)))
        elif op==7:put(d,signed32(get(a))*sext(imm,16))
        elif op in (8,12,13):
            x,y=(~get(a)&MASK,sext(imm,16)&MASK) if op==8 else (get(a),sext(imm,16)&MASK)
            total=x+y+(1 if op==8 else 0)
            put(d,total);ca=int(total>MASK)
            if op==13:record(get(d))
        elif op in (24,25,26,27,28,29):
            x=get(d);y=imm<<(16 if op in (25,27,29) else 0)
            put(a,x|y if op in (24,25) else x^y if op in (26,27) else x&y)
            if op in (28,29):record(get(a))
        elif op in (20,21,23):
            mask=ppc_mask((w>>6)&31,(w>>1)&31)
            value=rotate(get(d),get(b) if op==23 else b)&mask
            if op==20:value|=get(a)&~mask
            put(a,value)
            if w&1:record(get(a))
        elif op==16:
            if w&1:raise ValueError("conditional linked branch outside subset")
            if condition(d,a):following=((0 if w&2 else pc)+sext(w&0xfffc,16))&MASK
        elif op==18:
            target=((0 if w&2 else pc)+sext(w&0x03fffffc,26))&MASK
            if w&1:
                if target not in returns:raise ValueError(f"unmodeled call {target:08X}")
                result=returns[target]
                calls.append({"site":f"{pc:08X}","target":f"{target:08X}","assumed_return":result})
                for reg in (0,*range(3,13)):r.pop(reg,None)
                cr.clear();ca=None;put(3,result)
            else:following=target
        elif op==19 and (w>>1)&1023==16:
            if w&1:raise ValueError("linked LR branch outside subset")
            if condition(d,a):return {"registers":r,"steps":steps,"calls":calls,"path":path}
        elif op==31:
            xo=(w>>1)&1023
            if xo in (0,32):
                if w&(1<<21):raise ValueError("64-bit compare outside scalar subset")
                compare((w>>23)&7,get(a),get(b),xo==32)
            elif xo in (28,60,124,316,444):
                x,y=get(d),get(b)
                put(a,{28:x&y,60:x&~y,124:~(x|y),316:x^y,444:x|y}[xo])
                if w&1:record(get(a))
            elif xo in (8,40,136,266):
                x,y=get(a),get(b)
                if xo==136 and ca is None:raise ValueError("unknown carry")
                total=x+y if xo==266 else (MASK^x)+y+(ca if xo==136 else 1)
                put(d,total)
                if xo in (8,136):ca=int(total>MASK)
                if w&1:record(get(d))
            elif xo==104:
                put(d,-get(a))
                if w&1:record(get(d))
            elif xo==26:
                put(a,32-get(d).bit_length())
                if w&1:record(get(a))
            else:raise ValueError(f"unmodeled XO {xo} at {pc:08X}")
        else:raise ValueError(f"unmodeled primary {op} at {pc:08X}")
        pc=following
    return {"registers":r,"steps":steps,"calls":calls,"path":path}

def original_system_object_heap_selection(read):
    """Run only the verified scalar portions of the original allocation path."""
    # At 816A17C4/C8 the original caller supplies r4=15, r3=6536.
    caller=evaluate(read,0x816A17C4,{0x816A17CC},{})
    if (caller["registers"][3],caller["registers"][4])!=(6536,15):
        raise ValueError("original object allocation arguments changed")
    setup=evaluate(read,0x816E6C90,{0x816E6C9C},{4:15,31:6536})
    regs=setup["registers"]
    rows=[]
    # Distinguish possible TLS/process-derived values from measured values.
    # The current boot has not measured these yet.
    for category in (238,254,242,244,247,250,255):
        for helper in (0,1):
            for default in (0,0x10000000):
                normalized=evaluate(read,0x816E5F24,{0x816E600C},{31:regs[3],3:category},
                                    {0x816B8190:helper,0x816BA780:default})
                args=evaluate(read,0x816E6CA0,{0x816E6CB0},
                              {3:normalized["registers"][3],30:regs[30],31:6536,1:0x70000000})
                flags=args["registers"][3]
                index=evaluate(read,0x816E5E40,set(),{3:flags})
                selector=index["registers"][3]
                rows.append({"category":category,"helper_boolean":helper,
                             "default_flags":f"{default:08X}",
                             "normalized_flags":f'{normalized["registers"][3]:08X}',
                             "allocation_flags":f"{flags:08X}","allocation_bytes":args["registers"][4],
                             "heap_selector":f"{selector:08X}",
                             "descriptor_address":f"{0x81AABFF8+28*selector:08X}" if selector<9 else None,
                             "normalizer_assumed_calls":normalized["calls"],
                             "selector_path":[f"{pc:08X}" for pc in index["path"]]})
    return {"scope":"original scalar path, explicit hypothetical helper return values; not a live observation",
            "allocation_bytes":6536,"tag":15,"normalizer_input":f'{regs[3]:08X}',
            "tag_word":f'{regs[30]:08X}',"scenarios":rows}
