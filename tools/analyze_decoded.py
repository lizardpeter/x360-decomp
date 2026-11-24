#!/usr/bin/env python3
"""Read-only decoded image inventory. Images and resource bytes remain local."""
import argparse
import csv
import hashlib
import json
import struct
from bisect import bisect_right
from pathlib import Path
from fetch_originals import ROOT, config, check, safe_key
from decode_image import decode, span, be
from xex import parse as parse_xex
from pirs import parse as parse_pirs

def le(data,off,n=4):
    return int.from_bytes(span(data,off,n),'little')

def pe_info(image, base):
    if image[:2]!=b'MZ': return None
    p=le(image,0x3c)
    if span(image,p,4)!=b'PE\0\0': raise ValueError('invalid PE signature')
    machine,n=le(image,p+4,2),le(image,p+6,2)
    opt=p+24; optional_bytes=le(image,p+20,2)
    if machine!=0x1f2 or le(image,opt,2)!=0x10b or optional_bytes<128:
        raise ValueError('expected Xbox PowerPC PE32')
    if le(image,opt+28)!=base: raise ValueError('PE base mismatch')
    sections=[]
    for i in range(n):
        q=opt+optional_bytes+i*40
        name=span(image,q,8).rstrip(b'\0').decode('ascii')
        vs,va,rs,ra=struct.unpack('<IIII',span(image,q+8,16))
        span(image,va,vs)
        sections.append(dict(name=name,rva=va,virtual_bytes=vs,raw_bytes=rs,raw_offset=ra,flags=le(image,q+36)))
    pdata_rva,pdata_bytes=struct.unpack('<II',span(image,opt+96+3*8,8))
    if pdata_bytes%8: raise ValueError('misaligned exception directory')
    functions=[]
    for start,packed in struct.iter_unpack('>II',span(image,pdata_rva,pdata_bytes)):
        if not start: continue
        size=((packed>>8)&0x3fffff)*4
        if not size or start%4: raise ValueError('invalid pdata range')
        if not any(s['flags']&0x20000000 and base+s['rva']<=start and start+size<=base+s['rva']+s['virtual_bytes'] for s in sections):
            raise ValueError(f'function outside executable section: {start:08X}')
        functions.append((start,size,packed))
    functions.sort()
    for a,b in zip(functions,functions[1:]):
        if a[0]+a[1]>b[0]: raise ValueError('overlapping pdata ranges')
    return dict(machine=f'{machine:04X}',entry_point=base+le(image,opt+16),sections=sections,functions=functions)

def imports(image,base,metadata):
    rows={}
    for record in metadata['imports']:
        for addr in record['slot_addresses']:
            a=int(addr,16); word=be(image,a-base)
            kind=word>>24; ordinal=word&0xffff
            if kind not in (0,1): raise ValueError('unknown import slot type')
            key=(record['library'],ordinal)
            item=rows.setdefault(key,{'library':key[0],'ordinal':ordinal,'value_slots':set(),'thunk_slots':set()})
            item['value_slots' if kind==0 else 'thunk_slots'].add(a)
    return [dict(library=i['library'],ordinal=f"{i['ordinal']:04X}",value_slots=sorted(i['value_slots']),thunk_slots=sorted(i['thunk_slots'])) for _,i in sorted(rows.items())]

def direct_calls(image,base,functions,import_rows):
    starts={a for a,s,p in functions}
    thunks={a:(r['library'],r['ordinal']) for r in import_rows for a in r['thunk_slots']}
    for start,size,_ in functions:
        code=span(image,start-base,size)
        for i,(word,) in enumerate(struct.iter_unpack('>I',code)):
            # PPC primary opcode 18 with LK=1: direct branch-and-link.
            if word>>26!=18 or not word&1: continue
            site=start+i*4; disp=word&0x03fffffc
            if disp&0x02000000: disp-=0x04000000
            target=(disp if word&2 else site+disp)&0xffffffff
            lib,ordinal=thunks.get(target,('',''))
            kind='import' if lib else ('pdata' if target in starts else 'unclassified')
            yield (f'{start:08X}',f'{site:08X}',f'{target:08X}',kind,lib,ordinal)

def tsv(path,head,rows):
    with path.open('w',newline='',encoding='utf-8') as f:
        w=csv.writer(f,delimiter='\t',lineterminator='\n');w.writerow(head);w.writerows(rows)

def json_write(path,data):
    path.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n',encoding='utf-8')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--originals',type=Path,default=ROOT/'originals')
    p.add_argument('--output',type=Path,default=ROOT/'analysis')
    p.add_argument('--images',type=Path,default=ROOT/'originals'/'decoded')
    p.add_argument('--lzx',type=Path,required=True)
    a=p.parse_args()
    c=config(); paths={}
    for item in c['source']:
        src=a.originals.joinpath(*safe_key(item['key']).parts);check(src,item);paths[item['id']]=src
    members=parse_pirs(paths['pirs'].read_bytes())
    inputs={'dash_17559':paths['dash'].read_bytes(),'dash_17559_basic':paths['dash_basic'].read_bytes()}
    for name,member in sorted(members.items()):
        if name.endswith('.xex'):
            ident=name.removeprefix('$flash_').removeprefix('$install_').removesuffix('.xex')+'_17559'
            if ident=='dash_17559':
                if member['payload']!=inputs[ident]:raise ValueError('PIRS dashboard mismatch')
            else: inputs[ident]=member['payload']
    expected_xam=next(b['sha256'] for b in c['build'] if b['id']=='xam_17559')
    if hashlib.sha256(inputs['xam_17559']).hexdigest()!=expected_xam:raise ValueError('retail XAM mismatch')
    summary={}
    for ident,data in sorted(inputs.items()):
        meta=parse_xex(data)
        if meta.get('encryption'):
            summary[ident]={'state':'unsupported-encrypted','source_sha256':hashlib.sha256(data).hexdigest()};continue
        image,info=decode(data,a.lzx.resolve())
        info['source_sha256']=hashlib.sha256(data).hexdigest()
        info['state']='verified'
        base=info['image_base']
        pe=pe_info(image,base)
        rows=imports(image,base,meta)
        info['distinct_imports']=len(rows)
        info['function_imports']=sum(bool(r['thunk_slots']) for r in rows)
        info['value_only_imports']=sum(not r['thunk_slots'] for r in rows)
        out=a.output/ident;out.mkdir(parents=True,exist_ok=True)
        a.images.mkdir(parents=True,exist_ok=True);(a.images/(ident+'.image.bin')).write_bytes(image)
        resources=[]
        for r in meta['resources']:
            payload=span(image,int(r['address'],16)-base,r['bytes'])
            resources.append(dict(id=r['id'],address=r['address'],bytes=r['bytes'],sha256=hashlib.sha256(payload).hexdigest(),magic=payload[:4].hex()))
        info['resource_count']=len(resources)
        json_write(out/'resource_hashes.json',resources)
        tsv(out/'imports.tsv',['library','ordinal','value_slots','thunk_slots'],
            ((r['library'],r['ordinal'],','.join(f'{x:08X}' for x in r['value_slots']),','.join(f'{x:08X}' for x in r['thunk_slots'])) for r in rows))
        if pe:
            funcs=pe.pop('functions')
            info['pdata_functions']=len(funcs);info['pe']=pe
            tsv(out/'functions.tsv',['address','size','packed','evidence'],
                ((f'{start:08X}',size,f'{packed:08X}','pdata') for start,size,packed in funcs))
            calls=list(direct_calls(image,base,funcs,rows))
            info['direct_call_sites']=len(calls)
            info['direct_import_call_sites']=sum(r[3]=='import' for r in calls)
            info['unclassified_direct_call_sites']=sum(r[3]=='unclassified' for r in calls)
            # Unique edges rather than every instruction: compact, reproducible, no original code.
            edges=sorted(set((r[0],r[2],r[3],r[4],r[5]) for r in calls))
            tsv(out/'direct_call_edges.tsv',['caller','target','kind','library','ordinal'],edges)
        else:
            info['pdata_functions']=0;info['pe']=None
        json_write(out/'decoded.json',info);summary[ident]=info
        print(ident,info['image_bytes'],info['pdata_functions'],info['distinct_imports'])
    if summary['dash_17559']['sha256']!=summary['dash_17559_basic']['sha256']:
        raise ValueError('independent dashboard encodings disagree')
    json_write(a.output/'decoded_summary.json',summary)

if __name__=='__main__':
    main()
