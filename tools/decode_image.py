"""Decode unencrypted XEX2 into a page-digest-verified loaded image."""
import ctypes
import hashlib

def span(data, off, n):
    if off < 0 or n < 0 or off > len(data)-n:
        raise ValueError('truncated range')
    return data[off:off+n]

def be(data, off, n=4):
    return int.from_bytes(span(data,off,n),'big')

def decode(data, lzx=None):
    if data[:4]!=b'XEX2': raise ValueError('not XEX2')
    header_size, sec, count = be(data,8),be(data,16),be(data,20)
    h=span(data,0,header_size)
    if header_size<24: raise ValueError('short header')
    span(h,24,count*8)
    opts={be(h,24+i*8):be(h,28+i*8) for i in range(count)}
    if len(opts)!=count or 0x3ff not in opts: raise ValueError('invalid optional headers')
    fmt=opts[0x3ff]; info_size=be(h,fmt)
    if info_size<8: raise ValueError('short format record')
    span(h,fmt,info_size)
    enc,comp=be(h,fmt+4,2),be(h,fmt+6,2)
    if enc: raise ValueError('encrypted XEX unsupported')
    page_size=4096 if be(h,sec+0x10c)&0x10000000 else 65536
    n=be(h,sec+0x180); desc=span(h,sec+0x184,n*24)
    runs=[(be(desc,24*i)>>4)*page_size for i in range(n)]
    size=sum(runs)
    if not n or not 0<size<=128*1024*1024 or size!=be(h,sec+4): raise ValueError('invalid image size')
    body=data[header_size:]; block_count=0
    if comp==0:
        image=span(body,0,size)
    elif comp==1:
        if (info_size-8)%8: raise ValueError('bad basic format')
        image=bytearray(); pos=0
        for off in range(fmt+8,fmt+info_size,8):
            d,z=be(h,off),be(h,off+4)
            if d+z>size-len(image): raise ValueError('basic extent exceeds image')
            image.extend(span(body,pos,d));image.extend(b'\0'*z);pos+=d;block_count+=1
        if len(image)!=size: raise ValueError('basic extent incomplete')
        image=bytes(image)
    elif comp==2:
        if info_size<36 or not lzx: raise ValueError('LZX adapter required')
        window=be(h,fmt+8); length=be(h,fmt+12); expected=span(h,fmt+16,20)
        if window<32768 or window>2097152 or window&(window-1): raise ValueError('bad window')
        pos=0; compressed=bytearray()
        while length:
            if length<26: raise ValueError('short LZX block')
            block=span(body,pos,length)
            if hashlib.sha1(block).digest()!=expected: raise ValueError('compressed block digest mismatch')
            nxt=be(block,0); expected=span(block,4,20); q=24
            while True:
                chunk=be(block,q,2);q+=2
                if not chunk:break
                compressed.extend(span(block,q,chunk));q+=chunk
            pos+=length;length=nxt;block_count+=1
        lib=ctypes.CDLL(str(lzx)); fn=lib.x360_lzx
        fn.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int];fn.restype=ctypes.c_int
        buf=ctypes.create_string_buffer(size); src=bytes(compressed)
        if fn(src,len(src),buf,size,window.bit_length()-1): raise ValueError('LZX decompression failed')
        image=buf.raw
    else: raise ValueError('unsupported compression')
    pos=0; expected=span(h,sec+0x114,20)
    for i,length in enumerate(runs):
        d=span(desc,24*i,24)
        if hashlib.sha1(span(image,pos,length)+d).digest()!=expected: raise ValueError(f'page run {i} digest mismatch')
        expected=d[4:];pos+=length
    return image, {'compression':comp,'compressed_blocks':block_count,'verified_page_runs':n,'page_size':page_size,'image_bytes':size,'image_base':be(h,sec+0x110),'sha256':hashlib.sha256(image).hexdigest()}
