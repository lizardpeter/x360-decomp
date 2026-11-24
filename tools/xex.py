"""Read XEX2 metadata only. No decryption, patching or executable loading."""
import struct

def span(data, offset, count):
    if offset < 0 or count < 0 or offset > len(data) - count:
        raise ValueError("out-of-bounds XEX span")
    return data[offset:offset + count]

def u32(data, offset):
    return struct.unpack(">I", span(data, offset, 4))[0]

def u16(data, offset):
    return struct.unpack(">H", span(data, offset, 2))[0]

def version(value):
    return f"{value >> 28}.{(value >> 24) & 15}.{(value >> 8) & 65535}.{value & 255}"

def parse(data):
    if span(data, 0, 4) != b"XEX2":
        raise ValueError("not XEX2")
    header_size, security, n = u32(data, 8), u32(data, 16), u32(data, 20)
    if header_size > len(data) or header_size < 24:
        raise ValueError("invalid XEX header size")
    header = span(data, 0, header_size)
    span(header, 24, n * 8)
    opts = {}
    for i in range(n):
        key, value = struct.unpack(">II", span(header, 24 + 8*i, 8))
        if key in opts:
            raise ValueError("duplicate XEX optional header")
        opts[key] = value
    result = {"file_bytes": len(data), "header_bytes": header_size,
              "image_bytes": u32(header, security + 4),
              "image_base": opts.get(0x10201), "entry_point": opts.get(0x10100),
              "optional_headers": {f"{k:08X}": v for k, v in opts.items()},
              "imports": [], "resources": []}
    if 0x3ff in opts:
        p = opts[0x3ff]
        span(header, p, u32(header, p))
        result["encryption"] = u16(header, p+4)
        result["compression"] = u16(header, p+6)
    if 0x103ff in opts:
        p = opts[0x103ff]
        total, string_bytes, name_count = struct.unpack(">III", span(header, p, 12))
        table = span(header, p, total)
        strings = span(table, 12, string_bytes)
        names = []
        pos = 0
        for _ in range(name_count):
            end = strings.find(b"\0", pos)
            if end < 0 or end == pos:
                raise ValueError("invalid import library name")
            names.append(strings[pos:end].decode("ascii"))
            pos = (end+4) & ~3
            if pos > len(strings):
                raise ValueError("invalid import string alignment")
        pos = 12 + string_bytes
        # Multiple records can refer to the same name. Walk record extents.
        while pos < len(table):
            span(table, pos, 40)
            size = u32(table, pos)
            index, count = u16(table, pos+36), u16(table, pos+38)
            if size < 40 or size != 40 + count*4 or index >= len(names):
                raise ValueError("invalid import record")
            rec = span(table, pos, size)
            result["imports"].append({
                "library": names[index], "library_id": f"{u32(rec,24):08X}",
                "version": version(u32(rec,28)), "minimum_version": version(u32(rec,32)),
                "slot_count": count,
                "slot_addresses": [f"{u32(rec,40+4*i):08X}" for i in range(count)]})
            pos += size
    if 0x2ff in opts:
        p = opts[0x2ff]
        size = u32(header, p)
        if size < 4 or (size-4) % 16:
            raise ValueError("invalid resource table size")
        for pos in range(4, size, 16):
            r = span(header, p+pos, 16)
            result["resources"].append({
                "id": r[:8].rstrip(b"\0").decode("ascii"),
                "address": f"{u32(r,8):08X}", "bytes": u32(r,12)})
    return result
