"""Reader for the observed read-only single-table contiguous PIRS format."""
import hashlib

def read(data, offset, size):
    if offset < 0 or size < 0 or offset > len(data)-size:
        raise ValueError("truncated PIRS range")
    return data[offset:offset+size]

def number(data, offset, size, endian="big"):
    return int.from_bytes(read(data, offset, size), endian)

def block_offset(base, index):
    if index < 0:
        raise ValueError("negative block")
    block, level = index, 170
    for _ in range(3):
        block += (index + level)//level
        if index < level:
            break
        level *= 170
    return base + (block << 12)

def parse(data):
    if read(data, 0, 4) != b"PIRS":
        raise ValueError("not PIRS")
    header_size = number(data, 0x340, 4)
    if header_size < 0x381 or header_size > len(data):
        raise ValueError("invalid PIRS header")
    if not (number(data, 0x37b, 1) & 1) or number(data, 0x37c, 2, "little") != 1:
        raise ValueError("unsupported PIRS volume layout")
    base = (header_size + 4095) & ~4095
    start = number(data, 0x37e, 3, "little")
    table = read(data, block_offset(base, start), 4096)
    members = {}
    used = {start}
    for off in range(0, len(table), 64):
        entry = table[off:off+64]
        if not entry[0]:
            break
        flags = entry[40]
        length = flags & 63
        if not 1 <= length <= 40 or flags & 0x80 or not flags & 0x40:
            raise ValueError("unsupported PIRS member layout")
        name = entry[:length].decode("ascii")
        if name in (".", "..") or "/" in name or "\\" in name or "\0" in name or name in members:
            raise ValueError("invalid or duplicate PIRS member name")
        if number(entry, 50, 2) != 0xffff:
            raise ValueError("unsupported nested PIRS path")
        block = number(entry, 47, 3, "little")
        size = number(entry, 52, 4)
        count = (size+4095)//4096
        if count > len(data)//4096:
            raise ValueError("impossible member extent")
        if any(b in used for b in range(block, block+count)):
            raise ValueError("overlapping PIRS members")
        used.update(range(block, block+count))
        payload = b"".join(read(data, block_offset(base, block+i), min(4096, size-i*4096))
                           for i in range(count))
        members[name] = {"bytes":size, "start_block":block,
                         "sha256":hashlib.sha256(payload).hexdigest(), "payload":payload}
    return members
