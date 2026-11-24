import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import xex
import pirs
import fetch_originals

def fixture():
    b = bytearray(512)
    struct.pack_into(">6I", b, 0, 0x58455832, 1, len(b), 0, 48, 2)
    struct.pack_into(">4I", b, 24, 0x103ff, 80, 0x2ff, 240)
    struct.pack_into(">I", b, 52, 0x2000)
    names = b"xam.xex\0xboxkrnl.exe\0\0\0\0"
    recs = []
    for index, address in [(0, 0x92000000),(0,0x92000004),(1,0x92000008)]:
        rec = bytearray(44)
        struct.pack_into(">I",rec,0,44)
        struct.pack_into(">IIIHHI",rec,24,1,0x20449700,0x20449700,index,1,address)
        recs.append(rec)
    table = struct.pack(">III",12+len(names)+sum(map(len,recs)),len(names),2)+names+b"".join(recs)
    b[80:80+len(table)] = table
    # Keep resource table separate from the import table.
    struct.pack_into(">I", b, 36, 256)
    struct.pack_into(">I8sII", b,256,20,b"dashmain",0x92001000,32)
    return b

class XexTests(unittest.TestCase):
    def test_repeated_library_records(self):
        r=xex.parse(fixture())
        self.assertEqual([i["library"] for i in r["imports"]],["xam.xex","xam.xex","xboxkrnl.exe"])
        self.assertEqual(r["imports"][2]["slot_addresses"],["92000008"])
        self.assertEqual(r["resources"][0]["id"],"dashmain")
    def test_truncated(self):
        with self.assertRaises(ValueError):
            xex.parse(fixture()[:100])
    def test_invalid_record_size(self):
        b=fixture()
        struct.pack_into(">I",b,80+12+24,0)
        with self.assertRaises(ValueError):
            xex.parse(b)
    def test_bad_name_index(self):
        b=fixture()
        struct.pack_into(">H",b,80+12+24+36,9)
        with self.assertRaises(ValueError):
            xex.parse(b)
    def test_bad_resource_length(self):
        b=fixture()
        struct.pack_into(">I",b,256,19)
        with self.assertRaises(ValueError):
            xex.parse(b)

class PirsTests(unittest.TestCase):
    def make(self):
        b=bytearray(0x4000)
        b[:4]=b"PIRS"
        struct.pack_into(">I", b,0x340,0x400)
        b[0x37b]=1
        b[0x37c]=1
        o=0x2000
        b[o:o+5]=b"a.xex"
        b[o+40]=0x45
        b[o+47]=1
        b[o+50:o+52]=b"\xff\xff"
        b[o+52:o+56]=(4).to_bytes(4,"big")
        b[0x3000:0x3004]=b"XEX2"
        return b
    def test_contiguous(self):
        self.assertEqual(pirs.parse(self.make())["a.xex"]["payload"],b"XEX2")
    def test_boundary(self):
        self.assertEqual(pirs.block_offset(0,169),170*4096)
        self.assertEqual(pirs.block_offset(0,170),173*4096)
    def test_truncated(self):
        with self.assertRaises(ValueError):
            pirs.parse(self.make()[:0x3002])
    def test_overlapping(self):
        b=self.make()
        b[0x2000+47]=0
        with self.assertRaises(ValueError):
            pirs.parse(b)
    def test_path_escape(self):
        b=self.make()
        b[0x2000:0x2005]=b"../xx"
        with self.assertRaises(ValueError):
            pirs.parse(b)
    def test_source_path(self):
        with self.assertRaises(ValueError):
            fetch_originals.safe_key("../outside")
if __name__=="__main__":
    unittest.main()
