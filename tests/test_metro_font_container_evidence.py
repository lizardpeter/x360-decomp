import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_font_container_evidence import inspect
class Fonts(unittest.TestCase):
    def test_bounded_font_tables(self):
        data=bytearray(160)
        struct.pack_into(">4sHHHH",data,0,b"\x00\x01\x00\x00",3,0,0,0)
        for i,(tag,offset,size) in enumerate(((b"head",60,54),(b"maxp",114,6),(b"cmap",120,8))):
            struct.pack_into(">4sIII",data,12+i*16,tag,0,offset,size)
        struct.pack_into(">I",data,72,0x5F0F3CF5)
        struct.pack_into(">H",data,78,2048)
        struct.pack_into(">H",data,118,42)
        r=inspect(bytes(data))
        self.assertEqual(r["format"],"sfnt")
        self.assertEqual(r["faces"][0]["glyph_count"],42)
        self.assertEqual(r["faces"][0]["units_per_em"],2048)
        struct.pack_into(">I",data,24,99999)
        self.assertEqual(inspect(bytes(data))["format"],"unclassified")
    def test_magic_is_not_a_font(self):
        self.assertEqual(inspect(b"ttcf"+b"\0"*40)["format"],"unclassified")
        self.assertEqual(inspect(b"OTTO"+b"\0"*40)["embedded_sfnt_offsets"],[])
