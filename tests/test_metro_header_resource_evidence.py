import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_header_resource_evidence import archive,string_table,scene_strings,classify

class TestHeaderResourceEvidence(unittest.TestCase):
    def test_utf8_mode1_and_exact_labels(self):
        payload=b"home\0"+bytes(4)+b"movies & tv\0"+bytes(4)
        table=b"XUIS"+bytes([2,1])+struct.pack(">IH",12+len(payload),2)+payload
        rows=string_table(table)
        self.assertEqual([classify(r[2]) for r in rows],["home","movies"])
        self.assertEqual(rows[1][1],21)
        self.assertEqual(classify("movies & t"),"movies_short")
        self.assertIsNone(classify("My movies & tv"))
        with self.assertRaises(ValueError):string_table(table[:-1])
    def test_utf16_mode0(self):
        def wide(s):return struct.pack(">H",len(s))+s.encode("utf-16-be")
        payload=wide("hom")+wide("identifier")
        table=b"XUIS"+bytes([1,0])+struct.pack(">IH",12+len(payload),1)+payload
        self.assertEqual(classify(string_table(table)[0][2]),"home_short")
    def test_archive_bounds(self):
        body=b"123";name=b"a.xus"
        directory=struct.pack(">IIB",len(body),0,len(name))+name
        data=b"XUIZ"+struct.pack(">IIIIH",3,22+len(directory)+len(body),0,len(directory),1)+directory+body
        self.assertEqual(archive(data),[("a.xus",0,body)])
        with self.assertRaises(ValueError):archive(data[:-1])
    def test_scene_string_bounds(self):
        strings=struct.pack(">IH",5,1)+b"home\0"
        data=b"XUIB"+struct.pack(">IIHIH",8,0,14,32+len(strings),1)+struct.pack(">4sII",b"STRN",32,len(strings))+strings
        self.assertEqual(scene_strings(data),[(0,38,"home")])
        with self.assertRaises(ValueError):scene_strings(data[:-1])
