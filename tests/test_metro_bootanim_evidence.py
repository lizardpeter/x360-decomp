import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_bootanim_evidence import riff_metadata,loader_references,xma1_format,matching_functions

def wave():
    fmt=struct.pack("<HHIIHH",1,2,48000,192000,4,16)
    body=b"WAVE"+b"fmt "+struct.pack("<I",len(fmt))+fmt+b"JUNK"+struct.pack("<I",1)+b"x\0"+b"data"+struct.pack("<I",4)+b"\0"*4
    return b"RIFF"+struct.pack("<I",len(body))+body

class BootanimEvidence(unittest.TestCase):
    def test_riff_bounds(self):
        payload=wave()
        result=riff_metadata(payload)
        self.assertEqual(result["format"]["sample_rate"],48000)
        self.assertEqual([c["id"] for c in result["chunks"]],["fmt ","JUNK","data"])
        with self.assertRaises(ValueError):riff_metadata(payload[:-1])
        with self.assertRaises(ValueError):riff_metadata(b"RIFF"+b"\0"*20)
    def test_xma1_header_and_packet_validation(self):
        fmt=struct.pack("<HHHHHBB",0x165,16,0x10d6,0,1,0,2)
        fmt+=struct.pack("<IIIIBBH",24000,48000,0,0,0,2,3)
        body=b"WAVE"+b"fmt "+struct.pack("<I",len(fmt))+fmt+b"data"+struct.pack("<I",2048)+b"\0"*2048
        parsed=riff_metadata(b"RIFF"+struct.pack("<I",len(body))+body)
        self.assertEqual(parsed["format"]["streams"][0]["sample_rate"],48000)
        self.assertEqual(parsed["format"]["channels"],2)
        self.assertEqual(parsed["packet_count"],1)
        with self.assertRaises(ValueError):xma1_format(fmt[:-1])
        with self.assertRaises(ValueError):xma1_format(fmt[:8]+b"\0\0"+fmt[10:])
    def test_normalized_cross_module_match(self):
        a=struct.pack(">4I",0x3c80981a,0x80840020,0x48001001,0x4e800020)
        b=struct.pack(">4I",0x3c80819a,0x80840020,0x48002001,0x4e800020)
        c=struct.pack(">4I",0x3c80819a,0x80840024,0x48002001,0x4e800020)
        src={"functions":[(0x1000,16,0)]}
        dst={"functions":[(0x2000,16,0),(0x2010,16,0)]}
        result=matching_functions(a,0x1000,src,b+c,0x2000,dst,[0x1000])[0]
        self.assertEqual(result["exact"],["00002000"])
        self.assertEqual(result["near"][0]["address"],"00002010")
    def test_loader_reference(self):
        base=0x10000000;image=bytearray(128)
        image[:13]=b"bootanim.xex\0"
        struct.pack_into(">I",image,32,base)
        struct.pack_into(">3I",image,64,0x3c801000,0x38840000,0x4e800020)
        pe={"sections":[{"rva":0,"loaded_bytes":64,"flags":0},
                        {"rva":64,"loaded_bytes":64,"flags":0x20000000}],
            "functions":[(base+64,12,0)]}
        result=loader_references(image,base,pe)
        self.assertEqual(result["literal_addresses"],["10000000"])
        self.assertIn("10000020",result["pointer_addresses"])
        self.assertEqual(result["code_references"][0]["target"],"10000000")

if __name__=="__main__":unittest.main()
