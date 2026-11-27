import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_bootanim_evidence import riff_metadata,loader_references

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
