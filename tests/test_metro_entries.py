import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_metro_entries import branch,terminal,verify_candidates

class Entries(unittest.TestCase):
    def test_branch(self):
        self.assertEqual(branch(0x1000,0x48000011),0x1010)
        self.assertEqual(branch(0x1000,0x4BFFFFF0),0x0ff0)
        self.assertTrue(terminal(0x4e800020))
        self.assertFalse(terminal(0x48000001))
    def test_pointer_evidence(self):
        base=0x1000;image=bytearray(64)
        struct.pack_into(">I",image,0,0x1024)
        struct.pack_into(">I",image,0x24,0x38600001)
        struct.pack_into(">I",image,0x28,0x4e800020)
        pe={"functions":[],"sections":[{"rva":0,"loaded_bytes":16,"flags":0,"name":".rdata"},
                                      {"rva":32,"loaded_bytes":32,"flags":0x20000000,"name":".text"}]}
        accepted,rejected=verify_candidates(image,base,pe,{0x1024,0x102c})
        self.assertEqual([x["address"] for x in accepted],["00001024"])
        self.assertEqual(rejected[0]["reason"],"no_independent_pointer")
        pe["functions"]=[(0x1020,16,0)]
        self.assertEqual(verify_candidates(image,base,pe,{0x1024})[1][0]["reason"],"pdata_covered")

if __name__=="__main__":unittest.main()
