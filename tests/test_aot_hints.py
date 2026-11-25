import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_aot_hints import tail_target, verify

class HintTests(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(tail_target(0x1000,0x48000008),0x1008)
        self.assertEqual(tail_target(0x1000,0x4bfffffc),0xffc)
        self.assertEqual(tail_target(0x1000,0x4800000a),8)
        self.assertIsNone(tail_target(0x1000,0x48000009))
        self.assertIsNone(tail_target(0x1000,0x60000000))
    def test_evidence(self):
        base=0x1000
        image=struct.pack(">IIII",0x48000008,0,0x4e800020,0)
        pe={"functions":[(base,4,0)],"sections":[{"rva":0,"loaded_bytes":16,"flags":0x20000000}]}
        self.assertEqual(verify(image,base,pe,{0x1008:[base]}),1)
        for candidates in ({base:[base]},{0x1008:[base+4]},{0x1002:[base]},{0x2000:[base]}):
            with self.assertRaises(ValueError):
                verify(image,base,pe,candidates)
if __name__=="__main__":unittest.main()
