import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_xui_text_twins import normalize,candidates,signature,incoming_calls

class TestTextTwins(unittest.TestCase):
    def test_external_branch_relocation(self):
        x=(0x48001001,0x4e800020)
        d=(0x48002001,0x4e800020)
        self.assertEqual(normalize(x,0x10000,0x10000,0x5000),
                         normalize(d,0x20000,0x20000,0x5000))
    def test_internal_branch_retained(self):
        x=(0x48000004,0x4e800020)
        self.assertEqual(normalize(x,0x10000,0x10000,0x5000),x)
    def test_address_pair_normalized(self):
        x=(0x3d609200,0x386b1234,0x4e800020)
        d=(0x3d608160,0x386b4567,0x4e800020)
        self.assertEqual(normalize(x,0x92000000,0x92000000,0x100000),
                         normalize(d,0x81600000,0x81600000,0x100000))
    def test_scalar_not_normalized(self):
        x=(0x3d600002,0x386b1234,0x4e800020)
        self.assertEqual(normalize(x,0x92000000,0x92000000,0x100000),x)
    def test_ambiguity_preserved(self):
        n=(0x4e800020,)
        self.assertEqual(candidates({"norm":n},{},{n:[1,2]},{}),
                         {"kind":"exact_normalized","addresses":[1,2]})
        self.assertEqual(len(signature(n)),64)
    def test_all_direct_callers_and_tail_edges_preserved(self):
        rows={10:{"calls":[(11,20,True),(12,30,False)]},
              15:{"calls":[(16,20,False)]},20:{"calls":[]}}
        self.assertEqual(incoming_calls(rows,[20,30,40]),
                         {20:[(10,11,True),(15,16,False)],30:[(10,12,False)],40:[]})
