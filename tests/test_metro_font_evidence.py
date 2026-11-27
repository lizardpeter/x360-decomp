import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_font_evidence import refs
def d(op,rt,ra,imm):return (op<<26)|(rt<<21)|(ra<<16)|(imm&65535)
class FontReferences(unittest.TestCase):
    def test_split_address_with_intervening_compare(self):
        words=[d(15,11,0,0x9290),d(11,0,4,1),d(14,3,11,-32)]
        self.assertEqual(list(refs(words,0x92000000,{0x928fffe0})),[(0x92000008,0x928fffe0,"constructed_address")])
    def test_unknown_and_branch_clear_constants(self):
        for barrier in (0,0x48000008):
            words=[d(15,11,0,0x9290),barrier,d(14,3,11,-32)]
            self.assertEqual(list(refs(words,0x92000000,{0x928fffe0})),[])
    def test_pointer_load_and_overwrite(self):
        words=[d(15,11,0,0x9290),d(32,3,11,-32),d(14,11,0,1),d(32,4,11,-32)]
        self.assertEqual(list(refs(words,0x92000000,{0x928fffe0})),[(0x92000004,0x928fffe0,"memory_operand")])
