import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_ui_preference_evidence import candidate
def d(op,rt,ra,imm):return (op<<26)|(rt<<21)|(ra<<16)|(imm&65535)
class Preferences(unittest.TestCase):
    def test_user_and_console_only(self):
        for cat,key in ((3,0x22),(7,0x0b)):
            result=candidate([d(14,3,0,cat),d(14,4,0,key),d(14,6,0,4),0x48000001],3)
            self.assertEqual((result["category"],result["selector"]),(cat,key))
        self.assertIsNone(candidate([d(14,3,0,2),d(14,4,0,1),0x48000001],2))
    def test_not_proven_through_branch_or_load(self):
        self.assertIsNone(candidate([d(14,3,0,7),0x48000004,d(14,4,0,11),0x48000001],3))
        self.assertIsNone(candidate([d(14,3,0,7),d(14,4,0,11),d(32,4,1,80),0x48000001],3))
