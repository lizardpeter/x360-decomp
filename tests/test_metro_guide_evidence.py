import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_guide_evidence import literal_mask,GUIDE_EXPORTS,SYSREQ_OWNERS
class GuideEvidence(unittest.TestCase):
    def test_literal_guide_bit(self):
        self.assertEqual(literal_mask(0x70630400)["kind"],"literal_0400")
        self.assertIsNone(literal_mask(0x70630008))
    def test_known_original_exports(self):
        self.assertEqual(GUIDE_EXPORTS["XamShowGuideUI"],0x816C3580)
        self.assertEqual(len(SYSREQ_OWNERS),4)
