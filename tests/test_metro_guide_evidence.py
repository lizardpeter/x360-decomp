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

from instrument_metro_guide import insert
class GuideInstrumentation(unittest.TestCase):
    def test_trace_inserts_at_exact_pc(self):
        source="  // METRO_GUEST_PC 816F0E88\n  ctx.r3.u64=9;\n"
        code,hits=insert(source,"xam",{"816F0E88":{"name":"init","phase":"return"}})
        self.assertEqual(hits["816F0E88"],1)
        self.assertIn("METRO_GUIDE_TRACE",code)
        self.assertIn("negative",code)
        self.assertLess(code.index("METRO_GUIDE_TRACE"),code.index("ctx.r3.u64=9"))
        with self.assertRaises(ValueError):insert(code,"xam",{})
    def test_unmatched_source_is_untouched(self):
        code,hits=insert("  // METRO_GUEST_PC 816F0E84\n","xam",{})
        self.assertEqual(code,"  // METRO_GUEST_PC 816F0E84\n")
        self.assertFalse(hits)
