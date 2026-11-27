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

from metro_guide_evidence import deferred_trace_plan
class DeferredStartup(unittest.TestCase):
    def test_continuations_and_actual_compares(self):
        rows=[{"pc":"00001000","kind":"branch","linked":True,"target":"00002000"},
              {"pc":"00001004","kind":"compare_immediate","register":3,"value":0},
              {"pc":"00001008","kind":"conditional_branch","target":"00001014"},
              {"pc":"0000100C","kind":"branch","linked":True,"target":"00003000"},
              {"pc":"00001010","kind":"branch","linked":True,"target":"00004000"},
              {"pc":"00001014","kind":"return"}]
        plan=deferred_trace_plan(rows)
        self.assertEqual(plan["00001004"]["result_kind"],"r3_class")
        self.assertEqual(plan["00001010"]["name"],"deferred_after_00003000")
        self.assertIn("00001014",plan)
        code,_=insert("  // METRO_GUEST_PC 00001004\n", "xam",plan)
        self.assertIn("ctx.r3.u32",code)
        self.assertNotIn("r4.u32",code)
    def test_unknown_class_rejected(self):
        with self.assertRaises(ValueError):
            insert("  // METRO_GUEST_PC 00001004\n","xam",{"00001004":{"name":"deferred_bad","phase":"compare","result_kind":"r4_class"}})

    def test_device_scope_categorizes_without_pointer_values(self):
        code,_=insert("  // METRO_GUEST_PC 8184B914\n","xam",{"8184B914":{"name":"device_publish","phase":"store","result_kind":"r31_nonzero"}})
        self.assertIn('ctx.r31.u32?"nonzero":"zero"',code)
        self.assertNotIn("negative",code)
        code,_=insert("  // METRO_GUEST_PC 8184B8F8\n","xam",{"8184B8F8":{"name":"device_process_type","phase":"compare","result_kind":"r3_process_type"}})
        self.assertIn('ctx.r3.u32==2?"system"',code)

    def test_guest_trace_includes_thread_and_caller_identity_only(self):
        code,_=insert("  // METRO_GUEST_PC 816BDE90\n","xam",{"816BDE90":{"name":"deferred_subsystem_816BDE90","phase":"entry"}})
        self.assertIn("pcr=%08X lr=%08X",code)
        self.assertIn("ctx.r13.u32,static_cast<unsigned>(ctx.lr)",code)
        self.assertNotIn("ctx.r4.u32",code)
