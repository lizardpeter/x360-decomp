import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from instrument_metro_profile import insert,points,EXPORTS,STORAGE_CALLS,verify_export_join,verify_storage_join

class ProfileTrace(unittest.TestCase):
    def test_original_entry_and_status_markers(self):
        p=points()["generated_xam"]
        self.assertEqual(len(EXPORTS),41)
        self.assertEqual(len(STORAGE_CALLS),24)
        source="// METRO_GUEST_PC 816DB860\nentry();\n// METRO_GUEST_PC 81680A74\ncall();\n// METRO_GUEST_PC 81680A78\nnext();\n"
        out,hits=insert(source,"generated_xam",p)
        self.assertEqual(sum(hits.values()),3)
        self.assertIn("api=XamProfileCreateEnumerator phase=entry",out)
        self.assertIn("api=StfsCreateDevice phase=return",out)
        self.assertIn('ctx.r3.u32==0?"zero"',out)
        for token in ("ctx.r4","GetGuestMemory","%08X","base +"):
            self.assertNotIn(token,out)
        with self.assertRaises(ValueError):insert(out,"generated_xam",p)

    def test_original_identity_and_call_join(self):
        verify_export_join(EXPORTS)
        with self.assertRaises(ValueError):verify_export_join({})
        sites={}
        for pc,n in STORAGE_CALLS.items():
            sites.setdefault(n,[]).append({"site":f"{pc:08X}","linked":True})
        verify_storage_join({"boundary_sites":sites})
        sites["StfsCreateDevice"].pop()
        with self.assertRaises(ValueError):verify_storage_join({"boundary_sites":sites})
