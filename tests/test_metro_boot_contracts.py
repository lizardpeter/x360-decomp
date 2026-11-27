import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from patch_metro_boot_contracts import *

class Contracts(unittest.TestCase):
    def test_original_record_count(self):verify_records()
    def test_exact_patch_anchors(self):
        for old,new in ((MERGE_OLD,MERGE_NEW),(SYMBOL_OLD,SYMBOL_NEW),(PTE_OLD,PTE_NEW),(EVENT_OLD,EVENT_NEW),(PAD_OLD,PAD_NEW)):
            self.assertEqual(replace(old,old,new),new)
            for bad in ("",old+old,new):
                with self.assertRaises(ValueError):replace(bad,old,new)
        self.assertIn("library.min_version.value",MERGE_NEW)
        self.assertIn("addresses.emplace(address",MERGE_NEW)
        self.assertIn("region.state & kernel::kMemoryAllocationCommit",PTE_NEW)
        self.assertIn("header->signal_state = 0",EVENT_NEW)
        self.assertNotIn("0x0157",EVENT_NEW)
    def test_stub_trace_preserves_macro_continuation(self):
        fixture=TRACE_ANCHOR+" "+chr(92)+"\n"+("    static constinit ::std::atomic_flag rex_stub_seen_; "+chr(92)+"\n")*3
        result=trace(fixture)
        self.assertEqual(result.count("REX_METRO_TRACE_STUB(subroutine);"),3)
        self.assertIn("metro_count.fetch_add",result)
        with self.assertRaises(ValueError):trace(result)
if __name__=="__main__":unittest.main()
