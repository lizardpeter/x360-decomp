import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from analyze_metro_boot import summarize
class BootEvidence(unittest.TestCase):
    def test_boot_observation(self):
        result=summarize(["METRO_BOOT pass guest_thread",
          "warn METRO_STUB name=__imp__Example lr=0x00001008 r3=0x00000001 r4=0x00000002 r5=0x00000003 r6=0x00000004",
          "METRO_BOOT frames 60","info METRO_PAD user=0 buttons=0x0008"],
          {"xam_17559":[(0x1000,16)]})
        self.assertEqual(result["stub_call_sites"][0]["pdata_caller"],"00001000")
        self.assertEqual(result["pad_transitions"][0]["buttons"],8)
        self.assertFalse(result["navigation_visually_verified"])
        self.assertFalse(result["menu_visually_verified"])
    def test_no_invented_calls(self):
        result=summarize(["METRO_BOOT pass guest_thread","METRO_BOOT xam_attach_begin"],{"xam":[]})
        self.assertFalse(result["stub_call_sites"])
        self.assertFalse(result["frame_counts"])
        self.assertFalse(result["navigation_visually_verified"])
if __name__=="__main__":unittest.main()
