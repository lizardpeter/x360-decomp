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
    def test_guest_consumption_not_inferred_from_host(self):
        result=summarize(["info METRO_PAD user=0 buttons=0x0008",
                          "info METRO_GUEST_PAD context=10000001 user=0 packet=12 buttons=0x0008",
                          "info METRO_GUEST_PAD context=10000001 user=0 packet=13 buttons=0x0000"],
                         {"xam":[]})
        self.assertEqual(len(result["pad_transitions"]),1)
        self.assertEqual([x["buttons"] for x in result["guest_pad_transitions"]],[8,0])
        self.assertEqual(result["guest_pad_transitions"][0]["packet"],12)
        self.assertFalse(result["navigation_visually_verified"])
    def test_no_invented_calls(self):
        result=summarize(["METRO_BOOT pass guest_thread","METRO_BOOT xam_attach_begin"],{"xam":[]})
        self.assertFalse(result["stub_call_sites"])
        self.assertFalse(result["frame_counts"])
        self.assertFalse(result["navigation_visually_verified"])
    def test_original_intro_cannot_count_as_dashboard(self):
        result=summarize(["METRO_INTRO frames 113",
                          "METRO_BOOT dashboard_frame_baseline 113",
                          "METRO_BOOT pass dashboard_entry"],{"xam":[]})
        self.assertEqual(result["intro_frame_counts"],[113])
        self.assertEqual(result["frame_counter_baseline"],113)
        self.assertEqual(result["frame_counts"],[])
        self.assertTrue(result["frame_count_excludes_intro"])
        self.assertFalse(result["menu_visually_verified"])
    def test_post_attach_frame_counts_and_reset_are_separate(self):
        result=summarize(["METRO_INTRO frames 113",
                          "METRO_BOOT dashboard_frame_baseline 113",
                          "METRO_INTRO post_handoff_frames 5",
                          "METRO_BOOT frames 5",
                          "METRO_BOOT dashboard_frame_reset 0",
                          "METRO_BOOT frames 1"],{"xam":[]})
        self.assertEqual(result["frame_counts"],[5,1])
        self.assertEqual(result["post_handoff_frame_counts"],[5])
        self.assertEqual(result["frame_counter_resets"],[0])
        self.assertFalse(result["menu_visually_verified"])
    def test_resource_read_and_font_results_remain_distinct(self):
        result=summarize([
            "METRO_FONT pc=92265754 label=dash_font_register_1 kind=descriptor status=00000000 path=segoe units=28 detail=00000000",
            "METRO_UI_FILE name=SegoeXbox-Light.xtt size=4096 offset=0 requested=4096 actual=4096 status=00000000 count=1",
            "METRO_UI_FILE name=SegoeXbox-Light.xtt size=4096 offset=4096 requested=16 actual=0 status=00000000 count=2",
            "METRO_FONT pc=81699244 label=xam_font_patch_result kind=patch status=00000000 path=null units=0 detail=00000000"],
            {"dash":[]})
        self.assertEqual(result["font_probes"][0]["path"],"segoe")
        self.assertEqual(result["font_probes"][1]["path"],"null")
        self.assertEqual([r["actual"] for r in result["resource_reads"]],[4096,0])
        self.assertFalse(result["menu_visually_verified"])
if __name__=="__main__":unittest.main()
