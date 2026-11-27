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
    def test_font_return_contract_and_shutdown_cancellation(self):
        result=summarize([
            "METRO_UI pc=92202490 label=dash_font_register phase=entry count=1 r3=7014F500 r4=00000000 r5=00000000 r6=00000000 r7=00000000 r8=00000000",
            "METRO_UI pc=92265758 label=dash_font_register_1 phase=return count=1 r3=00000000 r4=00000000 r5=00000000 r6=00000000 r7=00000000 r8=00000000",
            "METRO_UI pc=92202518 label=dash_font_validate_base phase=return count=1 r3=00000001 r4=00000000 r5=00000000 r6=00000000 r7=00000000 r8=00000000",
            "METRO_UI_OPEN name=SegoeXbox-Light.xtt status=00000000 handle=F8000004 count=1 share=00000001 options=00000060",
            "METRO_GPU packet_stream_cancelled during shutdown"],{"dash":[]})
        self.assertNotIn("dash_font_register",result["font_call_results"])
        self.assertEqual(result["font_call_results"]["dash_font_register_1"]["observed_r3"],["00000000"])
        self.assertEqual(result["font_call_results"]["dash_font_validate_base"]["observed_r3"],["00000001"])
        self.assertEqual(result["resource_opens"][0]["options"],"00000060")
        self.assertEqual(result["gpu_shutdown_cancellations"],1)
        self.assertFalse(result["menu_visually_verified"])
    def test_text_categories_are_sampled_not_inferred(self):
        result=summarize([
            "METRO_TEXT pc=9222F308 label=text_verification_provider phase=return count=1 kind=status result=positive",
            "METRO_TEXT pc=9222F308 label=text_verification_provider phase=return count=16 kind=status result=negative",
            "METRO_TEXT pc=9222F348 label=text_signature_result phase=return count=1 kind=boolean result=zero"],{"dash":[]})
        a,b=result["text_trace_results"]
        self.assertEqual(a["count_lower_bound"],16)
        self.assertEqual(a["sample_counts"],{"positive":1,"negative":1})
        self.assertEqual(b["observed_categories"],{"zero":1})
        self.assertFalse(result["menu_visually_verified"])
    def test_deferred_sequence_preserves_order_and_categories(self):
        result=summarize([
            "METRO_GUIDE_TRACE module=xam pc=81696558 name=guide_boot_81696558 phase=entry count=1 result=observed",
            "METRO_GUIDE_TRACE module=xam pc=8169667C name=deferred_compare_8169667C phase=compare count=1 result=negative",
            "METRO_GUIDE_TRACE module=xam pc=816967A0 name=deferred_branch_81696680 phase=target count=1 result=observed"],{"xam":[]})
        self.assertEqual([r["pc"] for r in result["deferred_startup_sequence"]],["81696558","8169667C","816967A0"])
        self.assertEqual(result["deferred_startup_sequence"][1]["result"],"negative")
        self.assertFalse(result["menu_visually_verified"])
if __name__=="__main__":unittest.main()

class GuideThreadEvidence(unittest.TestCase):
    def test_optional_thread_and_lr_are_preserved(self):
        result=summarize([
            "METRO_GUIDE_TRACE module=xam pc=816BDE90 name=deferred_subsystem_816BDE90 phase=entry count=1 result=observed pcr=30043000 lr=816966A8",
            "METRO_GUIDE_TRACE module=xam pc=81899570 name=deferred_key_service phase=return count=1 result=negative pcr=30043000 lr=81899570"],{"xam":[]})
        self.assertEqual([r["pcr"] for r in result["deferred_startup_sequence"]],["30043000","30043000"])
        self.assertEqual(result["deferred_startup_sequence"][0]["lr"],"816966A8")
