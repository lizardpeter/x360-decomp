import sys
import tomllib
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_intro import append_module
from stage_metro_xam_aot import manifest

class TestMetroIntro(unittest.TestCase):
    def test_original_modules_unchanged(self):
        old=tomllib.loads(manifest());new=tomllib.loads(append_module(manifest()))
        self.assertEqual(old["entrypoint"],new["entrypoint"])
        self.assertEqual(old["modules"],new["modules"][:2])
        module=new["modules"][2]
        self.assertEqual(module["project_name"],"metro_bootanim")
        self.assertEqual(module["guest_path"],"bootanim.xex")
        self.assertEqual(module["includes"],["verified-bootanim-entries.toml"])
        self.assertTrue(module["is_dll"])
        with self.assertRaises(ValueError):append_module(append_module(manifest()))

    def test_intro_handoff_uses_guest_notification_not_host_timer(self):
        source=(Path(__file__).resolve().parents[1]/"tools/native/metro_aot_boot.hpp").read_text()
        self.assertIn("GetByAddress(metro_intro::kInitialUpdateEvent)",source)
        self.assertIn("ready->manual_reset.load",source)
        self.assertIn("ready->Query(nullptr,&signaled)",source)
        self.assertIn("CreateTaskThread(metro_intro::kControl,0)",source)
        self.assertIn("metro_intro::kControlFlagB",source)
        self.assertIn("GetObjectWaiter().WaitHostObject(",source)
        self.assertIn("intro_control_completion.get(),std::chrono::milliseconds::max()",source)
        self.assertNotIn("intro_control_state.wait",source)
        self.assertNotIn("intro_frames>=",source)
        self.assertNotIn("intro_visible",source)
        self.assertNotIn("CreateTaskThread(metro_intro::kControl,1)",source)
        self.assertIn("compare_exchange_strong(idle,4",source)
        capture=(Path(__file__).resolve().parents[1]/"tools/capture_metro_intro.sh").read_text()
        self.assertIn("METRO_INTRO original_initial_update_event signaled",capture)
        self.assertIn("METRO_INTRO pass control_return argument=0 flag_b=1",capture)
        self.assertIn("events!=sorted(set(events))",capture)

    def test_original_intro_phase_probe_coverage(self):
        from instrument_metro_intro import POINTS,insert
        body="DEFINE_REX_FUNC(sub_9800EA10) {\n"+''.join(f"    // METRO_GUEST_PC {pc:08X}\n" for pc in POINTS)+"}\n"
        changed,hits=insert(body)
        self.assertEqual(set(hits),set(POINTS))
        self.assertEqual(changed.count("unsigned metro_intro_object=0;"),1)
        self.assertEqual(changed.count("metro_intro_object=ctx.r3.u32;"),1)
        self.assertNotIn("mem->Store",changed)
        with self.assertRaises(ValueError):insert(body.replace("sub_9800EA10","sub_98000000"))

    def test_optimization_targets_only_original_animation(self):
        from stage_metro_intro import optimized_scaffold
        old="rexglue_project(dash_17559)\nrexglue_setup_target(dash_17559)\n"
        new=optimized_scaffold(old)
        self.assertTrue(new.startswith(old))
        self.assertEqual(optimized_scaffold(new),new)
        self.assertIn("generated_bootanim",new)
        self.assertIn("target_compile_options(${_metro_bootanim_targets} PRIVATE",new)
        self.assertIn(":-O2>",new)
        with self.assertRaises(ValueError):optimized_scaffold("wrong target")

    def test_software_capture_display_mode_not_runtime_policy(self):
        root=Path(__file__).resolve().parents[1]
        capture=(root/"tools/capture_metro_intro.sh").read_text()
        self.assertIn('--ui.video_mode_width="$mode_width"',capture)
        self.assertIn('--ui.video_mode_height="$mode_height"',capture)
        self.assertIn('requested_guest_mode=',capture)
        workflow=(root/".github/workflows/aot-fixed-imports.yml").read_text()
        self.assertIn("METRO_CAPTURE_WIDTH=640 METRO_CAPTURE_HEIGHT=480",workflow)
