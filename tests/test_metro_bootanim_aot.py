import sys
import tomllib
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_bootanim_aot import MANIFEST,CMAKE,EXPORTS,hints

class BootanimAOT(unittest.TestCase):
    def test_entryless_native_module(self):
        data=tomllib.loads(MANIFEST)
        self.assertTrue(data["entrypoint"]["is_dll"])
        self.assertEqual(data["entrypoint"]["file_path"],"inputs/bootanim.xex")
        functions=tomllib.loads(hints({"functions":[]}))["functions"]
        self.assertEqual({int(a,16) for a in functions},set(EXPORTS.values()))
        self.assertNotIn(0x98000000,EXPORTS.values())
        self.assertIn("add_library(metro_bootanim_module SHARED",CMAKE)
        self.assertIn("add_executable(metro_bootanim_live",CMAKE)
        self.assertIn("target_compile_options(metro_bootanim_module PRIVATE",CMAKE)
        self.assertIn(":-O2>",CMAKE)
    def test_isolated_graceful_control_matches_integrated_policy(self):
        root=Path(__file__).resolve().parents[1]
        source=(root/"tools/native/metro_bootanim_live.cpp").read_text()
        capture=(root/"tools/capture_bootanim_live.sh").read_text()
        self.assertIn("GetByAddress(kInitialUpdateEvent)",source)
        self.assertIn("CreateTaskThread(kControl,0)",source)
        self.assertNotIn("frames>=",source)
        self.assertNotIn("110u",source)
        self.assertNotIn("165u",source)
        self.assertIn("X360_BOOTANIM_CONTROL=graceful_event",capture)
        self.assertIn("original_initial_update_event signaled",capture)
        self.assertIn("control_return argument=0",capture)
if __name__=="__main__":unittest.main()
