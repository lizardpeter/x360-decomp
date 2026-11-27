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
if __name__=="__main__":unittest.main()
