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
