import copy
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_preflight import BINDINGS, VALUE_SLOTS, ROOT, OLD, NEW, header, cmake_preflight

class MetroPreflightTests(unittest.TestCase):
    def setUp(self):
        self.dash, self.xam = (json.loads((ROOT/"analysis"/m/"decoded.json").read_text())
                               for m in ("dash_17559", "xam_17559"))

    def test_exact_verified_header(self):
        result = header(self.dash, self.xam)
        self.assertIn("kDashBase = 0x92000000u", result)
        self.assertIn("kXamBase = 0x815F0000u", result)
        self.assertIn("kXamDataBinding = {0x03DBu, 0x9293D11Cu, 0x81A87F20u, 0x92000550u};", result)
        for ordinal, (thunk, target) in BINDINGS.items():
            self.assertIn(f"{{0x{ordinal:04X}u, 0x{thunk:08X}u, 0x{target:08X}u, 0x{VALUE_SLOTS[ordinal]:08X}u}}", result)

    def test_reject_wrong_identity(self):
        bad = copy.deepcopy(self.xam)
        bad["source_sha256"] = "0"*64
        with self.assertRaises(ValueError):
            header(self.dash, bad)

    def test_reject_nonexecutable_mapping(self):
        bad = copy.deepcopy(self.xam)
        for section in bad["pe"]["sections"]:
            section["flags"] &= ~0x20000000
        with self.assertRaises(ValueError):
            header(self.dash, bad)

    def test_replace_only_known_scaffold(self):
        self.assertEqual(cmake_preflight(OLD), NEW)
        self.assertEqual(cmake_preflight(NEW), NEW)
        for bad in ("", OLD+"\n"+OLD, OLD+"\n"+NEW):
            with self.assertRaises(ValueError):
                cmake_preflight(bad)

if __name__ == "__main__":
    unittest.main()
