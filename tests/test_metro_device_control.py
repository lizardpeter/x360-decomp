import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from patch_metro_device_control import OLD, NEW, corrected

class DeviceControlPatch(unittest.TestCase):
    def test_exact_branch_and_failure(self):
        source = "geometry and partition branches\n" + OLD + "\ncompletion"
        updated = corrected(source)
        self.assertEqual(updated, source.replace(OLD, NEW))
        specific = updated.split("io_control_code == 0x4D028", 1)[1].split("} else {", 1)[0]
        self.assertIn("X_STATUS_NOT_SUPPORTED", specific)
        self.assertNotIn("X_STATUS_SUCCESS", specific)
        self.assertNotIn("REX_ASSERT_ALWAYS()", specific)
        self.assertIn(OLD, updated)
        self.assertIn("GetAbsolutePath()", specific)
    def test_rejects_drift_and_reapplication(self):
        for bad in ("", OLD+OLD, NEW):
            with self.assertRaises(ValueError):
                corrected(bad)

if __name__ == "__main__":
    unittest.main()
