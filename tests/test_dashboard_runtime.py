import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_dashboard_runtime import put, verify_members

class RuntimeTests(unittest.TestCase):
    def test_idempotent_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            a=put(root,"system/sample.xex",b"synthetic")
            self.assertEqual(put(root,"system/sample.xex",b"synthetic"),a)
            with self.assertRaises(ValueError):put(root,"system/sample.xex",b"different")
            with self.assertRaises(ValueError):put(root,"../escape.xex",b"synthetic")
    def test_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"real").mkdir()
            (root/"system").symlink_to(root/"real",target_is_directory=True)
            with self.assertRaises(ValueError):put(root,"system/sample.xex",b"synthetic")
    def test_census_mismatch(self):
        with self.assertRaises(ValueError):verify_members({"a":{"bytes":1,"payload":b"a"}},{"a":{"bytes":2}})
if __name__=="__main__":unittest.main()
