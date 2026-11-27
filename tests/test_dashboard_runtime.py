import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_dashboard_runtime import put, verify_members, acquire_font_complements
from hashlib import sha256

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
    def test_font_acquisition_requires_exact_hash(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            source=root/"source"
            source.write_bytes(b"synthetic")
            spec={"name":"test.xtt","key":"test/test.xtt","bytes":9,
                  "sha256":sha256(b"synthetic").hexdigest()}
            cfg={"local_resource":[spec],"r2_public":"unused"}
            def acquire_stub(item, output, origin):
                self.assertEqual(item["id"],"test.xtt")
                return source
            dest=root/"fonts"
            acquire_font_complements(dest,cfg,acquire_stub)
            self.assertEqual((dest/"test.xtt").read_bytes(),b"synthetic")
            source.write_bytes(b"different")
            with self.assertRaises(ValueError):acquire_font_complements(dest,cfg,acquire_stub)
if __name__=="__main__":unittest.main()
