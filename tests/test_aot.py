import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_recompilation as prep
from aot_receipt import receipt

class AotTests(unittest.TestCase):
    def test_manifests(self):
        for name in prep.EXPECTED:
            m = tomllib.loads(prep.manifest_text(name))
            self.assertEqual(m["project"]["name"], name)
            self.assertEqual(m["project"]["sdk_version"], "0.11.0")
            self.assertEqual(m["entrypoint"]["out_directory_path"], "generated")
        with self.assertRaises(ValueError):
            prep.manifest_text("../other")

    def test_stage(self):
        data = b"synthetic original"
        with tempfile.TemporaryDirectory() as d, patch.dict(prep.EXPECTED, {"dash_17559": prep.sha(data)}):
            path = Path(d)
            with self.assertRaises(ValueError):
                prep.prepare(path, "dash_17559", b"wrong")
            r = prep.prepare(path, "dash_17559", data)
            self.assertEqual(r["bytes"], len(data))
            self.assertEqual(prep.prepare(path, "dash_17559", data), r)
            target = path / "dash_17559" / "inputs" / "dash.xex"
            self.assertEqual(target.read_bytes(), data)
            target.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                prep.prepare(path, "dash_17559", data)

    def test_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertFalse(receipt(root, 0)["codegen_success"])
            (root/"sample.cpp").write_text("int x;")
            self.assertFalse(receipt(root, 1)["codegen_success"])
            r = receipt(root, 0)
            self.assertTrue(r["codegen_success"])
            self.assertEqual(r["cpp_files"], 1)
            self.assertEqual(r["generated_bytes"], 6)

if __name__ == "__main__":
    unittest.main()
