import sys
import tomllib
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_xam_aot import BINDINGS, OLD, NEW, corrected, manifest, verify_bindings, verify_catalog, rows, ROOT

class MetroXamTests(unittest.TestCase):
    def test_original_metadata(self):
        verify_bindings(rows(ROOT/"analysis/dash_17559/imports.tsv"), rows(ROOT/"analysis/xam_17559/exports.tsv"))

    def test_bad_binding_fails(self):
        imports = rows(ROOT/"analysis/dash_17559/imports.tsv")
        exports = rows(ROOT/"analysis/xam_17559/exports.tsv")
        with self.assertRaises(ValueError):
            verify_bindings(imports, exports[:-1] if not exports else [])
        with self.assertRaises(ValueError):
            verify_bindings([], exports)

    def test_patch_scope(self):
        source = "state.module_imports[sym.address] = {lib_name, ordinal};\n" + OLD
        self.assertEqual(corrected(source), source.replace(OLD, NEW))
        for ordinal, (thunk, _) in BINDINGS.items():
            self.assertIn(f"ordinal == 0x{ordinal:04X} && sym.address == 0x{thunk:08X}", NEW)
        self.assertIn('binary.GetBaseAddress() == 0x92000000', NEW)
        self.assertIn('lib_name == "xam"', NEW)
        for bad in (OLD, source + source, NEW):
            with self.assertRaises(ValueError):
                corrected(bad)
        verify_catalog("REX_EXPORT(xam, 0x0000054A, Other, kFunction),")
        with self.assertRaises(ValueError):
            verify_catalog("REX_EXPORT(xam, 0x00000546, Found, kFunction),")

    def test_manifest(self):
        m = tomllib.loads(manifest())
        self.assertEqual(m["entrypoint"]["includes"], ["verified-entries.toml"])
        self.assertEqual(m["modules"][0]["guest_path"], "xam.xex")
        self.assertTrue(m["modules"][0]["is_dll"])
        self.assertNotEqual(m["entrypoint"]["out_directory_path"], m["modules"][0]["out_directory_path"])

if __name__ == "__main__":
    unittest.main()
