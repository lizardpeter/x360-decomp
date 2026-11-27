import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from instrument_metro_heap import insert, instrument, REQUIRED

class MetroHeapProbeTests(unittest.TestCase):
    def test_only_exact_markers(self):
        s="void f() {\n  // METRO_GUEST_PC 816A17D0\n  original_instruction();\n  // METRO_GUEST_PC 12345678\n  next_instruction();\n}\n"
        patched,hits=insert(s)
        self.assertEqual(hits,{0x816A17D0:1})
        self.assertIn("stage=system_object_allocation",patched)
        self.assertIn("ctx.r3.u32",patched)
        self.assertIn("original_instruction();\n",patched)
        self.assertIn("// METRO_GUEST_PC 12345678\n  next_instruction();",patched)
        self.assertNotIn("stage=12345678",patched)
        with self.assertRaises(ValueError):insert(patched)

    def test_missing_required_sites_leaves_sources_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/"generated_xam"; directory.mkdir()
            path=directory/"code.cpp"
            source="// METRO_GUEST_PC 816A17D0\n"
            path.write_text(source)
            with self.assertRaises(ValueError):instrument(directory)
            self.assertEqual(path.read_text(),source)

    def test_complete_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/"generated_xam"; directory.mkdir()
            (directory/"code.cpp").write_text("".join(f"// METRO_GUEST_PC {pc:08X}\n" for pc in REQUIRED))
            r=instrument(directory)
            self.assertEqual(r["instrumented_translation_units"],1)
            self.assertEqual(sum(x["occurrences"] for x in r["probes"]),len(REQUIRED))

if __name__=="__main__":unittest.main()
