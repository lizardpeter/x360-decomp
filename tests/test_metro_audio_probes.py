import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from instrument_metro_audio import insert,instrument,POINTS,REQUIRED,HEADER

class TestAudioProbes(unittest.TestCase):
    def test_original_instruction_preserved(self):
        src="void test() {\n // METRO_GUEST_PC 819A4158\n original_load();\n}\n"
        result,hits=insert(src)
        self.assertEqual(hits,{0x819A4158:1})
        self.assertIn('metro_original_audio_probe("faulting_header_read",0x819A4158u',result)
        self.assertIn(" original_load();",result)
        self.assertIn("GetActiveCPU",HEADER)
        # PPCContext::ctr is a Register union, not an integer-convertible type.
        self.assertIn("ctx.ctr.u32",HEADER)
        self.assertNotIn("static_cast<unsigned>(ctx.ctr)",HEADER)
        self.assertIn("global_object=unmapped",HEADER)
        self.assertNotIn("mem->Store",HEADER)
        self.assertNotIn("TranslateVirtual",HEADER)
        with self.assertRaises(ValueError):insert(result)

    def test_essential_coverage_is_atomic(self):
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)/"generated_xam";folder.mkdir()
            path=folder/"module.cpp"
            first="// METRO_GUEST_PC 819A4158\n"
            path.write_text(first)
            with self.assertRaises(ValueError):instrument(folder)
            self.assertEqual(path.read_text(),first)
            path.write_text("".join(f"// METRO_GUEST_PC {pc:08X}\n" for pc in POINTS))
            result=instrument(folder)
            self.assertEqual(result["covered"],len(POINTS))
            self.assertTrue(REQUIRED<=set(POINTS))
