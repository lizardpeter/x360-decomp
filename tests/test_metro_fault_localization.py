import sys
import struct
import tempfile
import unittest
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from symbolize_metro_crash import executable_segments,virtual_address,guest_pc,choose_file
from patch_metro_guest_pc import OLD,NEW,corrected

class FaultLocalization(unittest.TestCase):
    def test_file_offset_is_not_virtual_address(self):
        # Deliberately nonidentity ELF executable mapping.
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"fixture.so"
            data=bytearray(0x2000)
            data[:6]=b"\x7fELF\x02\x01"
            struct.pack_into("<Q",data,32,64)
            struct.pack_into("<HH",data,54,56,2)
            struct.pack_into("<II6Q",data,64,1,4,0,0,0,0x1000,0x1000,0x1000)
            struct.pack_into("<II6Q",data,120,1,5,0x1000,0x3000,0,0x1000,0x1000,0x1000)
            p.write_bytes(data)
            segments=executable_segments(p)
            self.assertEqual(segments,[(0x1000,0x3000,0x1000)])
            self.assertEqual(virtual_address(segments,0x1123),0x3123)
            for invalid in (0,0xfff,0x2000):
                with self.assertRaises(ValueError):virtual_address(segments,invalid)
    def test_source_marker_ownership(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"generated_xam"/"test.cpp"
            p.parent.mkdir()
            p.write_text("DEFINE_REX_FUNC(sub_81671250) {\n"
                         "\tREX_FUNC_PROLOGUE();\n"
                         "\t// METRO_GUEST_PC 81671250\n"
                         "\t// original instruction\n"
                         "\tstatement();\n}\n"
                         "DEFINE_REX_FUNC(sub_816712C4) {\n"
                         "\tREX_FUNC_PROLOGUE();\n}\n")
            self.assertEqual(guest_pc(f"{p}:5","sub_81671250"),0x81671250)
            self.assertIsNone(guest_pc(f"{p}:5","sub_816712C4"))
            self.assertIsNone(guest_pc(f"{p}:8","sub_816712C4"))
    def test_identical_install_and_build_copies(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            a=root/"build"/"libtest.so"; b=root/"install"/"libtest.so"
            for p in (a,b):
                p.parent.mkdir();p.write_bytes(b"same")
            self.assertEqual(choose_file("libtest.so",[a.parent,b.parent]),a)
            b.write_bytes(b"different")
            with self.assertRaises(ValueError):choose_file("libtest.so",[a.parent,b.parent])
    def test_codegen_marker(self):
        self.assertEqual(corrected(OLD),NEW)
        with self.assertRaises(ValueError):corrected(NEW)
    def test_capture_syntax_and_unique_probe(self):
        path=ROOT/"tools/capture_metro_boot.sh"
        subprocess.run(["bash","-n",str(path)],check=True)
        source=path.read_text()
        self.assertEqual(source.count("for axis in vertical horizontal; do"),1)
        self.assertEqual(source.count('for key in "$first" "$second"; do'),1)
        self.assertIn("first=s; second=w",source)
        self.assertIn("--hid.keybind_dpad_up=W,Up,Shift+Up",source)
        self.assertIn("--hid.keybind_dpad_down=S,Down,Shift+Down",source)
        self.assertNotIn("xdotool keydown Shift_L",source)
        self.assertIn("first=Right; second=Left",source)
        self.assertEqual(source.count("navigation_visually_verified=false"),1)
        self.assertIn('if [ "$samples" -ne 4 ]',source)
        self.assertIn("if ((pad_observed!=4)); then",source)
        self.assertIn("if ((reversible_pairs<1)); then",source)
        self.assertIn("changed>threshold && motion<=threshold && restored<=threshold",source)
        self.assertIn("if ((streak>=2)); then break; fi",source)
        self.assertIn("for sample in $(seq 1 8); do",source)
if __name__=="__main__":unittest.main()
