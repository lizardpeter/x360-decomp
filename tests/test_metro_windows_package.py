import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from package_metro_windows import pe_identity,binary_files,REQUIRED,PROFILE_DLLS,LAUNCH,package

def pe(path,machine=0x8664,magic=0x20b,dll=False):
    data=bytearray(128);data[:2]=b"MZ"
    struct.pack_into("<I",data,60,64)
    data[64:68]=b"PE\0\0"
    struct.pack_into("<H",data,68,machine)
    struct.pack_into("<H",data,86,0x2000 if dll else 0x2)
    struct.pack_into("<H",data,88,magic)
    path.write_bytes(data)
class TestWindowsPackage(unittest.TestCase):
    def test_architecture(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)/"dash_17559.exe";pe(p)
            self.assertEqual(pe_identity(p)["machine"],"AMD64")
            pe(p,0x14c,0x10b)
            with self.assertRaises(ValueError):pe_identity(p)
            pe(p,dll=True)
            with self.assertRaises(ValueError):pe_identity(p)
    def test_native_module_census(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in REQUIRED:pe(root/name,dll=name.endswith(".dll"))
            (root/"dash.xex").write_bytes(b"original")
            self.assertEqual({p.name for p in binary_files(root)},REQUIRED)
            (root/"dash_17559_bootanim.dll").unlink()
            with self.assertRaises(ValueError):binary_files(root)
    def test_launcher_modes(self):
        self.assertIn("X360_METRO_BOOT=1",LAUNCH)
        self.assertIn("X360_METRO_INTRO=1",LAUNCH)
        self.assertIn(":preflight",LAUNCH)
        self.assertIn("inputs\\bootanim.xex",LAUNCH)

    def test_profile_module_census_is_all_or_nothing(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for name in REQUIRED:pe(root/name,dll=name.endswith(".dll"))
            with self.assertRaisesRegex(ValueError,"missing original profile DLLs"):
                binary_files(root,True)
            for name in PROFILE_DLLS:pe(root/name,dll=True)
            self.assertEqual({p.name for p in binary_files(root,True)},REQUIRED|PROFILE_DLLS)
            with self.assertRaisesRegex(ValueError,"unexpected original profile DLLs"):
                binary_files(root)
            (root/next(iter(PROFILE_DLLS))).unlink()
            with self.assertRaises(ValueError):binary_files(root,True)

    def test_diagnostic_mode_is_separate_from_normal_boot(self):
        self.assertIn('if /i "%~1"=="guide" goto guide',LAUNCH)
        self.assertIn(":guide\nset X360_METRO_GUIDE_UI=1\nset X360_METRO_GUIDE_TRACE=1\nset X360_METRO_PROFILE_TRACE=1",LAUNCH)
        self.assertIn("--hid.mnk_mode=true --hid.guide_button=true --hid.keybind_guide=F9",LAUNCH)
        self.assertIn("set METRO_GUIDE_ARGS=\n",LAUNCH)
        self.assertIn("%METRO_GUIDE_ARGS% --log.level",LAUNCH)
        self.assertIn(":profilepreflight\nset X360_METRO_PROFILE_MODULE_PREFLIGHT=1",LAUNCH)
        self.assertIn("goto boot\n:guide",LAUNCH)
        self.assertNotIn("set X360_METRO_LOCAL_PROFILES=1",LAUNCH)
