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
        self.assertIn("--hid.mnk_mode=true",LAUNCH)
        self.assertIn("--hid.guide_button=true --hid.keybind_guide=F9",LAUNCH)
        self.assertIn("set X360_METRO_GUIDE_UI=\n",LAUNCH)
        self.assertIn("%METRO_INPUT_ARGS% --log.level",LAUNCH)
        self.assertIn(":profilepreflight\nset X360_METRO_PROFILE_MODULE_PREFLIGHT=1",LAUNCH)
        self.assertIn("goto boot\n:guide",LAUNCH)
        self.assertNotIn("set X360_METRO_LOCAL_PROFILES=1",LAUNCH)

    def test_desktop_navigation_binds_apply_to_every_boot_mode(self):
        line=next(x for x in LAUNCH.splitlines() if x.startswith('set "METRO_INPUT_ARGS='))
        binds=dict(x.split("=",1) for x in line.split("=",1)[1].rstrip('"').split())
        self.assertEqual(binds["--hid.mnk_mode"],"true")
        self.assertEqual(binds["--hid.mnk_mouse"],"false")
        self.assertEqual(binds["--hid.mnk_passthrough"],"false")
        self.assertEqual(binds["--hid.keybind_a"],"Space,Return")
        self.assertEqual(binds["--hid.keybind_b"],"Escape,Backspace")
        for direction,key in zip(("up","down","left","right"),"WSAD"):
            self.assertIn(key,binds["--hid.keybind_dpad_"+direction].split(","))
            self.assertNotEqual(binds["--hid.keybind_lstick_"+direction],key)
        keys=[key for name,value in binds.items() if name.startswith("--hid.keybind_") for key in value.split(",")]
        self.assertEqual(len(keys),len(set(keys)))
        self.assertLess(LAUNCH.index('set "METRO_INPUT_ARGS='),LAUNCH.index('goto guide'))

    def test_guest_video_mode_and_hd_diagnostics_are_independent(self):
        self.assertIn('set "METRO_VIDEO_ARGS=--ui.video_mode_width=1280 --ui.video_mode_height=720"', LAUNCH)
        self.assertIn('set "METRO_SCALE_ARGS="', LAUNCH)
        self.assertIn('if /i "%~1"=="hd" (\n    set "METRO_SCALE_ARGS=--gpu.resolution_scale_x=2 --gpu.resolution_scale_y=2"\n    set "METRO_LOG=metro-hd.log"\n)', LAUNCH)
        self.assertIn('if /i "%~1"=="1080p" (\n    set "METRO_VIDEO_ARGS=--ui.video_mode_width=1920 --ui.video_mode_height=1080"\n    set "METRO_LOG=metro-1080p.log"\n)', LAUNCH)
        self.assertIn('%METRO_VIDEO_ARGS% %METRO_SCALE_ARGS% %METRO_INPUT_ARGS%', LAUNCH)
        self.assertIn('> "%METRO_LOG%" 2>&1', LAUNCH)
