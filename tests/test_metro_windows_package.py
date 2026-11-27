import struct
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from package_metro_windows import pe_identity,binary_files,REQUIRED,LAUNCH

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
