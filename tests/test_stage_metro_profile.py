import sys
import struct
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_profile import inspect_header,stage,MIN_HEADER
NAME="E000000000000001"
def fixture():
    d=bytearray(0xC000)
    d[:4]=b"CON "
    struct.pack_into(">III",d,0x340,0xA000,0x10000,2)
    struct.pack_into(">I",d,0x360,0xFFFE07D1)
    struct.pack_into(">Q",d,0x371,int(NAME,16))
    d[0x379]=0x24
    return bytes(d)
class LocalProfile(unittest.TestCase):
    def test_exact_copy_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage"
            self.assertEqual(stage(src,dest),len(fixture()))
            target=dest/"Content"/NAME/"FFFE07D1"/"00010000"/NAME
            self.assertEqual(target.read_bytes(),src.read_bytes())
            with self.assertRaises(FileExistsError):stage(src,dest)
            self.assertEqual(src.read_bytes(),fixture())
    def test_reject_wrong_content_header_and_name(self):
        for off in (0,0x344,0x360,0x379,0x3A9):
            d=bytearray(fixture());d[off]^=0xff
            with self.assertRaises(ValueError):inspect_header(d,len(d))
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/"E000000000000002";src.write_bytes(fixture())
            with self.assertRaises(ValueError):stage(src,root/"storage")
    def test_reject_links(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage";dest.mkdir()
            (dest/"Content").symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):stage(src,dest)
