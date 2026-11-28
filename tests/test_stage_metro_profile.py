import sys
import struct
import tempfile
import unittest
from unittest import mock
import os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_profile import inspect_header,stage,MIN_HEADER,MAX_BYTES
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
    def test_native_snapshot_capacity(self):
        self.assertEqual(MAX_BYTES,64*1024*1024)
        inspect_header(fixture(),MAX_BYTES)
        with self.assertRaises(ValueError):inspect_header(fixture(),MAX_BYTES+1)

    def test_reject_links(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage";dest.mkdir()
            (dest/"Content").symlink_to(root,target_is_directory=True)
            with self.assertRaises(ValueError):stage(src,dest)

    def test_publication_is_complete_and_exclusive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage"
            target=dest/"Content"/NAME/"FFFE07D1"/"00010000"/NAME
            real_link=os.link
            def check_complete(source,destination):
                self.assertFalse(target.exists())
                self.assertEqual(Path(source).read_bytes(),fixture())
                self.assertEqual(Path(destination),target)
                real_link(source,destination)
            with mock.patch("stage_metro_profile.os.link",side_effect=check_complete):
                self.assertEqual(stage(src,dest),len(fixture()))
            self.assertEqual(list(target.parent.iterdir()),[target])
            self.assertEqual(src.read_bytes(),fixture())
    def test_publish_failure_never_exposes_partial_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage"
            with mock.patch("stage_metro_profile.os.link",side_effect=OSError("unsupported filesystem")):
                with self.assertRaises(OSError):stage(src,dest)
            target=dest/"Content"/NAME/"FFFE07D1"/"00010000"/NAME
            self.assertFalse(target.exists())
            self.assertEqual(list(target.parent.iterdir()),[])
    def test_concurrent_publication_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);src=root/NAME;src.write_bytes(fixture())
            dest=root/"storage"
            target=dest/"Content"/NAME/"FFFE07D1"/"00010000"/NAME
            def concurrent(source,destination):
                target.write_bytes(b"existing profile")
                raise FileExistsError()
            with mock.patch("stage_metro_profile.os.link",side_effect=concurrent):
                with self.assertRaises(FileExistsError):stage(src,dest)
            self.assertEqual(target.read_bytes(),b"existing profile")
            self.assertEqual(list(target.parent.iterdir()),[target])
