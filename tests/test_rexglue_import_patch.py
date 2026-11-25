import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from patch_rexglue_imports import corrected,OLD,NEW

class PatchTests(unittest.TestCase):
    def test_exact_scoped_replacement(self):
        s=OLD+"\n    if (size < kLibraryHeaderSize || u64{offset} + size > total ||\n    offset += size;\n"
        self.assertEqual(corrected(s),s.replace(OLD,NEW))
        with self.assertRaises(ValueError):corrected(NEW)
        with self.assertRaises(ValueError):corrected(s+s)
        with self.assertRaises(ValueError):corrected(OLD)
if __name__=="__main__":unittest.main()
