import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from instrument_metro_ui import insert,probes,MARK

class MetroUIProbes(unittest.TestCase):
    def test_call_and_return(self):
        points=probes("generated_hud")
        self.assertEqual(points[0x913E9960],("hud_xui_init","call"))
        self.assertEqual(points[0x913E9964],("hud_xui_init","return"))
        source="  // METRO_GUEST_PC 913E9960\n  original_call();\n  // METRO_GUEST_PC 913E9964\n  original_next();\n"
        out,hits=insert(source,points)
        self.assertEqual(sum(hits.values()),2)
        self.assertLess(out.index("phase=call"),out.index("original_call();"))
        self.assertLess(out.index("original_call();"),out.index("phase=return"))
        self.assertLess(out.index("phase=return"),out.index("original_next();"))
        self.assertIn("metro_ui_n<=8",out)
        with self.assertRaises(ValueError):insert(out,points)
    def test_no_matching_marker(self):
        source="// METRO_GUEST_PC 12345678\noriginal();\n"
        self.assertEqual(insert(source,probes("generated"))[0],source)

if __name__=="__main__":unittest.main()
