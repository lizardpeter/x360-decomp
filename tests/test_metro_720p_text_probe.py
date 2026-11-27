import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_720p_text_probe import analyze,runs,WIDTH,HEIGHT,REGIONS,EXPECTED

class TestMetro720pTextProbe(unittest.TestCase):
    def frame(self,missing):
        data=bytearray([90])*(WIDTH*HEIGHT)
        for label,(left,right) in REGIONS.items():
            count=EXPECTED[label]-(1 if missing and label=="movies" else 0)
            for i in range(count):
                x=left+i*12
                for y in range(130,151):
                    data[y*WIDTH+x:y*WIDTH+x+5]=bytes([220 if label=="home" else 130])*5
        return data
    def test_projection_runs(self):
        self.assertEqual(runs([1,2,4,8,9]),[[1,3],[4,5],[8,10]])
    def test_missing_terminal_candidate(self):
        self.assertEqual(analyze(self.frame(True))["status"],"suspected_missing_terminal_glyph")
    def test_complete_candidate_not_visual_proof(self):
        r=analyze(self.frame(False))
        self.assertEqual(r["status"],"nine_separate_ink_runs")
        self.assertFalse(r["visually_verified"])
    def test_unknown_scene(self):
        self.assertEqual(analyze(bytearray(WIDTH*HEIGHT))["status"],"unclassified")
