import sys
import unittest
from pathlib import Path
from collections import defaultdict
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_ui_font_graph import forward
class Graph(unittest.TestCase):
    def test_depth_and_cycle(self):
        edges=defaultdict(set,{1:{(2,4,True)},2:{(1,8,True),(3,12,True)},3:{(4,16,True)}})
        self.assertEqual(forward({1},edges,depth=2),({1:0,2:1,3:2},False))
    def test_limit(self):
        edges=defaultdict(set,{1:{(2,4,True),(3,8,True)}})
        self.assertEqual(forward({1},edges,limit=2),({1:0,2:1},True))
