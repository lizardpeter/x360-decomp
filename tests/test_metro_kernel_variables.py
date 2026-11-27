import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_kernel_variables import entries,header
class KernelVariables(unittest.TestCase):
    def test_inventory(self):
        self.assertEqual(len(entries("dash_17559")),16)
        self.assertEqual(len(entries("xam_17559")),20)
        self.assertIn("0x02DCu, 0x815F07C4u",header())
        self.assertIn("0x02F1u, 0x815F05CCu",header())
        self.assertIn("std::array<KernelVariableBinding,16>",header())
if __name__=="__main__":unittest.main()
