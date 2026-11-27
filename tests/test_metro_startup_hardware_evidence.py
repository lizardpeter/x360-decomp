import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_startup_hardware_evidence import continuation

class StartupHardwareEvidenceTests(unittest.TestCase):
    def test_result_read(self):
        self.assertEqual(continuation([{"pc":"00000001","kind":"memory_load","base":3,"writes":9}])["kind"],"reads_result")
        self.assertEqual(continuation([{"pc":"00000002","kind":"compare_immediate","register":3}])["kind"],"reads_result")
        self.assertEqual(continuation([{"pc":"00000003","kind":"register_copy","source":3,"writes":5}])["kind"],"reads_result")
    def test_overwritten_result(self):
        self.assertEqual(continuation([{"pc":"00000004","kind":"immediate","writes":3}])["kind"],"overwrites_result")
        self.assertEqual(continuation([{"pc":"00000005","kind":"register_offset","base":3,"writes":3}])["kind"],"reads_result")
    def test_unproven_result(self):
        self.assertEqual(continuation([{"pc":"00000006","kind":"unclassified"},{"pc":"00000007","kind":"immediate","writes":3}])["kind"],"control_or_unknown")
        self.assertEqual(continuation([])["kind"],"not_proven")
