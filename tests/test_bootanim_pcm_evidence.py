import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from bootanim_pcm_evidence import analyze,RATE,CHANNELS

class TestPCM(unittest.TestCase):
    def test_silence(self):
        d=analyze(bytes(RATE*CHANNELS*4),0)
        self.assertTrue(d["baseline_silent"])
        self.assertFalse(d["non_silent_output"])
    def test_actual_non_silent_activity(self):
        silence=bytes(RATE*CHANNELS*4)
        signal=struct.pack("<ff",.125,-.125)*(RATE//2)
        d=analyze(silence+signal,0)
        self.assertTrue(d["baseline_silent"])
        self.assertTrue(d["non_silent_output"])
        self.assertEqual(d["active_windows"],5)
        self.assertEqual(d["first_active_seconds"],1)
        self.assertFalse(d["audible_fidelity_verified"])
    def test_reject_click_and_invalid_samples(self):
        d=analyze(bytes(RATE*CHANNELS*4)+struct.pack("<ff",1.,1.),0)
        self.assertFalse(d["non_silent_output"])
        self.assertFalse(analyze(struct.pack("<ff",float("nan"),0),1)["finite_samples"])
        with self.assertRaises(ValueError):analyze(b"x",0)
