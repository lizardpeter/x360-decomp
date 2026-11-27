import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_audio_buffer_evidence import GLOBAL,add,scaled_cpu,local_accesses

def dform(op,rt,ra,d):
    return (op<<26)|(rt<<21)|(ra<<16)|(d&0xffff)
def xform(rt,ra,rb,xo):
    return (31<<26)|(rt<<21)|(ra<<16)|(rb<<11)|(xo<<1)
def rlwinm(rs,ra,sh,mb,me):
    return (21<<26)|(rs<<21)|(ra<<16)|(sh<<11)|(mb<<6)|(me<<1)

class AudioBufferEvidenceTests(unittest.TestCase):
    def test_cpu_expression(self):
        self.assertEqual(scaled_cpu((None,0,1),3,0,28),(None,0,8))
        self.assertIsNone(scaled_cpu((None,0,1),3,30,31))
        self.assertIsNone(add(("arg3",0,0),("arg4",0,0)))
    def test_exact_pair_pointer(self):
        code=[dform(15,11,0,0x81b6),dform(32,10,11,-18972),
              dform(34,6,13,268),rlwinm(6,11,3,0,28),
              xform(11,11,10,266),dform(32,11,11,12),
              dform(36,3,10,16)]
        rows=local_accesses(code,0x819affc0)
        self.assertEqual(rows[0]["address"],{"object":None,"constant":f"{GLOBAL:08X}","processor_multiplier":0})
        self.assertEqual(rows[1]["address"]["object"],"audio_global_object")
        self.assertEqual(rows[1]["address"]["processor_multiplier"],8)
        self.assertEqual(rows[2]["access"],"memory_store")
        self.assertEqual(rows[2]["address"]["constant"],"00000010")
    def test_branch_clears_unproven_register(self):
        code=[dform(15,11,0,0x81b6),0x48000008,0x60000000,dform(32,10,11,-18972)]
        self.assertFalse(local_accesses(code,0x819a0000))
