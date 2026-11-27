import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_stfs_abi_evidence import flow,value,merge,transfer,successors,render

class StfsABI(unittest.TestCase):
    def test_stack_frame_and_unknown_call(self):
        # stwu r1,-112(r1); addi r3,r1,80; li r4,88; bl next
        words=[0x9421ff90,0x38610050,0x38800058,0x48000005,0x4e800020]
        graph,states=flow(words,0x1000)
        self.assertEqual(states[0x100c][0][1],value("stack",-112))
        self.assertEqual(states[0x100c][0][3],value("stack",-32))
        self.assertEqual(states[0x100c][0][4],value("const",88))
        self.assertEqual(states[0x1010][0][3],value("return",0x100c,0x1010))
        self.assertNotIn(4,states[0x1010][0])
        self.assertEqual(states[0x1010][0][1],value("stack",-112))
    def test_conflicting_control_flow_drops_fact(self):
        # li r4,1; beq +8; li r4,2; blr
        graph,states=flow([0x38800001,0x41820008,0x38800002,0x4e800020],0x1000)
        self.assertNotIn(4,states[0x100c][0])
        self.assertEqual(states[0x100c][0][1],value("stack",0))
    def test_stack_store_and_load(self):
        # li r4,9; stw r4,80(r1); lwz r5,80(r1); blr
        _,states=flow([0x38800009,0x90810050,0x80a10050,0x4e800020],0x1000)
        self.assertEqual(states[0x100c][0][5],value("const",9))
    def test_unknown_write_does_not_create_a_fact(self):
        regs={1:value("stack",0),3:value("const",88)}
        new,_=transfer((regs,{}),0x1000,0xffffffff)
        self.assertNotIn(3,new)
    def test_constant_or_high_and_signed_offsets(self):
        _,states=flow([0x3c600007,0x60634004,0x4e800020],0x1000)
        self.assertEqual(render(states[0x1008][0][3]),{"kind":"const","value":0x74004})
