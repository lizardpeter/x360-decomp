import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_heap_scalar import evaluate,ppc_mask,rotate

class MetroHeapScalarTests(unittest.TestCase):
    def test_wrapping_ppc_mask(self):
        self.assertEqual(ppc_mask(0,31),0xffffffff)
        self.assertEqual(ppc_mask(14,12),0xfffbffff)
        self.assertEqual(ppc_mask(31,31),1)
        self.assertEqual(rotate(0x80000001,1),3)

    def test_signed_condition_and_branch(self):
        # li r3,-1; cmpwi cr0,r3,0; blt +8; li r3,7; blr.
        words=[0x3860ffff,0x2c030000,0x41800008,0x38600007,0x4e800020]
        r=evaluate(lambda pc:words[pc//4],0,set(),{})
        self.assertEqual(r["registers"][3],0xffffffff)
        self.assertNotIn(12,r["path"])

    def test_assumed_calls_clobber_volatile_registers(self):
        # li r4,1; bl +12; or r3,r4,r4; blr.
        words=[0x38800001,0x4800000d,0x7c832378,0x4e800020]
        with self.assertRaises(ValueError):evaluate(lambda pc:words[pc//4],0,set(),{}, {16:3})
        with self.assertRaises(ValueError):evaluate(lambda pc:words[pc//4],0,set(),{})

    def test_logical_immediate(self):
        # lis r3,0x1; oris r3,r3,0x8000; ori r3,r3,15; blr.
        words=[0x3c600001,0x64638000,0x6063000f,0x4e800020]
        r=evaluate(lambda pc:words[pc//4],0,set(),{})
        self.assertEqual(r["registers"][3],0x8001000f)

if __name__=="__main__":unittest.main()
