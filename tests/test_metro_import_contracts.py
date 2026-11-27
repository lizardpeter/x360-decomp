import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_import_contracts import branch, setup, result_use, variable_reference, inspect, reachable, report
import struct

class Contracts(unittest.TestCase):
    def test_branch(self):
        self.assertEqual(branch(0x1000,0x48000011),(0x1010,True))
        self.assertEqual(branch(0x1000,0x4bfffff0),(0xff0,False))
        self.assertIsNone(branch(0,0x4e800020))
    def test_argument_evidence(self):
        self.assertEqual(setup(0x3860ffff),(3,{"kind":"immediate","base":0,"value":-1}))
        self.assertEqual(result_use(0x2c030000),"compare_r3_immediate")
        self.assertEqual(result_use(0x90610010),"store_r3")
    def test_variable_reference(self):
        self.assertEqual(variable_reference(0x3d608e04,0x806b8630),(0x8e038630,"memory_access"))
        self.assertIsNone(variable_reference(0x60000000,0x806b8630))
    def test_cross_module_direct_graph(self):
        image=struct.pack(">IIIIIIII",0x48000011,0x4e800020,0x60000000,0x60000000,
                          0x38600001,0x4800000d,0x2c030000,0x4e800020)
        pe={"entry_point":0x1000,"functions":[(0x1000,8,0),(0x1010,16,0)]}
        rows=[{"library":"xam.xex","ordinal":"0001","thunk_slots":[0x1020],"value_slots":[]}]
        cat={("xam",1):("XamTest","kFunction")}
        dash=inspect("dash",image,0x1000,pe,rows,cat,{"XamTest"})
        xam=inspect("xam",struct.pack(">I",0x4e800020),0x2000,
                    {"entry_point":0x2000,"functions":[(0x2000,4,0)]},[],cat,set())
        seen,unresolved=reachable({"dash":dash,"xam":xam},{1:0x2000},[("dash",0x1000)])
        self.assertEqual(seen,{("dash",0x1000):0,("dash",0x1010):1,("xam",0x2000):2})
        self.assertFalse(unresolved)
        result=report({"dash":dash,"xam":xam},{1:0x2000},cat,set())
        self.assertEqual(result["modules"]["dash"]["imports"][0]["startup_graph_sites"],1)
        self.assertEqual(result["modules"]["dash"]["imports"][0]["sites"][0]["immediate_return_use"],"compare_r3_immediate")
if __name__=="__main__":unittest.main()
