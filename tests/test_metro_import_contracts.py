import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_import_contracts import branch, setup, result_use, variable_reference, inspect, reachable, report
import struct
from metro_xam_fault_evidence import conditional_details, observed_call, notification_gate, direct_tail_path

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

    def test_observed_lr_and_tail_wrapper(self):
        # bl from 0x1000 to 0x1010; wrapper tail b to import 0x1020.
        image=struct.pack(">9I",0x48000011,0x2c030000,0x41820008,0x4e800020,
                          0x48000010,0x60000000,0x60000000,0x60000000,0x4e800020)
        pe={"functions":[(0x1000,16,0),(0x1010,4,0)],
            "sections":[{"flags":0x20000000,"rva":0,"loaded_bytes":len(image)}]}
        imp={0x1020:{"name":"Example","library":"xboxkrnl","ordinal":"0001"}}
        row=observed_call(image,0x1000,pe,0x1004,"Example",imp)
        self.assertEqual(row["classification"],"direct_or_tail_match")
        self.assertEqual(row["tail_chain"],[{"from":"00001010","to":"00001020"}])
        self.assertEqual(row["operand_window"][2]["cr_test"],{"field":0,"bit":"eq","sense":"set"})
        self.assertEqual(observed_call(image,0x1000,pe,0x1004,"Other",imp)["classification"],"different_import")
        self.assertEqual(observed_call(image,0x1000,pe,0x1004,"Example",{})["classification"],"unresolved_wrapper_or_indirect")
        self.assertEqual(conditional_details(0x1008,0x40820008)["cr_test"]["sense"],"clear")
        self.assertIsNone(conditional_details(0,0x42000008)["cr_test"])

    def test_signed_notification_gate(self):
        imp={0x1020:{"name":"DrvGetContentStorageNotification"}}
        image=struct.pack(">3I",0x48000021,0x2c030000,0x41800008)
        row=notification_gate(image,0x1000,0x1000,0x1010,imp)
        self.assertEqual(row["negative_status_target"],"00001010")
        self.assertEqual(row["nonnegative_status_target"],"0000100C")
        self.assertEqual([x["next_pc"] for x in row["examples"]],
                         ["0000100C","0000100C","00001010","00001010"])
        # Reverse condition, as on the worker's second polling call.
        image=struct.pack(">3I",0x48000021,0x2c030000,0x4080fff8)
        row=notification_gate(image,0x1000,0x1000,0x100c,imp)
        self.assertEqual(row["nonnegative_status_target"],"00001000")
        with self.assertRaises(ValueError):notification_gate(image,0x1000,0x1000,0x1000,imp)
    def test_tail_path_preserves_original_function_entries(self):
        image=struct.pack(">5I",0x48000008,0x60000000,0x48000008,0x60000000,0x4e800020)
        pe={"functions":[(0x1000,4,0),(0x1008,4,0),(0x1010,4,0)]}
        path=direct_tail_path(image,0x1000,pe,0x1000,0x1010)
        self.assertEqual([x["to"] for x in path],["00001008","00001010"])
        self.assertIsNone(direct_tail_path(image,0x1000,pe,0x1000,0x1010,max_depth=1))
        self.assertIsNone(direct_tail_path(image,0x1000,pe,0x1000,0x1004))
if __name__=="__main__":unittest.main()
