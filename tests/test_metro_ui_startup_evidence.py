import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_ui_startup_evidence import literal_sites,data_pointer_sites,scan_code,ancestors

class UIStartupEvidence(unittest.TestCase):
    def test_reference_and_call(self):
        base=0x10000000;image=bytearray(256)
        image[0:9]=b"dashmain\0"
        struct.pack_into(">I",image,32,base)
        image[48:57]=b"dashmain\0"
        pe={"sections":[{"rva":0,"loaded_bytes":64,"flags":0,"name":".rdata"},
                       {"rva":64,"loaded_bytes":192,"flags":0x20000000,"name":".text"}],
            "functions":[(base+64,16,0),(base+96,8,0)]}
        # lis r4,0x1000; addi r4,r4,0; bl import; blr
        struct.pack_into(">4I",image,64,0x3c801000,0x38840000,0x48000039,0x4e800020)
        # Direct caller to first function.
        struct.pack_into(">2I",image,96,0x4bffffe1,0x4e800020)
        labels=literal_sites(image,base,pe,[(base+48,base+57)])
        self.assertEqual(labels[base],{"dashmain"})
        self.assertNotIn(base+48,labels)
        pointers=data_pointer_sites(image,base,pe,labels)
        self.assertEqual(pointers[base+32],{"dashmain"})
        calls,refs,inbound=scan_code(image,base,pe,{base+128:{
            "name":"XexGetModuleSection","library":"xboxkrnl"}},labels,set())
        self.assertEqual(len(calls),1)
        self.assertEqual(refs[0]["address"],"10000000")
        graph=ancestors({base+64},inbound)
        self.assertEqual(len(graph["nodes"]),2)
        self.assertEqual(graph["edges"][0]["caller"],"10000060")
    def test_bounded_reverse_graph(self):
        graph=ancestors({1},{1:{(2,3,True),(4,5,True)},2:{(1,6,True)}},max_nodes=2)
        self.assertTrue(graph["truncated"])
        self.assertEqual(len(graph["nodes"]),2)

if __name__=="__main__":unittest.main()
