import sys
import struct
import unittest
from collections import defaultdict
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_storage_boundary import shortest,path_to,graph

class StorageBoundary(unittest.TestCase):
    def test_shortest_paths_and_cycles(self):
        edges=defaultdict(set,{1:{(2,4,True),(3,8,False)},2:{(4,12,True)},3:{(4,16,True)},4:{(1,20,True)}})
        reached,truncated=shortest({1},edges)
        self.assertFalse(truncated)
        self.assertEqual(len(reached),4)
        self.assertEqual(path_to(4,reached),[{"caller":"00000001","site":"00000004","callee":"00000002","linked":True},
                                           {"caller":"00000002","site":"0000000C","callee":"00000004","linked":True}])
        self.assertTrue(shortest({1},edges,depth=1)[1])
        self.assertTrue(shortest({1},edges,limit=2)[1])

    def test_non_pdata_tail_wrapper_and_import(self):
        base=0x1000
        # entry calls 1010 (not PDATA), which tail-branches to 1030 import.
        words=[0x48000011,0x4E800020,0,0,0x48000020,0,0,0,
               0,0,0,0,0x4E800020,0,0,0]
        image=struct.pack(">16I",*words)
        pe={"functions":[(base,8,0)],
            "sections":[{"rva":0,"loaded_bytes":64,"flags":0x20000000}]}
        thunks={0x1030:{"name":"StfsControlDevice"}}
        funcs,wrappers,calls,edges,indirect,unknown=graph(image,base,pe,thunks,{})
        self.assertEqual(wrappers,{0x1010:"direct_tail"})
        self.assertEqual(edges[base],{(0x1010,base,True)})
        self.assertEqual(calls[0x1010][0]["import"]["name"],"StfsControlDevice")
        self.assertFalse(calls[0x1010][0]["linked"])
        self.assertEqual(len(path_to(0x1010,shortest({base},edges)[0])),1)
