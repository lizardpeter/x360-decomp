import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_module_lifecycle import shortest_paths,path_to

class LifecycleTests(unittest.TestCase):
    def test_cross_module_path_retains_exact_sites(self):
        a=("dash",0x1000); b=("xam",0x2000); c=("xam",0x3000)
        edges={a:[(b,0x1010,True)],b:[(c,0x2008,False)],c:[(a,0x3000,True)]}
        p=shortest_paths(edges,[a])
        self.assertEqual(len(p),3)
        self.assertEqual(path_to(p,c),[
            {"module":"dash","entry":"00001000","site":"00001010","target_module":"xam","target":"00002000","linked":True},
            {"module":"xam","entry":"00002000","site":"00002008","target_module":"xam","target":"00003000","linked":False}])
        self.assertIsNone(path_to(p,("xam",0x4000)))
        self.assertEqual(path_to(p,a),[])
        self.assertIsNone(path_to(p,c,limit=1))
if __name__=="__main__":unittest.main()
