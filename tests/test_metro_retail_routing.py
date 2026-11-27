import copy
import json
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from patch_metro_retail_routing import OLD,header,patched,inventory,original_inventory,ROOT,rows

class RetailRouting(unittest.TestCase):
    def setUp(self):
        self.im=rows(ROOT/"analysis/dash_17559/imports.tsv")
        self.ex=rows(ROOT/"analysis/xam_17559/exports.tsv")
        self.dash,self.xam=(json.loads((ROOT/"analysis"/m/"decoded.json").read_text())
                           for m in ("dash_17559","xam_17559"))
    def test_complete_set(self):
        bindings=original_inventory()
        self.assertEqual(len(bindings),522)
        self.assertEqual(sum(x["data"] for x in bindings),1)
        self.assertEqual(len({x["slot"] for x in bindings}),522)
        self.assertEqual(len({x["thunk"] for x in bindings}),522)
        self.assertIn("array<Binding, 521>",header(bindings))
        code=patched(OLD,bindings)
        self.assertEqual(code.count("case 0x"),521)
        self.assertNotIn("case 0x03DB:",code)
        self.assertIn('binary.GetBaseAddress() == 0x92000000 && lib_name == "xam"',code)
        for x in bindings:
            if not x["data"]:
                self.assertIn(f"case 0x{x['ordinal']:04X}: return sym.address == 0x{x['thunk']:08X};",code)
        for source in ("",OLD+OLD,code):
            with self.assertRaises(ValueError):patched(source,bindings)
    def test_metadata_fail_closed(self):
        for im,ex,dash,xam in [
            (self.im[:-1],[],self.dash,self.xam),
            (self.im+self.im,self.ex,self.dash,self.xam),
            (self.im,self.ex,self.dash,{**self.xam,"source_sha256":"0"*64}),
        ]:
            with self.assertRaises(ValueError):inventory(im,ex,dash,xam)
        with self.assertRaises(ValueError):
            inventory(self.im,self.ex,self.dash,self.xam,{0x03DB:("bad","kFunction")})
        bad=copy.deepcopy(self.im)
        item=next(x for x in bad if x["library"]=="xam.xex")
        item["thunk_slots"]=item["value_slots"]
        with self.assertRaises(ValueError):inventory(bad,self.ex,self.dash,self.xam)

if __name__=="__main__":unittest.main()
