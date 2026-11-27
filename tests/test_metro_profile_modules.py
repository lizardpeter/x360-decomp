import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_profile_modules import inventory,patch_codegen,mapping_coverage,validate_metadata,metadata
from patch_metro_retail_routing import OLD

class ProfileModules(unittest.TestCase):
    def test_verified_census_and_overlays(self):
        r=inventory()
        self.assertEqual(r["xam_binding_count"],710)
        self.assertEqual(r["distinct_xam_ordinals"],366)
        self.assertEqual(r["pdata_functions"],1699)
        self.assertEqual(len(r["overlapping_guest_images"]),3)
        self.assertFalse(r["guest_executed"])
        self.assertEqual(len(r["modules"]),5)
    def test_exact_forwarding(self):
        r=inventory()
        code=patch_codegen(OLD,r)
        for m in r["modules"].values():
            for b in m["xam_bindings"]:
                self.assertIn(f"case 0x{b['thunk']:08X}u: return ordinal==0x{b['ordinal']:04X}u;",code)
        self.assertEqual(code.count("return ordinal=="),710)
        self.assertIn("Unverified Metro profile XAM import",code)
        with self.assertRaises(ValueError):patch_codegen(code,r)
    def test_mapping_coverage_no_inference_from_pdata(self):
        r=inventory()
        all_targets={b["target"] for m in r["modules"].values() for b in m["xam_bindings"]}
        source="const PPCFuncMapping kPPCFuncMappings[] = {\n" + "".join(
            f"  {{0x{x:08X}, &func}},\n" for x in sorted(all_targets))+"  {0, nullptr},\n};"
        coverage=mapping_coverage(source,r)
        self.assertEqual(sum(m["mapped_bindings"] for m in coverage.values()),710)
        omitted=min(all_targets)
        coverage=mapping_coverage(source.replace(f"  {{0x{omitted:08X}, &func}},\n",""),r)
        self.assertGreater(sum(len(m["missing"]) for m in coverage.values()),0)
    def test_tampered_module_metadata_rejected(self):
        m=metadata("signin");m["image_bytes"]+=4096
        with self.assertRaises(ValueError):validate_metadata("signin",m)
