import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from stage_metro_profile_modules import inventory,patch_codegen,mapping_coverage,validate_metadata,metadata,patch_profile_loader,integrated_manifest
from patch_metro_retail_routing import patched,original_inventory,hud_inventory
from stage_metro_xam_aot import manifest
from stage_metro_intro import append_module
import tomllib
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

    def test_profile_codegen_distinguishes_overlays(self):
        r=inventory()
        code=patch_codegen(patched(OLD,original_inventory(),hud_inventory()),r,integrated=True)
        for m in r["modules"].values():
            identity=(f"binary.GetBaseAddress()==0x{m['base']:08X}u && "
                      f"binary.GetImageSize()=={m['size']}u && "
                      f"binary.GetEntryPoint()==0x{m['entry']:08X}u")
            self.assertEqual(code.count(identity),2)
        self.assertIn("else if (metro_retail_function_import)",code)
        self.assertEqual(code.count("return ordinal=="),710)
        with self.assertRaises(ValueError):patch_codegen(code,r,integrated=True)

    def test_integrated_manifest_retains_baseline(self):
        before=append_module(manifest())
        original=tomllib.loads(before)
        after=tomllib.loads(integrated_manifest(before,inventory()))
        self.assertEqual(after["project"],original["project"])
        self.assertEqual(after["entrypoint"],original["entrypoint"])
        self.assertEqual(after["modules"][:3],original["modules"])
        self.assertEqual(len(after["modules"]),8)
        for m in after["modules"][3:]:
            self.assertTrue(m["file_path"].startswith("inputs/flash/"))
            self.assertTrue(m["is_dll"])
        with self.assertRaises(ValueError):integrated_manifest(manifest(),inventory())

    def test_profile_loader_fails_closed(self):
        from patch_metro_retail_routing import patch_hud_loader
        original=("\n    if (rex::kernel::ModuleFromName(library.name) || IsKernelModule(library.name)) {\n"
                  "  std::string path(raw_name);\n  if (name == raw_name) {\n"
                  "  auto recomp = FindRecompiledModule(path);\n")
        baseline=patch_hud_loader(original,hud_inventory())
        code=patch_profile_loader(baseline,inventory())
        self.assertIn("if (!FindRecompiledModule(path))",code)
        self.assertIn("metro_profile_name.empty() && name == raw_name",code)
        self.assertIn("!runtime_.FindFunction(target)",code)
        self.assertIn("ReleaseDependencies(*module,call_entry)",code)
        self.assertIn("module->user.is_dll_module",code)
        self.assertEqual(code.count("return import.value_address=="),710)
        with self.assertRaises(ValueError):patch_profile_loader(code,inventory())

    def test_preflight_header_has_every_exact_original_slot(self):
        from stage_metro_profile_modules import preflight_header
        r=inventory();h=preflight_header(r)
        for name,m in r["modules"].items():
            self.assertIn(f'{{"{name}.xex",0x{m["base"]:08X}u,{m["size"]}u,0x{m["entry"]:08X}u',h)
            for kind in ("xam","kernel"):
                for b in m[kind+"_bindings"]:
                    self.assertIn(f"{{0x{b['ordinal']:04X}u,0x{b['slot']:08X}u,0x{b['thunk']:08X}u,0x{b.get('target',0):08X}u}}",h)

    def test_strict_callable_registration_gate(self):
        from verify_metro_profile_generated import strict_mappings
        prefix="const PPCFuncMapping kPPCFuncMappings[] = {\n"
        body="  {0x1000, &fn},\n  {0, nullptr},\n};"
        self.assertEqual(strict_mappings(prefix+body,[0x1000])["native_mappings"],1)
        for bad in (body.replace("&fn","nullptr"),body.replace("0x1000","0x1001"),
                    body.replace("  {0, nullptr},","  {0x1000, &fn2},\n  {0, nullptr},"),
                    body.replace("  {0, nullptr},",""),
                    body.replace("0x1000","0x2000")):
            with self.assertRaises(ValueError):strict_mappings(prefix+bad,[0x1000])
