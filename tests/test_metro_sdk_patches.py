import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from filter_zero_aot_mappings import filter_text  # noqa: E402
from patch_metro_import_slots import (  # noqa: E402
    BINDINGS, VALUE_SLOTS, VARIABLE_ORDINAL, VARIABLE_SLOT, VARIABLE_TARGET,
    VARIABLE_OLD, VARIABLE_NEW, OLD as IMPORT_OLD, NEW as IMPORT_NEW,
    corrected as corrected_imports, rows, verify_slots,
)
from patch_rexglue_function_tables import (  # noqa: E402
    ALLOC, RELEASE, FIXED_ALLOC, FIXED_RELEASE,
    corrected as corrected_tables,
)


class MetroSDKPatchTests(unittest.TestCase):
    def test_zero_address_mapping_is_removed_but_null_sentinel_is_preserved(self):
        source = '''const PPCFuncMapping kPPCFuncMappings[] = {\n  { 0x0, &sub_00000000 },\n  { 0x92196610, &xstart },\n  { 0, nullptr }\n};\n'''
        updated, removed, retained = filter_text(source, (0x92196610,))
        self.assertEqual(removed, ["&sub_00000000"])
        self.assertEqual(retained, 1)
        self.assertNotIn("&sub_00000000", updated)
        self.assertIn("{ 0, nullptr }", updated)
        again, removed_again, retained_again = filter_text(updated, (0x92196610,))
        self.assertEqual(again, updated)
        self.assertEqual(removed_again, [])
        self.assertEqual(retained_again, 1)

    def test_zero_address_filter_rejects_missing_required_entrypoint(self):
        source = '''const PPCFuncMapping kPPCFuncMappings[] = {\n  { 0x1000, &sub_1000 },\n  { 0, nullptr }\n};\n'''
        with self.assertRaises(ValueError):
            filter_text(source, (0x92196610,))
    def test_original_dashboard_slots_match_exact_xam_ordinals(self):
        imports = rows(ROOT / "analysis/dash_17559/imports.tsv")
        exports = rows(ROOT / "analysis/xam_17559/exports.tsv")
        verify_slots(imports, exports)
        self.assertEqual(set(BINDINGS), set(VALUE_SLOTS))
        self.assertEqual(len(VALUE_SLOTS), 5)

    def test_rejects_wrong_value_slot(self):
        imports = rows(ROOT / "analysis/dash_17559/imports.tsv")
        exports = rows(ROOT / "analysis/xam_17559/exports.tsv")
        changed = copy.deepcopy(imports)
        target = next(
            item for item in changed
            if item["library"] == "xam.xex"
            and int(item["ordinal"], 16) == next(iter(VALUE_SLOTS))
        )
        target["value_slots"] = "92000000"
        with self.assertRaises(ValueError):
            verify_slots(changed, exports)

    def test_import_slot_patch_is_exact_and_guarded(self):
        source = VARIABLE_OLD + "\n" + IMPORT_OLD
        patched = corrected_imports(source)
        self.assertIn(VARIABLE_NEW, patched)
        self.assertIn(IMPORT_NEW, patched)
        self.assertIn("base_address_ == 0x92000000", patched)
        self.assertIn('base_name == "xam"', patched)
        self.assertIn("import_info.value_address", patched)
        self.assertIn("import_info.thunk_address", patched)
        self.assertIn("record_addr == 0x92000550", patched)
        self.assertIn('kernel_export->name == "g_XuiAutomation"', patched)
        with self.assertRaises(ValueError):
            corrected_imports(patched)
        with self.assertRaises(ValueError):
            corrected_imports(source.replace("Patched function import", "Patched function imports", 1))

    def test_g_xui_automation_data_binding_is_exact(self):
        imports = rows(ROOT / "analysis/dash_17559/imports.tsv")
        exports = rows(ROOT / "analysis/xam_17559/exports.tsv")
        verify_slots(imports, exports)
        item = next(r for r in imports if r["library"] == "xam.xex" and
                    int(r["ordinal"], 16) == VARIABLE_ORDINAL)
        self.assertEqual(item["value_slots"], f"{VARIABLE_SLOT:08X}")
        self.assertEqual(item["thunk_slots"], "")
        item = next(r for r in exports if int(r["ordinal"], 16) == VARIABLE_ORDINAL)
        self.assertEqual(int(item["address"], 16), VARIABLE_TARGET)

    def test_function_table_patch_selects_heap_from_guest_address(self):
        source = ALLOC + """
          kernel::kMemoryAllocationReserve | kernel::kMemoryAllocationCommit,
          kernel::kMemoryProtectRead | kernel::kMemoryProtectWrite)) {
    REXSYS_FAIL(false, "Failed to allocate function table at {:08X}", table_base);
  }
""" + RELEASE
        patched = corrected_tables(source)
        self.assertIn(FIXED_ALLOC, patched)
        self.assertIn(FIXED_RELEASE, patched)
        self.assertIn("LookupHeap(table_base)", patched)
        self.assertIn("table_heap->GetPageSize()", patched)
        self.assertNotIn("heaps_.v80000000.AllocFixed", patched)
        self.assertNotIn("heaps_.v80000000.Release", patched)
        with self.assertRaises(ValueError):
            corrected_tables(patched)

    def test_function_table_patch_rejects_partial_sdk_match(self):
        with self.assertRaises(ValueError):
            corrected_tables(ALLOC + "\n// missing release")


if __name__ == "__main__":
    unittest.main()
