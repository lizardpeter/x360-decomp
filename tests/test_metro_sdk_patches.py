import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from patch_metro_import_slots import (  # noqa: E402
    BINDINGS, VALUE_SLOTS, OLD as IMPORT_OLD, NEW as IMPORT_NEW,
    corrected as corrected_imports, rows, verify_slots,
)
from patch_rexglue_function_tables import (  # noqa: E402
    ALLOC, RELEASE, FIXED_ALLOC, FIXED_RELEASE,
    corrected as corrected_tables,
)


class MetroSDKPatchTests(unittest.TestCase):
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
        patched = corrected_imports(IMPORT_OLD)
        self.assertEqual(patched, IMPORT_NEW)
        self.assertIn("base_address_ == 0x92000000", patched)
        self.assertIn('base_name == "xam"', patched)
        self.assertIn("import_info.value_address", patched)
        self.assertIn("import_info.thunk_address", patched)
        with self.assertRaises(ValueError):
            corrected_imports(patched)
        with self.assertRaises(ValueError):
            corrected_imports(IMPORT_OLD.replace("Patched function import", "Patched function imports", 1))

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
