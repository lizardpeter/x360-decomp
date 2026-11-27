import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"tools"))

from audit_metro_startup_imports import startup_edges, classify

def edge(caller, target, kind, library="", ordinal=""):
    return dict(caller=caller, target=target, kind=kind, library=library, ordinal=ordinal)

class StartupAuditTests(unittest.TestCase):
    def test_depth_and_cycle_are_bounded(self):
        graph = [
            edge("A", "B", "pdata"), edge("B", "A", "pdata"),
            edge("A", "X", "unclassified"), edge("B", "C", "pdata"),
            edge("B", "T", "import", "xam.xex", "01CC"),
            edge("C", "U", "import", "xboxkrnl.exe", "0015"),
            edge("C", "T", "import", "xam.xex", "01CC"),
        ]
        a = startup_edges(graph, "A", 1)
        self.assertEqual(a["known_functions_visited"], 2)
        self.assertEqual(a["unclassified_direct_targets"], ["X"])
        self.assertEqual(a["imports"], [{"library":"xam.xex", "ordinal":"01CC",
                                        "thunk":"T", "depth":1, "path":["A","B"]}])
        b = startup_edges(graph, "A", 2)
        self.assertEqual(b["known_functions_visited"], 3)
        self.assertEqual(len(b["imports"]), 2)

    def test_actual_stub_and_retail_target_are_distinct_evidence(self):
        item = {"library":"xam.xex", "ordinal":"01CC", "thunk":"9293ACDC",
                "depth":1, "path":["92196610", "921870A0"]}
        r = classify(item, {("xam",0x1CC):("XamSetDashContext","kFunction")},
                     {("xam","XamSetDashContext")}, {0x1CC:"816E1680"},
                     {"816E1680"}, lambda address: address == 0x816E1680)
        self.assertEqual(r["sdk_status"], "explicit_stub")
        self.assertTrue(r["retail_pdata_entry"])
        self.assertTrue(r["retail_target_executable"])
        self.assertNotIn("sdk_status", item)

    def test_unclassified_edges_and_unknown_catalog_are_not_guessed(self):
        a = classify({"library":"xam.xex","ordinal":"0546"}, {}, set(),
                     {0x546:"8168EB50"}, set(), lambda _: True)
        self.assertEqual(a["sdk_status"], "not_catalogued")
        self.assertFalse(a["retail_pdata_entry"])
        with self.assertRaises(ValueError):
            startup_edges([edge("A","B","unknown")], "A")
        with self.assertRaises(ValueError):
            startup_edges([], "A", 33)

if __name__ == "__main__":
    unittest.main()
