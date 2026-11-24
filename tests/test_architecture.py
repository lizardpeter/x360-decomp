import unittest
import tomllib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class ArchitectureTests(unittest.TestCase):
    def test_components(self):
        spec=tomllib.loads((ROOT/"architecture.toml").read_text())
        items=spec["component"]
        graph={r["id"]:r["allow"] for r in items}
        self.assertEqual(len(graph),len(items))
        for r in items:
            for key in ("source","headers"):
                self.assertTrue((ROOT/r[key]).is_dir(),r[key])
        def visit(node,stack):
            self.assertNotIn(node,stack)
            for dep in graph[node]:
                self.assertIn(dep,graph)
                visit(dep,stack|{node})
        for node in graph:visit(node,set())
        for path in (ROOT/"profiles").glob("*.toml"):
            p=tomllib.loads(path.read_text())
            selected=set(p["components"])
            self.assertIn(p["entry"],selected)
            self.assertTrue(selected<=graph.keys())
            for node in selected:
                self.assertTrue(set(graph[node])<=selected or (node=="composition" and p["boot_mode"]=="hosted" and set(graph[node])-selected=={"boot"}))
