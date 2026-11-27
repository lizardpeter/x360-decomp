import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_text_draw_evidence import virtual_calls,MAGIC
from metro_font_evidence import refs
class TextDrawEvidence(unittest.TestCase):
    def test_indirect_window_not_resolved(self):
        body={"operands":[{"pc":"00000004","kind":"memory_load","base":3,"offset":20},
                          {"pc":"00000008","kind":"indirect_branch","linked":True,"via":"ctr"},
                          {"pc":"0000000C","kind":"indirect_branch","linked":False,"via":"ctr"}]}
        r=virtual_calls(body)
        self.assertEqual(len(r),1)
        self.assertEqual(r[0]["site"],"00000008")
        self.assertNotIn("target",r[0])
    def test_xttf_magic_observation(self):
        words=[(15<<26)|(11<<21)|0x7874,(24<<26)|(11<<21)|(11<<16)|0x7466]
        self.assertEqual(list(refs(words,0x92000000,MAGIC)),[(0x92000004,0x78747466,"constructed_address")])

    def test_trace_plan_counts_and_semantics(self):
        from instrument_metro_ui import TEXT_CALLS,TEXT_ENTRIES
        self.assertEqual(sum(map(len,TEXT_CALLS.values())),30)
        self.assertEqual(sum(map(len,TEXT_ENTRIES.values())),19)
        self.assertEqual(TEXT_CALLS['generated'][0x9222F344][2],'boolean')
        self.assertEqual(TEXT_CALLS['generated'][0x9222F304][2],'status')
