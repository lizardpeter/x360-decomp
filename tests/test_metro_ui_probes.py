import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from instrument_metro_ui import insert,probes,MARK

class MetroUIProbes(unittest.TestCase):
    def test_call_and_return(self):
        points=probes("generated_hud")
        self.assertEqual(points[0x913E9960],("hud_xui_init","call"))
        self.assertEqual(points[0x913E9964],("hud_xui_init","return"))
        source="  // METRO_GUEST_PC 913E9960\n  original_call();\n  // METRO_GUEST_PC 913E9964\n  original_next();\n"
        out,hits=insert(source,points)
        self.assertEqual(sum(hits.values()),2)
        self.assertLess(out.index("phase=call"),out.index("original_call();"))
        self.assertLess(out.index("original_call();"),out.index("phase=return"))
        self.assertLess(out.index("phase=return"),out.index("original_next();"))
        self.assertIn("metro_ui_n<=8",out)
        with self.assertRaises(ValueError):insert(out,points)
    def test_no_matching_marker(self):
        source="// METRO_GUEST_PC 12345678\noriginal();\n"
        self.assertEqual(insert(source,probes("generated"))[0],source)

    def test_original_font_call_sites_and_adjacent_returns(self):
        dash=probes("generated")
        xam=probes("generated_xam")
        for pc in (0x922655FC,0x92265604,0x92265754,0x92265778,0x922657B8):
            self.assertEqual(dash[pc][1],"call")
            self.assertEqual(dash[pc+4],(dash[pc][0],"return"))
        self.assertEqual(xam[0x81699190],("xam_font_patch_resolver","entry"))
        self.assertEqual(xam[0x81699810],("xam_font_typeface_resolver","entry"))
        self.assertEqual(xam[0x81699910],("xam_font_typeface_result","entry"))
        self.assertEqual(xam[0x816998FC],("xam_font_copy_path_2","return"))
        self.assertEqual(xam[0x81699244],("xam_font_patch_result","entry"))
    def test_font_path_probe_uses_caller_stack_and_checked_memory(self):
        source="// METRO_GUEST_PC 92265600\nnext();\n// METRO_GUEST_PC 92265754\ncall();\n"
        out,hits=insert(source,probes("generated"))
        self.assertEqual(sum(hits.values()),2)
        self.assertIn('ctx,0u,656u',out)
        self.assertIn('ctx,1u,0u',out)
        self.assertIn('mem.Load<rex::be_u16>',out)
        self.assertIn('mem->Load<rex::be_u32>(descriptor+4)',out)
        self.assertNotIn('mem->Store',out)
    def test_text_trace_never_logs_arguments_or_payload(self):
        points=probes("generated")
        source="// METRO_GUEST_PC 9222F304\noriginal_call();\n// METRO_GUEST_PC 9222F308\noriginal_next();\n"
        out,hits=insert(source,points)
        self.assertEqual(sum(hits.values()),2)
        self.assertIn("kind=none result=%s",out)
        self.assertIn("kind=status result=%s",out)
        self.assertIn("ctx.r3.u32==0",out)
        self.assertNotIn("ctx.r4",out)
        self.assertNotIn("METRO_UI pc=",out)
        self.assertLess(out.index("phase=call"),out.index("original_call();"))
        self.assertLess(out.index("phase=return"),out.index("original_next();"))
    def test_header_classifier_uses_only_known_labels_and_checked_reads(self):
        source="// METRO_GUEST_PC 921CB758\noriginal();\n// METRO_GUEST_PC 921F2800\nstore();\n// METRO_GUEST_PC 921E3B48\nnext();\n"
        out,hits=insert(source,probes("generated"))
        self.assertEqual(sum(hits.values()),3)
        self.assertIn('metro_header_observe<0x921CB758u>("entry",ctx,4u)',out)
        self.assertIn('metro_header_observe<0x921F2800u>("return",ctx,0u)',out)
        self.assertIn('metro_header_observe<0x921E3B48u>("return",ctx,29u)',out)
        self.assertIn('counts[tag.index]',out)
        self.assertIn("mem.Load<rex::be_u16>",out)
        self.assertNotIn("mem->Store",out)
        self.assertNotIn("METRO_UI pc=",out)
    def test_original_metric_epilogues_capture_both_rectangle_stages(self):
        dash=probes("generated")
        xam=probes("generated_xam")
        self.assertEqual(dash[0x92228EBC],("text_metric_integer","return"))
        self.assertEqual(dash[0x92229250],("text_metric_converted","return"))
        self.assertEqual(xam[0x81794664],("text_metric_integer","return"))
        self.assertEqual(xam[0x817949F8],("text_metric_converted","return"))
        source="// METRO_GUEST_PC 92228EBC\nrestore_stack();\n// METRO_GUEST_PC 92229250\nrestore_stack2();\n"
        out,hits=insert(source,dash)
        self.assertEqual(sum(hits.values()),2)
        self.assertIn('metro_metric_observe(0x92228EBCu,ctx,1u)',out)
        self.assertIn('metro_metric_observe(0x92229250u,ctx,2u)',out)
        self.assertLess(out.index('metro_metric_observe(0x92228EBCu'),out.index('restore_stack();'))
        self.assertIn('kind==1?ctx.r27.u32:ctx.r28.u32',out)
        self.assertIn('mem->Load<rex::be_u32>(rect+4*i)',out)
        self.assertIn('counts[kind-1][tag.index]',out)
        self.assertNotIn('mem->Store',out)
        self.assertNotIn('METRO_UI pc=',out)
    def test_property_and_resource_boundary_uses_checked_pointer(self):
        points=probes("generated")
        source="// METRO_GUEST_PC 921EB708\nentry();\n// METRO_GUEST_PC 921EB774\nreturn_copy();\n// METRO_GUEST_PC 921E0454\nreturn_resource();\n"
        out,hits=insert(source,points)
        self.assertEqual(sum(hits.values()),3)
        self.assertIn('metro_header_observe<0x921EB708u>("entry",ctx,4u)',out)
        self.assertIn('metro_header_observe<0x921EB774u>("return",ctx,31u)',out)
        self.assertIn('metro_header_observe<0x921E0454u>("return",ctx,3u)',out)
        self.assertIn("mem->Load<rex::be_u32>(object+4)",out)
        self.assertIn("template<unsigned pc>",out)
        self.assertNotIn("mem->Store",out)
        self.assertNotIn("METRO_UI pc=",out)
if __name__=="__main__":unittest.main()
