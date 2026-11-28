import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from compare_metro_text_paths import compare

class TextPathsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def write(self,variant,pixels,extra="",frames=None):
        path=self.root/variant;path.mkdir()
        receipt=[f"variant={variant}",f"quad_conversion={'true' if variant=='quad' else 'false'}",
                 "guest_mode=1280x720","render_scale=1x1","async_shader_compilation=false",
                 "placeholder_draw_frames=0","METRO_BOOT pass dashboard_entry",extra]
        for i,data in enumerate(pixels):
            name=f"candidate-{i+1:02}.png";(path/name).write_bytes(data)
            frame=frames[i] if frames else i+1
            receipt += [f"sample={name} guest_frames={frame} width=1280 height=720 colors=999",
                        f"{hashlib.sha256(data).hexdigest()}  {name}"]
        (path/"receipt.txt").write_text("\n".join(receipt))
        return path

    @staticmethod
    def decode(path):
        data=path.read_bytes()
        return hashlib.sha256(data).hexdigest(),{
            "home_header_signature":data!=b"splash","status":"suspected_missing_terminal_glyph"}

    def test_identical_settled(self):
        a=self.write("baseline",[b"splash",b"home",b"home"])
        b=self.write("quad",[b"home",b"home"])
        result=compare(a,b,self.decode)
        self.assertEqual(result["status"],"identical_settled_pixels")
        self.assertTrue(result["both_suspected_missing_terminal_glyph"])
        self.assertFalse(result["repair_verified"])

    def test_different_pixels(self):
        a=self.write("baseline",[b"home",b"home"])
        b=self.write("quad",[b"other",b"other"])
        self.assertEqual(compare(a,b,self.decode)["status"],"different_settled_pixels")

    def test_splash_or_frozen_guest_not_settled(self):
        a=self.write("baseline",[b"splash",b"splash"])
        b=self.write("quad",[b"home",b"home"],frames=[2,2])
        self.assertEqual(compare(a,b,self.decode)["status"],"unavailable")

    def test_changed_sample_or_ambiguous_settings(self):
        a=self.write("baseline",[b"home",b"home"])
        b=self.write("quad",[b"home",b"home"],extra="quad_conversion=false")
        (a/"candidate-02.png").write_bytes(b"changed")
        r=compare(a,b,self.decode)
        self.assertEqual(r["baseline"]["reason"],"missing or changed sample")
        self.assertEqual(r["quad"]["reason"],"invalid quad_conversion")

if __name__=="__main__":unittest.main()
