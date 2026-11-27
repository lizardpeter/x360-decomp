import sys
import struct
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_bootanim_evidence import riff_metadata,loader_references,xma1_format,matching_functions,direct_audio_contract,control_flag_references

def wave():
    fmt=struct.pack("<HHIIHH",1,2,48000,192000,4,16)
    body=b"WAVE"+b"fmt "+struct.pack("<I",len(fmt))+fmt+b"JUNK"+struct.pack("<I",1)+b"x\0"+b"data"+struct.pack("<I",4)+b"\0"*4
    return b"RIFF"+struct.pack("<I",len(body))+body

class BootanimEvidence(unittest.TestCase):
    def test_riff_bounds(self):
        payload=wave()
        result=riff_metadata(payload)
        self.assertEqual(result["format"]["sample_rate"],48000)
        self.assertEqual([c["id"] for c in result["chunks"]],["fmt ","JUNK","data"])
        with self.assertRaises(ValueError):riff_metadata(payload[:-1])
        with self.assertRaises(ValueError):riff_metadata(b"RIFF"+b"\0"*20)
    def test_xma1_header_and_packet_validation(self):
        fmt=struct.pack("<HHHHHBB",0x165,16,0x10d6,0,1,0,2)
        fmt+=struct.pack("<IIIIBBH",24000,48000,0,0,0,2,3)
        body=b"WAVE"+b"fmt "+struct.pack("<I",len(fmt))+fmt+b"data"+struct.pack("<I",2048)+b"\0"*2048
        parsed=riff_metadata(b"RIFF"+struct.pack("<I",len(body))+body)
        self.assertEqual(parsed["format"]["streams"][0]["sample_rate"],48000)
        self.assertEqual(parsed["format"]["channels"],2)
        self.assertEqual(parsed["packet_count"],1)
        with self.assertRaises(ValueError):xma1_format(fmt[:-1])
        with self.assertRaises(ValueError):xma1_format(fmt[:8]+b"\0\0"+fmt[10:])
    def test_normalized_cross_module_match(self):
        a=struct.pack(">4I",0x3c80981a,0x80840020,0x48001001,0x4e800020)
        b=struct.pack(">4I",0x3c80819a,0x80840020,0x48002001,0x4e800020)
        c=struct.pack(">4I",0x3c80819a,0x80840024,0x48002001,0x4e800020)
        src={"functions":[(0x1000,16,0)]}
        dst={"functions":[(0x2000,16,0),(0x2010,16,0)]}
        result=matching_functions(a,0x1000,src,b+c,0x2000,dst,[0x1000])[0]
        self.assertEqual(result["exact"],["00002000"])
        self.assertEqual(result["near"][0]["address"],"00002010")
    def test_direct_audio_contract(self):
        pc=0x980517C4;cb=0x9804BEA0
        registration={"operands":[
            {"pc":f"{pc-0x44:08X}","kind":"register_copy","source":4,"writes":29},
            {"pc":f"{pc-0x14:08X}","kind":"memory_load","base":30,"offset":12,"writes":11},
            {"pc":f"{pc-0x0c:08X}","kind":"memory_store","base":1,"offset":80,"source":29},
            {"pc":f"{pc-8:08X}","kind":"register_offset","base":1,"value":80,"writes":3},
            {"pc":f"{pc-4:08X}","kind":"memory_store","base":1,"offset":84,"source":11},
            {"pc":f"{pc:08X}","kind":"branch","linked":True,
             "import":{"name":"XAudioRegisterRenderDriverClient"}}]}
        callback={"operands":[
            {"pc":f"{cb+0x10:08X}","kind":"register_copy","source":3,"writes":31},
            {"pc":f"{cb+0x30:08X}","kind":"memory_load","base":31,"offset":304,"writes":10},
            {"pc":f"{cb+0x38:08X}","kind":"memory_store","base":31,"offset":300,"source":11}]}
        self.assertEqual(direct_audio_contract(registration,callback,pc,cb)["registration_return"],"980517C8")
        callback["operands"][1]["offset"]=4
        with self.assertRaises(ValueError):direct_audio_contract(registration,callback,pc,cb)
    def test_control_flag_references(self):
        # lis r10,0x9807; stb r11,0x7760(r10);
        # lis r11,0x9807; lbz r10,0x7761(r11)
        image=struct.pack(">4I",0x3d409807,0x996a7760,0x3d609807,0x894b7761)
        result=control_flag_references(image,0x1000,{"functions":[(0x1000,16,0)]},
                                      {0x98077760,0x98077761})
        self.assertEqual([(r["address"],r["access"]) for r in result],
                         [("98077760","write"),("98077761","read")])
    def test_loader_reference(self):
        base=0x10000000;image=bytearray(128)
        image[:13]=b"bootanim.xex\0"
        struct.pack_into(">I",image,32,base)
        struct.pack_into(">3I",image,64,0x3c801000,0x38840000,0x4e800020)
        pe={"sections":[{"rva":0,"loaded_bytes":64,"flags":0},
                        {"rva":64,"loaded_bytes":64,"flags":0x20000000}],
            "functions":[(base+64,12,0)]}
        result=loader_references(image,base,pe)
        self.assertEqual(result["literal_addresses"],["10000000"])
        self.assertIn("10000020",result["pointer_addresses"])
        self.assertEqual(result["code_references"][0]["target"],"10000000")


class PhaseArithmetic(unittest.TestCase):
    def test_scalar_fp_operands(self):
        from metro_bootanim_evidence import phase_fp_instruction as decode
        self.assertEqual(decode((48<<26)|(13<<21)|(31<<16)|36),
                         {"op":"lfs","fpr":13,"base":31,"offset":36,"width":4})
        self.assertEqual(decode((52<<26)|(13<<21)|(31<<16)|0xfff8),
                         {"op":"stfs","fpr":13,"base":31,"offset":-8,"width":4})
        self.assertEqual(decode((63<<26)|(6<<23)|(13<<16)),
                         {"op":"fcmpu","cr":6,"lhs":13,"rhs":0})
        self.assertEqual(decode((59<<26)|(2<<21)|(3<<16)|(4<<6)|(25<<1)),
                         {"op":"fmuls","dest":2,"a":3,"c":4})
        self.assertEqual(decode((63<<26)|(1<<21)|(3<<11)|(72<<1)),
                         {"op":"fmr","dest":1,"src":3})
        self.assertIsNone(decode(0x4e800020))

if __name__=="__main__":unittest.main()
