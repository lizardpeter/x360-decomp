import hashlib
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from decode_image import decode
from analyze_decoded import imports,direct_calls

def basic_fixture():
    header=bytearray(0x400)
    struct.pack_into('>6I',header,0,0x58455832,0,len(header),0,0x80,1)
    struct.pack_into('>II',header,24,0x3ff,0x30)
    struct.pack_into('>IHHII',header,0x30,16,0,1,4,4092)
    struct.pack_into('>I',header,0x84,4096)
    struct.pack_into('>II',header,0x80+0x10c,0x10000000,0x92000000)
    struct.pack_into('>I',header,0x80+0x180,1)
    struct.pack_into('>I',header,0x80+0x184,0x11)
    body=b'ABCD';image=body+b'\0'*4092
    header[0x80+0x114:0x80+0x128]=hashlib.sha1(image+header[0x80+0x184:0x80+0x19c]).digest()
    return bytes(header)+body,image
class DecodedTests(unittest.TestCase):
    def test_basic(self):
        x,want=basic_fixture();got,info=decode(x)
        self.assertEqual(got,want);self.assertEqual(info['verified_page_runs'],1)
    def test_digest(self):
        x,_=basic_fixture()
        with self.assertRaisesRegex(ValueError,'digest mismatch'):decode(x[:-1]+b'X')
    def test_truncated(self):
        x,_=basic_fixture()
        with self.assertRaises(ValueError):decode(x[:-1])
    def test_import_split(self):
        data=bytes.fromhex('000001230100012300000456')
        meta={'imports':[{'library':'xam.xex','slot_addresses':['00001000']},{'library':'xam.xex','slot_addresses':['00001004','00001008']}]}
        rows=imports(data,0x1000,meta)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['thunk_slots'],[0x1004])
        self.assertEqual(rows[0]['value_slots'],[0x1000])
    def test_branch_classification(self):
        data=bytes.fromhex('480000094bfffffc600000004e800020')
        r=list(direct_calls(data,0x1000,[(0x1000,8,0)], [{'library':'xam.xex','ordinal':'0123','thunk_slots':[0x1008]}]))
        self.assertEqual(r,[('00001000','00001000','00001008','import','xam.xex','0123')])
if __name__=='__main__':unittest.main()
