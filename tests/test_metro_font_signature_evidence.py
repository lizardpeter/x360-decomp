import sys
import unittest
import hashlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from metro_font_signature_evidence import recover_block,scan_headers,candidate_ranges,rotsum_sha,inspect_signature
from patch_metro_public_verification import PUBLIC_TEST_VECTORS,TEST_HASH,TEST_SALT,guest_number

class FontSignatures(unittest.TestCase):
    def test_public_only_original_format_vectors(self):
        expected=hashlib.sha1(bytes(8)+TEST_HASH+TEST_SALT).digest()
        for e,n,s in PUBLIC_TEST_VECTORS:
            n=int(n,16);signature=guest_number(int(s,16))
            self.assertEqual(recover_block(signature,n,e,TEST_SALT),expected)
            changed=bytearray(signature);changed[9]^=1
            self.assertIsNone(recover_block(changed,n,e,TEST_SALT))
            self.assertIsNone(recover_block(signature,n,e,b"WRONG_SALT"))
            data=bytes(32)+signature+bytes(64)
            found,count=scan_headers(data,n,e,TEST_SALT)
            self.assertEqual(found,[(32,expected)])
            self.assertGreater(count,1)
            report=inspect_signature(data,n,e,TEST_SALT)
            self.assertEqual(report["matching_encoded_signatures"][0]["signature_offset"],32)
            self.assertEqual(report["matching_encoded_signatures"][0]["signed_contiguous_ranges"],[])
    def test_candidate_ranges_do_not_cross_signature(self):
        for a,b in candidate_ranges(bytes(512),128):
            self.assertTrue(b<=128 or a>=384)
            self.assertTrue(0<=a<b<=512)
    def test_rotsum_single_input_and_empty(self):
        self.assertEqual(rotsum_sha(b""),hashlib.sha1(bytes(64)+b"\xff"*64).digest())
        prefix=bytes.fromhex("00000000000000000000000020000000ffffffffffffffffffffffffffffffff")
        # The explicit expected result below is from the single-word update,
        # including rotate-left of the subtraction accumulator.
        self.assertEqual(rotsum_sha(bytes.fromhex("0000000000000001")),
                         hashlib.sha1(prefix*2+bytes.fromhex("0000000000000001")+
                                      bytes(x^255 for x in prefix)*2).digest())

    def test_post_signature_length_metadata_is_considered(self):
        data=bytearray(1024)
        data[260:264]=(48).to_bytes(4,"big")
        ranges=candidate_ranges(bytes(data),4)
        self.assertIn((260,308),ranges)
        self.assertIn((264,312),ranges)
        self.assertTrue(all(a<b and (b<=4 or a>=260) for a,b in ranges))
