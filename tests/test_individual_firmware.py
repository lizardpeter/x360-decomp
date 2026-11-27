import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_individual_firmware import rot_sum_sha,rc4,reverse_qwords,xex_rsa,xex_header

class IndividualFirmware(unittest.TestCase):
    def test_rotsum_reference(self):
        self.assertEqual(rot_sum_sha(bytes(range(0x74))).hex(),"213645359a41fa502f80d5c38f3a4a3c7c55b0ec")
    def test_rc4_reference(self):
        self.assertEqual(rc4(b"Key",b"Plaintext").hex(),"bbf316e8d940af0ad3")
    def test_qword_order(self):
        self.assertEqual(reverse_qwords(b"12345678abcdefgh"),b"abcdefgh12345678")
        self.assertFalse(xex_rsa(bytes(256),bytes(20),b"XBOX360XEX"))
        with self.assertRaises(ValueError):xex_header(b"bad")
