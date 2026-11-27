import hashlib
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from verify_retail_firmware import rsa_valid,table_block,KEY
class FirmwareTests(unittest.TestCase):
    def test_public_key_layout(self):
        self.assertEqual(len(KEY),272)
        self.assertEqual(int.from_bytes(KEY[:4],"big"),32)
        self.assertEqual(int.from_bytes(KEY[4:8],"big"),3)
        self.assertFalse(rsa_valid(bytes(256),hashlib.sha1(b"bad").digest()))
    def test_table_layout(self):
        self.assertEqual(table_block(0,0),0)
        self.assertEqual(table_block(169,0),0)
        self.assertEqual(table_block(170,0),172)
        self.assertEqual(table_block(0,1),171)
        self.assertEqual(table_block(28900,2),29071)
