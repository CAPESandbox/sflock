import unittest
from sflock.unpack.pgp import PGP
from sflock.abstracts import File

class TestPGPMetadata(unittest.TestCase):
    def test_public_key_ascii(self):
        f = File(contents=b"-----BEGIN PGP PUBLIC KEY BLOCK-----...")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["public_key"])

    def test_private_key_ascii(self):
        f = File(contents=b"-----BEGIN PGP PRIVATE KEY BLOCK-----...")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["private_key"])

    def test_encrypted_ascii(self):
        f = File(contents=b"-----BEGIN PGP MESSAGE-----...")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["encrypted_message"])

    def test_binary_public_key_old(self):
        # Tag 6 (Public Key Packet) -> 000110
        # Old format: 10xxxxxx
        # Tag is bits 5-2.
        # 0x80 | (6 << 2) = 0x80 | 0x18 = 0x98.
        # Let's use 0x98 (length type 0 - 1 byte length)
        f = File(contents=b"\x98\x01") 
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["public_key"])

    def test_binary_encrypted_new(self):
        # Tag 18 (Sym Encrypted) -> 010010
        # New format: 11xxxxxx
        # 0xC0 | 18 = 0xC0 | 0x12 = 0xD2
        f = File(contents=b"\xD2\x05")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["encrypted_message"])

if __name__ == '__main__':
    unittest.main()
