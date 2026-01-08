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

    def test_signature_ascii(self):
        f = File(contents=b"-----BEGIN PGP SIGNATURE-----...")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["signature"])

    def test_binary_public_key_old(self):
        # Tag 6 (Public Key Packet) -> 000110
        # Old format: 10xxxxxx
        # Tag is bits 5-2.
        # 0x80 | (6 << 2) = 0x80 | 0x18 = 0x98.
        f = File(contents=b"\x98\x01") 
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["public_key"])

    def test_binary_public_key_new(self):
        # Tag 6 -> 000110
        # New format: 11xxxxxx -> 0xC0 | 6 = 0xC6
        f = File(contents=b"\xC6\x01")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["public_key"])

    def test_binary_private_key_old(self):
        # Tag 5 (Secret Key Packet) -> 000101
        # Old format: 0x80 | (5 << 2) = 0x80 | 0x14 = 0x94
        f = File(contents=b"\x94\x01")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["private_key"])

    def test_binary_private_key_new(self):
        # Tag 5 -> 000101
        # New format: 11xxxxxx -> 0xC0 | 5 = 0xC5
        f = File(contents=b"\xC5\x01")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["private_key"])

    def test_binary_signature_old(self):
        # Tag 2 (Signature Packet) -> 000010
        # Old format: 0x80 | (2 << 2) = 0x80 | 0x08 = 0x88
        f = File(contents=b"\x88\x01")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["signature"])

    def test_binary_signature_new(self):
        # Tag 2 -> 000010
        # New format: 11xxxxxx -> 0xC0 | 2 = 0xC2
        f = File(contents=b"\xC2\x05")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["signature"])

    def test_binary_encrypted_old(self):
        # Tag 1 (Public-Key Encrypted Session Key Packet) -> 000001
        # Old format: 0x80 | (1 << 2) = 0x84
        f = File(contents=b"\x84\x01")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["encrypted_message"])

    def test_binary_encrypted_new(self):
        # Tag 18 (Sym Encrypted) -> 010010
        # New format: 11xxxxxx
        # 0xC0 | 18 = 0xC0 | 0x12 = 0xD2
        f = File(contents=b"\xD2\x05")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), ["encrypted_message"])

    def test_no_pgp_data(self):
        f = File(contents=b"this is not pgp data")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), [])

    def test_empty_content(self):
        f = File(contents=b"")
        p = PGP(f)
        self.assertEqual(p.get_metadata(), [])

if __name__ == '__main__':
    unittest.main()
