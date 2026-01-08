import unittest
from sflock.unpack.pgp import PGP
from sflock.abstracts import File

class TestPGPMetadata(unittest.TestCase):
    def test_get_metadata(self):
        # (test_name, contents, expected_metadata)
        test_cases = [
            ("public_key_ascii", b"-----BEGIN PGP PUBLIC KEY BLOCK-----...", ["public_key"]),
            ("private_key_ascii", b"-----BEGIN PGP PRIVATE KEY BLOCK-----...", ["private_key"]),
            ("encrypted_ascii", b"-----BEGIN PGP MESSAGE-----...", ["encrypted_message"]),
            ("signature_ascii", b"-----BEGIN PGP SIGNATURE-----...", ["signature"]),
            # Old format: 0x80 | (tag << 2)
            ("binary_public_key_old", b"\x98\x01", ["public_key"]),      # Tag 6
            ("binary_private_key_old", b"\x94\x01", ["private_key"]),    # Tag 5
            ("binary_signature_old", b"\x88\x01", ["signature"]),      # Tag 2
            ("binary_encrypted_old", b"\x84\x01", ["encrypted_message"]),# Tag 1
            # New format: 0xC0 | tag
            ("binary_public_key_new", b"\xC6\x01", ["public_key"]),      # Tag 6
            ("binary_private_key_new", b"\xC5\x01", ["private_key"]),    # Tag 5
            ("binary_signature_new", b"\xC2\x05", ["signature"]),      # Tag 2
            ("binary_encrypted_new", b"\xD2\x05", ["encrypted_message"]),# Tag 18
            ("no_pgp_data", b"this is not pgp data", []),
            ("empty_content", b"", []),
        ]

        for name, contents, expected in test_cases:
            with self.subTest(name=name):
                f = File(contents=contents)
                p = PGP(f)
                self.assertEqual(p.get_metadata(), expected)

if __name__ == '__main__':
    unittest.main()
