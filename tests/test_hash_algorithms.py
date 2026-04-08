import hashlib
import unittest

from hash_algorithms import pbkdf2_sha256, sha256_hex


class TestHashAlgorithms(unittest.TestCase):
    def test_sha256_empty(self):
        self.assertEqual(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855",
        )

    def test_sha256_abc(self):
        self.assertEqual(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223"
            "b00361a396177a9cb410ff61f20015ad",
        )

    def test_pbkdf2_matches_hashlib(self):
        password = b"password"
        salt = b"salt"
        iterations = 2000
        dklen = 32

        expected = hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=dklen)
        actual = pbkdf2_sha256(password, salt, iterations=iterations, dklen=dklen)
        self.assertEqual(actual, expected)


if __name__ == "__main__":
    unittest.main()

