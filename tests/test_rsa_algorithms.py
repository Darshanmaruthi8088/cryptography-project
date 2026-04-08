import unittest

from rsa_algorithms import generate_rsa_keypair, rsa_decrypt, rsa_encrypt, rsa_sign, rsa_verify


class TestRSAAlgorithms(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = generate_rsa_keypair(bits=128)

    def test_encrypt_decrypt(self):
        message = "rsa demo message"
        cipher = rsa_encrypt(message, self.keys["e"], self.keys["n"])
        plain = rsa_decrypt(cipher, self.keys["d"], self.keys["n"])
        self.assertEqual(plain, message)

    def test_sign_verify(self):
        message = "signed payload"
        signature = rsa_sign(message, self.keys["d"], self.keys["n"])
        self.assertTrue(rsa_verify(message, signature, self.keys["e"], self.keys["n"]))
        self.assertFalse(rsa_verify("tampered", signature, self.keys["e"], self.keys["n"]))


if __name__ == "__main__":
    unittest.main()

