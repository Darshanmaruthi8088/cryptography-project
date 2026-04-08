import unittest

from config import APP_SECRET_KEY
from crypto_algorithms import (
    CryptoError,
    decrypt_binary_payload,
    decrypt_message,
    encrypt_binary_payload,
    encrypt_message,
    reverse_rotate_bits_bytes,
    rotate_bits_bytes,
    vigenere_encrypt_bytes,
    xor_cipher_bytes,
)


class TestCryptoAlgorithms(unittest.TestCase):
    def test_rotate_reverse_roundtrip(self):
        data = b"\x00\x10\x20\x7f\x80\xff"
        self.assertEqual(reverse_rotate_bits_bytes(rotate_bits_bytes(data)), data)

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = "Hello cryptography नमस्ते"
        encrypted = encrypt_message(plaintext, password="safe-pass", iterations=1500)
        decrypted = decrypt_message(
            ciphertext_hex=encrypted["cipher"],
            nonce=encrypted["nonce"],
            salt_hex=encrypted["salt"],
            password="safe-pass",
            iterations=int(encrypted["iterations"]),
        )
        self.assertEqual(decrypted["decrypted"], plaintext)

    def test_decrypt_fails_with_wrong_password(self):
        encrypted = encrypt_message("secure message", password="correct-pass", iterations=1500)
        with self.assertRaises(CryptoError):
            decrypt_message(
                ciphertext_hex=encrypted["cipher"],
                nonce=encrypted["nonce"],
                salt_hex=encrypted["salt"],
                password="wrong-pass",
                iterations=int(encrypted["iterations"]),
            )

    def test_legacy_decrypt_compatibility(self):
        plaintext = "legacy-text"
        nonce = "ABCD1234"
        key = APP_SECRET_KEY.upper().encode("utf-8")
        step1 = vigenere_encrypt_bytes(plaintext.encode("latin-1"), key)
        step2 = xor_cipher_bytes(step1, nonce.encode("utf-8"))
        legacy_cipher_hex = rotate_bits_bytes(step2).hex()

        decrypted = decrypt_message(legacy_cipher_hex, nonce)
        self.assertEqual(decrypted["decrypted"], plaintext)

    def test_binary_payload_roundtrip(self):
        original = b"\x00\x01\x02HelloFile\xff"
        payload = encrypt_binary_payload(original, password="file-pass", iterations=1800)
        restored = decrypt_binary_payload(payload, password="file-pass")
        self.assertEqual(restored, original)


if __name__ == "__main__":
    unittest.main()

