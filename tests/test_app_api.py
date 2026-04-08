import unittest

from app import app


class TestAppAPI(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_encrypt_decrypt_flow(self):
        enc_response = self.client.post(
            "/encrypt",
            json={
                "message": "api roundtrip",
                "password": "api-pass",
                "iterations": 1200,
            },
        )
        self.assertEqual(enc_response.status_code, 200)
        enc_data = enc_response.json

        dec_response = self.client.post(
            "/decrypt",
            json={
                "cipher": enc_data["cipher"],
                "nonce": enc_data["nonce"],
                "salt": enc_data["salt"],
                "password": "api-pass",
                "iterations": enc_data["iterations"],
            },
        )
        self.assertEqual(dec_response.status_code, 200)
        self.assertEqual(dec_response.json["decrypted"], "api roundtrip")

    def test_sha256_endpoint(self):
        response = self.client.post("/hash/sha256", json={"text": "abc"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json["digest"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )


if __name__ == "__main__":
    unittest.main()

