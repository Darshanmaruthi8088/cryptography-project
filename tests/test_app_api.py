import unittest
from io import BytesIO

from PIL import Image
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

    def test_hide_supports_jpg_images(self):
        image_bytes = BytesIO()
        Image.new("RGB", (80, 80), color=(10, 20, 30)).save(image_bytes, format="JPEG")
        image_bytes.seek(0)

        response = self.client.post(
            "/hide",
            data={"message": "hidden", "image": (image_bytes, "sample.jpg")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json["output_file"].endswith(".png"))

    def test_encrypt_file_download_link_works(self):
        encrypt_response = self.client.post(
            "/encrypt-file",
            data={"file": (BytesIO(b"sample payload"), "demo.txt"), "password": "strong-pass"},
            content_type="multipart/form-data",
        )
        self.assertEqual(encrypt_response.status_code, 200)
        download_url = encrypt_response.json["download_url"]
        self.assertTrue(download_url.startswith("/download/"))

        download_response = self.client.get(download_url)
        try:
            self.assertEqual(download_response.status_code, 200)
            disposition = download_response.headers.get("Content-Disposition", "")
            self.assertIn("attachment;", disposition)
            self.assertGreater(len(download_response.data), 0)
        finally:
            download_response.close()


if __name__ == "__main__":
    unittest.main()
