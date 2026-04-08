import unittest

from PIL import Image

from steganography import StegoError, extract_message, hide_message, image_capacity_chars
from tests.test_helpers import workspace_temp_dir


class TestSteganography(unittest.TestCase):
    def test_hide_extract_roundtrip(self):
        with workspace_temp_dir() as tmp:
            source = tmp / "source.png"
            output_dir = tmp / "output"

            Image.new("RGB", (80, 80), color=(120, 30, 220)).save(source)
            hidden = hide_message(str(source), "hidden text", output_dir=output_dir)
            extracted = extract_message(str(hidden))
            self.assertEqual(extracted, "hidden text")

    def test_capacity_check(self):
        with workspace_temp_dir() as tmp:
            source = tmp / "tiny.png"
            output_dir = tmp / "output"
            Image.new("RGB", (4, 4), color=(0, 0, 0)).save(source)

            capacity = image_capacity_chars(str(source))
            oversized = "a" * (capacity + 10)
            with self.assertRaises(StegoError):
                hide_message(str(source), oversized, output_dir=output_dir)


if __name__ == "__main__":
    unittest.main()
