"""LSB steganography helpers with validation and capacity checks."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from PIL import Image


class StegoError(ValueError):
    """Raised when a steganography operation cannot be completed."""


_END_MARKER = b"\xFE"


def _bytes_to_bits(data: bytes) -> str:
    return "".join(format(byte, "08b") for byte in data)


def image_capacity_chars(image_path: str) -> int:
    with Image.open(image_path).convert("RGB") as img:
        width, height = img.size
    return (width * height * 3) // 8 - len(_END_MARKER)


def hide_message(image_path: str, message: str, output_dir: Path) -> Path:
    if not message:
        raise StegoError("Message cannot be empty for steganography.")

    with Image.open(image_path).convert("RGB") as img:
        width, height = img.size
        pixels = img.load()

        payload = message.encode("utf-8") + _END_MARKER
        bits = _bytes_to_bits(payload)
        capacity_bits = width * height * 3

        if len(bits) > capacity_bits:
            max_chars = max((capacity_bits // 8) - len(_END_MARKER), 0)
            raise StegoError(
                f"Message is too long for this image. Capacity is approximately {max_chars} characters."
            )

        index = 0
        for y in range(height):
            for x in range(width):
                pixel = list(pixels[x, y])
                for channel in range(3):
                    if index >= len(bits):
                        break
                    pixel[channel] = (pixel[channel] & ~1) | int(bits[index])
                    index += 1
                pixels[x, y] = tuple(pixel)
                if index >= len(bits):
                    break
            if index >= len(bits):
                break

        output_dir.mkdir(parents=True, exist_ok=True)
        out_path = output_dir / f"stego_{uuid4().hex[:8]}.png"
        img.save(out_path)
        return out_path


def extract_message(image_path: str) -> str:
    with Image.open(image_path).convert("RGB") as img:
        width, height = img.size
        pixels = img.load()

        bits = []
        for y in range(height):
            for x in range(width):
                pixel = pixels[x, y]
                bits.extend(str(pixel[channel] & 1) for channel in range(3))

    byte_values = []
    for i in range(0, len(bits), 8):
        chunk = "".join(bits[i : i + 8])
        if len(chunk) < 8:
            break
        value = int(chunk, 2)
        byte_values.append(value)
        if value == _END_MARKER[0]:
            break

    if not byte_values or byte_values[-1] != _END_MARKER[0]:
        raise StegoError("No hidden message marker found.")

    payload = bytes(byte_values[:-1])
    return payload.decode("utf-8", errors="replace")


def detect_steganography(image_path: str) -> dict:
    with Image.open(image_path).convert("RGB") as img:
        width, height = img.size
        pixels = img.load()

        sample_width = min(width, 300)
        sample_height = min(height, 300)

        ones = 0
        zeros = 0
        transitions = 0
        previous_bit = None

        for y in range(sample_height):
            for x in range(sample_width):
                pixel = pixels[x, y]
                for channel in range(3):
                    bit = pixel[channel] & 1
                    if bit == 1:
                        ones += 1
                    else:
                        zeros += 1

                    if previous_bit is not None and previous_bit != bit:
                        transitions += 1
                    previous_bit = bit

    total = ones + zeros
    ratio = ones / (zeros + 1)
    transition_ratio = transitions / max(total - 1, 1)
    lsb_balance = 1 - abs(0.5 - (ones / max(total, 1))) * 2

    # Heuristic confidence score (0-100)
    confidence = round((lsb_balance * 70 + transition_ratio * 30) * 100, 2)
    detected = 0.9 <= ratio <= 1.1 and confidence > 55

    return {
        "detected": bool(detected),
        "ratio": round(ratio, 4),
        "confidence": confidence,
        "sampled_bits": total,
    }

