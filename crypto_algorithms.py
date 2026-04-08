"""Handwritten crypto primitives and custom hybrid cipher workflows."""

from __future__ import annotations

import json
import os
import random
import string
import time
from dataclasses import dataclass
from typing import Dict, Optional

from config import APP_SECRET_KEY, DEFAULT_PBKDF2_ITERATIONS
from hash_algorithms import pbkdf2_sha256


class CryptoError(ValueError):
    """Raised for crypto/format validation errors."""


def _ensure_key_bytes(key: bytes) -> bytes:
    if not key:
        raise CryptoError("Key material cannot be empty.")
    return key


def vigenere_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    key = _ensure_key_bytes(key)
    return bytes((value + key[index % len(key)]) % 256 for index, value in enumerate(data))


def vigenere_decrypt_bytes(data: bytes, key: bytes) -> bytes:
    key = _ensure_key_bytes(key)
    return bytes((value - key[index % len(key)]) % 256 for index, value in enumerate(data))


def xor_cipher_bytes(data: bytes, key: bytes) -> bytes:
    key = _ensure_key_bytes(key)
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def rotate_bits_bytes(data: bytes) -> bytes:
    return bytes((((value << 3) & 0xFF) | (value >> 5)) for value in data)


def reverse_rotate_bits_bytes(data: bytes) -> bytes:
    return bytes(((value >> 3) | ((value << 5) & 0xFF)) & 0xFF for value in data)


def _derive_key_material(
    password: str,
    salt: bytes,
    required_len: int,
    iterations: int,
) -> bytes:
    required_len = max(required_len, 16)
    return pbkdf2_sha256(
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=required_len,
    )


def _random_nonce(length: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def encrypt_message(
    message: str,
    password: Optional[str] = None,
    demo_mode: bool = False,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> Dict[str, object]:
    plaintext = message.encode("utf-8")
    key_password = password or APP_SECRET_KEY
    nonce = _random_nonce()
    salt = os.urandom(8)

    key_stream = _derive_key_material(
        key_password, salt, required_len=len(plaintext), iterations=iterations
    )

    start = time.perf_counter()
    step1 = vigenere_encrypt_bytes(plaintext, key_stream)
    step2 = xor_cipher_bytes(step1, nonce.encode("utf-8"))
    step3 = rotate_bits_bytes(step2)
    duration_ms = round((time.perf_counter() - start) * 1000, 3)

    payload: Dict[str, object] = {
        "cipher": step3.hex(),
        "nonce": nonce,
        "salt": salt.hex(),
        "iterations": iterations,
        "duration_ms": duration_ms,
    }

    if demo_mode:
        payload["demo_steps"] = {
            "plaintext_hex": plaintext.hex(),
            "derived_key_hex": key_stream.hex(),
            "after_vigenere_hex": step1.hex(),
            "after_xor_hex": step2.hex(),
            "after_rotate_hex": step3.hex(),
        }

    return payload


def decrypt_message(
    ciphertext_hex: str,
    nonce: str,
    salt_hex: Optional[str] = None,
    password: Optional[str] = None,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    demo_mode: bool = False,
) -> Dict[str, object]:
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise CryptoError("Ciphertext must be a valid hexadecimal string.") from exc

    start = time.perf_counter()
    step1 = reverse_rotate_bits_bytes(ciphertext)
    step2 = xor_cipher_bytes(step1, nonce.encode("utf-8"))

    payload: Dict[str, object] = {}

    if salt_hex:
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError as exc:
            raise CryptoError("Salt must be valid hexadecimal.") from exc
        key_password = password or APP_SECRET_KEY
        key_stream = _derive_key_material(
            key_password, salt, required_len=len(step2), iterations=iterations
        )
        step3 = vigenere_decrypt_bytes(step2, key_stream)
        try:
            decrypted = step3.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CryptoError("Decryption failed. Check password/salt/nonce/cipher.") from exc
        payload["salt"] = salt_hex
    else:
        # Backward compatibility path for legacy ciphertexts without salt/PBKDF2.
        legacy_key = APP_SECRET_KEY.upper().encode("utf-8")
        step3 = vigenere_decrypt_bytes(step2, legacy_key)
        decrypted = step3.decode("latin-1")

    duration_ms = round((time.perf_counter() - start) * 1000, 3)

    payload.update(
        {
            "decrypted": decrypted,
            "duration_ms": duration_ms,
        }
    )

    if demo_mode:
        payload["demo_steps"] = {
            "cipher_hex": ciphertext.hex(),
            "after_reverse_rotate_hex": step1.hex(),
            "after_xor_hex": step2.hex(),
            "after_vigenere_hex": step3.hex(),
        }

    return payload


def encrypt_binary_payload(
    data: bytes,
    password: str,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
) -> Dict[str, object]:
    nonce = _random_nonce()
    salt = os.urandom(8)
    key_stream = _derive_key_material(
        password=password, salt=salt, required_len=len(data), iterations=iterations
    )
    step1 = vigenere_encrypt_bytes(data, key_stream)
    step2 = xor_cipher_bytes(step1, nonce.encode("utf-8"))
    step3 = rotate_bits_bytes(step2)

    return {
        "version": "CST1",
        "nonce": nonce,
        "salt": salt.hex(),
        "iterations": iterations,
        "cipher_hex": step3.hex(),
    }


def decrypt_binary_payload(payload: Dict[str, object], password: str) -> bytes:
    try:
        if payload.get("version") != "CST1":
            raise CryptoError("Unsupported encrypted file format.")

        nonce = str(payload["nonce"])
        salt = bytes.fromhex(str(payload["salt"]))
        iterations = int(payload["iterations"])
        cipher_bytes = bytes.fromhex(str(payload["cipher_hex"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise CryptoError("Invalid encrypted file payload format.") from exc

    step1 = reverse_rotate_bits_bytes(cipher_bytes)
    step2 = xor_cipher_bytes(step1, nonce.encode("utf-8"))
    key_stream = _derive_key_material(
        password=password, salt=salt, required_len=len(step2), iterations=iterations
    )
    return vigenere_decrypt_bytes(step2, key_stream)


def serialize_encrypted_payload(payload: Dict[str, object]) -> bytes:
    return json.dumps(payload, indent=2).encode("utf-8")


def parse_encrypted_payload(raw: bytes) -> Dict[str, object]:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CryptoError("Encrypted file is not valid JSON payload.") from exc

