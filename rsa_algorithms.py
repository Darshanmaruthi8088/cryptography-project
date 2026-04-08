"""Handwritten RSA utilities for educational demos."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List

from hash_algorithms import sha256_bytes


class RSAError(ValueError):
    """Raised when RSA operations fail."""


def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def _extended_gcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def _mod_inverse(a: int, modulus: int) -> int:
    g, x, _ = _extended_gcd(a, modulus)
    if g != 1:
        raise RSAError("Modular inverse does not exist.")
    return x % modulus


def _is_probable_prime(n: int) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for base in [2, 3, 5, 7, 11, 13, 17]:
        if base >= n - 2:
            continue
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits: int) -> int:
    if bits < 16:
        raise RSAError("Prime bit-size must be at least 16 bits.")

    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def generate_rsa_keypair(bits: int = 512) -> Dict[str, int]:
    if bits < 64:
        raise RSAError("RSA key size must be at least 64 bits for this demo.")

    e = 65537
    half_bits = bits // 2

    while True:
        p = _generate_prime(half_bits)
        q = _generate_prime(half_bits)
        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        if _gcd(e, phi) == 1:
            break

    d = _mod_inverse(e, phi)
    return {
        "p": p,
        "q": q,
        "n": n,
        "e": e,
        "d": d,
        "bits": n.bit_length(),
    }


def rsa_encrypt(message: str, e: int, n: int) -> List[int]:
    if n <= 255:
        raise RSAError("Modulus is too small.")
    data = message.encode("utf-8")
    return [pow(byte, e, n) for byte in data]


def rsa_decrypt(cipher_blocks: List[int], d: int, n: int) -> str:
    try:
        plain_bytes = bytes(pow(int(block), d, n) for block in cipher_blocks)
        return plain_bytes.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise RSAError("RSA decryption failed. Check private key and cipher blocks.") from exc


def rsa_sign(message: str, d: int, n: int) -> int:
    digest = sha256_bytes(message.encode("utf-8"))
    digest_int = int.from_bytes(digest, byteorder="big") % n
    return pow(digest_int, d, n)


def rsa_verify(message: str, signature: int, e: int, n: int) -> bool:
    digest = sha256_bytes(message.encode("utf-8"))
    expected = int.from_bytes(digest, byteorder="big") % n
    actual = pow(signature, e, n)
    return actual == expected

