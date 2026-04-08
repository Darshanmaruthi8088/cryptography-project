"""Handwritten hashing and key-derivation algorithms."""

import math

_MASK32 = 0xFFFFFFFF

_H0 = [
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
]

_K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _right_rotate(value: int, shift: int) -> int:
    return ((value >> shift) | ((value << (32 - shift)) & _MASK32)) & _MASK32


def sha256_bytes(data: bytes) -> bytes:
    """Compute SHA-256 digest with a handwritten implementation."""
    message = bytearray(data)
    bit_length = len(message) * 8
    message.append(0x80)

    while (len(message) % 64) != 56:
        message.append(0)

    message.extend(bit_length.to_bytes(8, byteorder="big"))

    h = _H0[:]

    for chunk_start in range(0, len(message), 64):
        chunk = message[chunk_start : chunk_start + 64]
        w = [0] * 64

        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4 : (i + 1) * 4], byteorder="big")

        for i in range(16, 64):
            s0 = _right_rotate(w[i - 15], 7) ^ _right_rotate(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _right_rotate(w[i - 2], 17) ^ _right_rotate(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

        a, b, c, d, e, f, g, hv = h

        for i in range(64):
            s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            choice = (e & f) ^ (~e & g)
            temp1 = (hv + s1 + choice + _K[i] + w[i]) & _MASK32
            s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + majority) & _MASK32

            hv = g
            g = f
            f = e
            e = (d + temp1) & _MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & _MASK32

        h = [
            (h[0] + a) & _MASK32,
            (h[1] + b) & _MASK32,
            (h[2] + c) & _MASK32,
            (h[3] + d) & _MASK32,
            (h[4] + e) & _MASK32,
            (h[5] + f) & _MASK32,
            (h[6] + g) & _MASK32,
            (h[7] + hv) & _MASK32,
        ]

    return b"".join(value.to_bytes(4, byteorder="big") for value in h)


def sha256_hex(data: bytes) -> str:
    return sha256_bytes(data).hex()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    block_size = 64

    if len(key) > block_size:
        key = sha256_bytes(key)
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    o_key_pad = bytes(b ^ 0x5C for b in key)
    i_key_pad = bytes(b ^ 0x36 for b in key)

    return sha256_bytes(o_key_pad + sha256_bytes(i_key_pad + message))


def pbkdf2_sha256(password: bytes, salt: bytes, iterations: int = 3000, dklen: int = 32) -> bytes:
    """PBKDF2-HMAC-SHA256 (handwritten building blocks)."""
    if iterations <= 0:
        raise ValueError("iterations must be > 0")
    if dklen <= 0:
        raise ValueError("dklen must be > 0")

    hash_len = 32
    blocks = math.ceil(dklen / hash_len)
    derived = bytearray()

    for block_index in range(1, blocks + 1):
        u = hmac_sha256(password, salt + block_index.to_bytes(4, byteorder="big"))
        t = bytearray(u)

        for _ in range(1, iterations):
            u = hmac_sha256(password, u)
            for i, value in enumerate(u):
                t[i] ^= value

        derived.extend(t)

    return bytes(derived[:dklen])


def constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

