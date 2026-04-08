"""Benchmark helpers for algorithm comparison."""

from __future__ import annotations

import time
from statistics import mean
from typing import Dict

from crypto_algorithms import decrypt_message, encrypt_message
from hash_algorithms import sha256_hex
from rsa_algorithms import generate_rsa_keypair, rsa_decrypt, rsa_encrypt


def _avg_ms(samples):
    return round(mean(samples) * 1000, 3)


def run_benchmarks(sample_message: str) -> Dict[str, float]:
    encrypt_times = []
    decrypt_times = []
    hash_times = []

    for _ in range(3):
        start = time.perf_counter()
        encrypted = encrypt_message(sample_message, password="benchmark", demo_mode=False)
        encrypt_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        decrypt_message(
            ciphertext_hex=encrypted["cipher"],
            nonce=encrypted["nonce"],
            salt_hex=encrypted["salt"],
            password="benchmark",
            iterations=int(encrypted["iterations"]),
            demo_mode=False,
        )
        decrypt_times.append(time.perf_counter() - start)

        start = time.perf_counter()
        sha256_hex(sample_message.encode("utf-8"))
        hash_times.append(time.perf_counter() - start)

    start = time.perf_counter()
    keypair = generate_rsa_keypair(bits=256)
    rsa_keygen_time = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    rsa_cipher = rsa_encrypt(sample_message, keypair["e"], keypair["n"])
    rsa_encrypt_time = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    rsa_decrypt(rsa_cipher, keypair["d"], keypair["n"])
    rsa_decrypt_time = (time.perf_counter() - start) * 1000

    return {
        "hybrid_encrypt_ms": _avg_ms(encrypt_times),
        "hybrid_decrypt_ms": _avg_ms(decrypt_times),
        "sha256_ms": _avg_ms(hash_times),
        "rsa_keygen_ms": round(rsa_keygen_time, 3),
        "rsa_encrypt_ms": round(rsa_encrypt_time, 3),
        "rsa_decrypt_ms": round(rsa_decrypt_time, 3),
    }

