"""Handwritten Diffie-Hellman key exchange simulation."""

from __future__ import annotations

import random
from typing import Dict


# RFC 3526 group 14 prime (2048-bit), used here for simulation.
DEFAULT_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
DEFAULT_G = 2


def generate_private_key(bits: int = 256) -> int:
    return random.getrandbits(bits) | 1


def generate_public_key(private_key: int, p: int = DEFAULT_P, g: int = DEFAULT_G) -> int:
    return pow(g, private_key, p)


def compute_shared_secret(peer_public_key: int, private_key: int, p: int = DEFAULT_P) -> int:
    return pow(peer_public_key, private_key, p)


def simulate_key_exchange(p: int = DEFAULT_P, g: int = DEFAULT_G) -> Dict[str, str]:
    private_a = generate_private_key()
    private_b = generate_private_key()

    public_a = generate_public_key(private_a, p, g)
    public_b = generate_public_key(private_b, p, g)

    shared_a = compute_shared_secret(public_b, private_a, p)
    shared_b = compute_shared_secret(public_a, private_b, p)

    return {
        "p": str(p),
        "g": str(g),
        "alice_public": str(public_a),
        "bob_public": str(public_b),
        "alice_shared": hex(shared_a),
        "bob_shared": hex(shared_b),
        "match": shared_a == shared_b,
    }

