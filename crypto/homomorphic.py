"""Simple Paillier homomorphic encryption wrappers.

This module depends on the ``phe`` library ("Python Homomorphic Encryption").
Install with ``pip install phe``.  It provides a basic Paillier
implementation allowing addition and scalar multiplication on ciphertexts
without decryption.

The wrappers mirror the API of the other crypto helpers in this project
and are used by the top-level demo script to show homomorphic operations.
"""

from typing import Tuple

try:
    import phe
except ImportError:  # pragma: no cover
    phe = None


def generate_paillier_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
    """Return (public_key, private_key) serialized to bytes."""
    if phe is None:
        raise ImportError("phe library not installed; pip install phe")
    pub, priv = phe.generate_paillier_keypair(n_length=bits)
    return pub, priv


def paillier_encrypt(public_key, value: int):
    """Encrypt an integer using Paillier.  Returns a ciphertext object."""
    if phe is None:
        raise ImportError("phe library not installed; pip install phe")
    return public_key.encrypt(value)


def paillier_decrypt(private_key, ciphertext):
    """Decrypt a Paillier ciphertext back to an integer."""
    if phe is None:
        raise ImportError("phe library not installed; pip install phe")
    return private_key.decrypt(ciphertext)


def paillier_add(c1, c2):
    """Homomorphically add two ciphertexts (returning a new ciphertext)."""
    return c1 + c2


def paillier_mul_const(ciphertext, constant: int):
    """Homomorphically multiply ciphertext by a public constant."""
    return ciphertext * constant
