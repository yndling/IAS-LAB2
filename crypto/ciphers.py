"""Symmetric cipher helpers for ChaCha20 and AES-GCM.

This module provides a minimal wrapper around the `cryptography` library
so that the main demo script can focus on high-level behaviour and
performance comparison.

ChaCha20 is implemented as a *pure* stream cipher (no authentication
built in).  When integrity is desired it must be paired with Poly1305
or another MAC; the demo script prints a note explaining that.

AES-GCM is used via the high-level Aead API which already combines
confidentiality and integrity.

The helpers below return and accept separate nonces, ciphertexts and
authentication tags to make the differences clear.
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# ChaCha20 stream cipher (no authentication)
# ---------------------------------------------------------------------------

def chacha20_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt ``plaintext`` using ChaCha20 and return (nonce, ciphertext).

    The provided ``key`` must be 32 bytes (256 bits).  A fresh 16‑byte
    nonce is generated for each operation.  The caller is responsible for
    storing/transmitting the nonce alongside the ciphertext.
    ``cryptography`` exposes a low‑level implementation of ChaCha20 that
    does not perform authentication.
    """

    # ChaCha20 in the `cryptography` library expects a 16‑byte nonce.
    nonce = os.urandom(16)
    algo = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algo, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return nonce, ciphertext


def chacha20_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext previously produced by :func:`chacha20_encrypt`.

    The same key and nonce used during encryption must be supplied.  No
    integrity checks are performed, so a corrupted ciphertext may decrypt
    to garbage without error.
    """

    algo = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algo, mode=None, backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


# ---------------------------------------------------------------------------
# AES-GCM authenticated encryption
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> tuple[bytes, bytes, bytes]:
    """Encrypt ``plaintext`` with AES-GCM and return (nonce, ciphertext, tag).

    ``key`` must be 16, 24 or 32 bytes (AES-128/192/256).  A 12‑byte nonce
    is generated randomly.  ``aad`` may be used for associated data; it is
    authenticated but not encrypted.
    """

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    # the last 16 bytes of the output are the authentication tag
    return nonce, ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes | None = None) -> bytes:
    """Decrypt data previously encrypted with :func:`aes_gcm_encrypt`.

    This routine will verify the authentication tag and raise an
    exception if verification fails.
    """

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)
