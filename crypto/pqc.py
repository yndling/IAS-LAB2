"""Post-quantum KEM primitives wrappers.

This module demonstrates usage of lattice-based algorithms via the
``pqcrypto`` package.  It currently exposes a thin API for two of the
popular candidate algorithms, Kyber (CRYSTALS-Kyber) and NTRU.  These
are key-encapsulation mechanisms (KEMs) which provide a simple way to
exchange a shared secret securely over an untrusted channel.

The wrappers keep the demonstration script free of library-specific
imports; the higher-level comments in ``encryption_compare.py`` explain
security considerations.
"""

from typing import Tuple

# the ``pqcrypto`` package provides Python bindings for a variety of
# post-quantum primitives.  make sure it's installed in your environment
# (``pip install pqcrypto``).

try:
    from pqcrypto.kem import kyber1024, ntru_hps4096821
except ImportError:  # pragma: no cover - simply informs the user if missing
    kyber1024 = None
    ntru_hps4096821 = None


def kyber_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, secret_key) for Kyber-1024 KEM."""
    if kyber1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return kyber1024.generate_keypair()


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret under ``public_key``.

    Returns ``(ciphertext, shared_secret)`` where the secret is 32 bytes
    (the algorithm's chosen size).  The ciphertext is sent to the owner
    of the corresponding secret key.
    """
    if kyber1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return kyber1024.encapsulate(public_key)


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Recover the shared secret from ``ciphertext`` using ``secret_key``."""
    if kyber1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return kyber1024.decapsulate(ciphertext, secret_key)


def ntru_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, secret_key) for NTRU-HPS-4096821 KEM."""
    if ntru_hps4096821 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return ntru_hps4096821.generate_keypair()


def ntru_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret under an NTRU public key."""
    if ntru_hps4096821 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return ntru_hps4096821.encapsulate(public_key)


def ntru_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an NTRU ciphertext and return the shared secret."""
    if ntru_hps4096821 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return ntru_hps4096821.decapsulate(ciphertext, secret_key)
