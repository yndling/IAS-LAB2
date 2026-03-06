"""Post-quantum KEM primitives wrappers.

This module demonstrates usage of lattice-based algorithms via the
``pqcrypto`` package.  It currently exposes a thin API for two of the
popular candidate algorithms, ML-KEM (formerly Kyber) and HQC.  These
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
# Note: The old kyber1024 has been renamed to ml_kem_* in newer versions
# NTRU is no longer available, replaced by HQC

_pqc_available = False

try:
    from pqcrypto.kem import ml_kem_1024
    _pqc_available = True
except ImportError:
    ml_kem_1024 = None

try:
    from pqcrypto.kem import hqc_256
except ImportError:
    hqc_256 = None


def kyber_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, secret_key) for ML-KEM-1024 (Kyber-1024) KEM."""
    if ml_kem_1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return ml_kem_1024.generate_keypair()


def kyber_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret under ``public_key``.

    Returns ``(ciphertext, shared_secret)`` where the secret is 32 bytes
    (the algorithm's chosen size).  The ciphertext is sent to the owner
    of the corresponding secret key.
    """
    if ml_kem_1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    # Note: pqcrypto uses encrypt/decrypt instead of encapsulate/decapsulate
    return ml_kem_1024.encrypt(public_key)


def kyber_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Recover the shared secret from ``ciphertext`` using ``secret_key``."""
    if ml_kem_1024 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    # Note: pqcrypto has parameter order bug - decrypt expects (secret_key, ciphertext) but validates wrong
    # Workaround: swap the order as verified to work
    return ml_kem_1024.decrypt(secret_key, ciphertext)


def ntru_keypair() -> Tuple[bytes, bytes]:
    """Return (public_key, secret_key) for HQC-256 KEM (post-quantum alternative to NTRU).
    
    Note: NTRU is no longer available in pqcrypto 0.4.0, replaced by HQC.
    """
    if hqc_256 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    return hqc_256.generate_keypair()


def ntru_encapsulate(public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret under an HQC public key (post-quantum alternative to NTRU)."""
    if hqc_256 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    # Note: pqcrypto uses encrypt/decrypt instead of encapsulate/decapsulate
    return hqc_256.encrypt(public_key)


def ntru_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """Decapsulate an HQC ciphertext and return the shared secret."""
    if hqc_256 is None:
        raise ImportError("pqcrypto not available; install with 'pip install pqcrypto'")
    # Note: pqcrypto has parameter order bug - same as ML-KEM
    return hqc_256.decrypt(secret_key, ciphertext)
