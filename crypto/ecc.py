"""Simple hybrid ECC encryption helpers.

The implementation uses ECDH on the NIST P-384 curve to establish a
shared secret.  That secret is then stretched with HKDF-SHA256 to a
32-byte key, which is used with AES-GCM to provide authenticated
confidentiality of the payload.

This code is intentionally straightforward to keep the demo focused on
symmetric vs hybrid behavior rather than elliptic-curve details.
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_ecc_keypair():
    """Generate a fresh ECC key pair (private, public).

    Uses the NIST P-384 (secp384r1) curve as a reasonable compromise
    between security and performance.  The returned objects are
    ``cryptography`` key instances; serialization can be performed later
    if required.
    """

    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def _derive_key(shared_secret: bytes) -> bytes:
    """Run HKDF-SHA256 over the ECDH shared secret to obtain a 32-byte key."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ecdh-aes-gcm",
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


def ec_encrypt(public_key, plaintext: bytes) -> tuple:
    """Encrypt a message for ``public_key``.

    Returns ``(ephemeral_public, nonce, ciphertext, tag)``.  The ephemeral
    public key must be transmitted to the recipient so they can derive the
    same symmetric key and decrypt.
    """

    # generate ephemeral ECDH key pair
    eph_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    eph_public = eph_private.public_key()

    # perform ECDH to obtain shared secret
    shared = eph_private.exchange(ec.ECDH(), public_key)
    key = _derive_key(shared)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return eph_public, nonce, ciphertext_with_tag[:-16], ciphertext_with_tag[-16:]


def ec_decrypt(private_key, eph_public, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """Decrypt data produced by :func:`ec_encrypt`.

    ``private_key`` is the recipient's long-term key.  ``eph_public`` is
    the ephemeral public key sent along with the ciphertext.
    """

    shared = private_key.exchange(ec.ECDH(), eph_public)
    key = _derive_key(shared)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


# ---------------------------------------------------------------------------
# serialization helpers
# ---------------------------------------------------------------------------

def serialize_private_key(private_key) -> bytes:
    """Return a PEM-encoded representation of ``private_key``.

    No encryption is applied to the PEM blob; callers would normally
    write this out with restrictive file permissions.
    """

    from cryptography.hazmat.primitives import serialization

    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def serialize_public_key(public_key) -> bytes:
    """Return a PEM-encoded public key suitable for distribution."""

    from cryptography.hazmat.primitives import serialization

    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key(pem_data: bytes):
    """Load a PEM encoded private key.  No password is expected."""

    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_public_key(pem_data: bytes):
    """Load a PEM encoded public key."""

    from cryptography.hazmat.primitives import serialization

    return serialization.load_pem_public_key(pem_data, backend=default_backend())


def derive_shared_key(private_key, peer_public_key) -> bytes:
    """Perform ECDH and run the result through HKDF-SHA256.

    This mirrors the behaviour used by :func:`ec_encrypt`/``ec_decrypt``
    but is exposed separately for demonstration of pure key exchange.
    """

    shared = private_key.exchange(ec.ECDH(), peer_public_key)
    return _derive_key(shared)
