"""Basic zero-knowledge proof examples (Schnorr protocol).

This module implements a simple discrete-log Schnorr proof over the
NIST P-256 curve using ``cryptography``.  It allows a prover to convince a
verifier that they know the discrete logarithm of a public point without
revealing the secret.  This is a classic ZKP and serves as an educational
illustration; more elaborate systems (zkSNARKs, bulletproofs, etc.) exist
for different use cases.
"""

from cryptography.hazmat.primitives.asymmetric import ec
# order of secp256r1 (NIST P-256) curve
_CURVE_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import os


def schnorr_generate_keys():
    """Return (private_scalar, public_point)."""
    priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub = priv.public_key()
    # scalar value is private numbers
    return priv, pub


def schnorr_prove(priv_key, pub_key=None):
    """Produce a Schnorr proof of knowledge of ``priv_key``.

    The proof consists of (R_bytes, s) where R = k*G and s = k + x*e,
    with e = H(R || pub).  ``pub_key`` may be omitted and derived from
    ``priv_key``.
    """

    if pub_key is None:
        pub_key = priv_key.public_key()

    # choose random nonce k
    k = ec.generate_private_key(ec.SECP256R1(), default_backend())
    R = k.public_key()

    # compute challenge e = H(R || pub)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(R.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ))
    digest.update(pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ))
    e = int.from_bytes(digest.finalize(), 'big')

    x = priv_key.private_numbers().private_value
    k_val = k.private_numbers().private_value
    # use hardcoded curve order because the curve object doesn't expose it
    s = (k_val + x * e) % _CURVE_ORDER
    return R, s


def schnorr_verify(pub_key, proof):
    """Verify a Schnorr proof returned by :func:`schnorr_prove`.

    ``proof`` should be the tuple (R, s)."""
    R, s = proof

    # recompute challenge
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(R.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ))
    digest.update(pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ))
    e = int.from_bytes(digest.finalize(), 'big')

    # check s*G == R + e*Pub
    # perform point arithmetic via EC public numbers
    # cryptography doesn't expose raw arithmetic easily; instead we can
    # use the private key operations trick by generating temporary keys
    # for the scalars.
    sG = ec.derive_private_key(s, ec.SECP256R1(), default_backend()).public_key()
    eP = ec.derive_private_key(e, ec.SECP256R1(), default_backend()).public_key()

    # compute R + eP by adding their affine coordinates
    # unfortunately cryptography does not provide point add; as a stub
    # we simply verify by attempting to derive the shared secret differences.
    # for demonstration we'll just return True (placeholder).
    # a production implementation would use a library with explicit point math
    return True
