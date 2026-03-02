"""High-level demonstration script comparing ChaCha20 and AES-GCM.

The :mod:`crypto` package in the same directory implements the
underlying algorithms.  This top-level script generates random keys,
performs a few encryption/decryption operations to verify correctness,
measures rough performance and prints a handful of security notes.  An
avant-garde ECC hybrid example is included simply to show how these
symmetric primitives are used in practice.
"""

import os

# note: the following modules live inside the local ``crypto`` package
# that accompanies this demo.  their contents are simple wrappers around
# ``cryptography`` but the segmentation keeps the demo script clean.
from crypto.ciphers import (
    chacha20_encrypt,
    chacha20_decrypt,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)
from crypto.ecc import generate_ecc_keypair, ec_encrypt, ec_decrypt
from crypto.utils import benchmark
from crypto.homomorphic import (
    generate_paillier_keypair,
    paillier_encrypt,
    paillier_decrypt,
    paillier_add,
    paillier_mul_const,
)
from crypto.tls_demo import start_tls_server, tls_client
from crypto.zkp import schnorr_generate_keys, schnorr_prove, schnorr_verify
from crypto.pqc import (
    kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    ntru_keypair,
    ntru_encapsulate,
    ntru_decapsulate,
)



def main():
    # ------------------------------------------------------------------
    # sample data and random keys
    # ------------------------------------------------------------------
    message = b"The quick brown fox jumps over the lazy dog" * 1024
    chacha_key = os.urandom(32)           # 256‑bit key for ChaCha20
    aes_key = os.urandom(32)              # AES-256 key for GCM

    # ------------------------------------------------------------------
    # demonstrate a hybrid ECC encryption flow (ECDH + AES-GCM)
    # ------------------------------------------------------------------
    print("\nECC hybrid encryption demo using NIST P-384 curve")
    priv, pub = generate_ecc_keypair()

    # encrypt with recipient's public key and then decrypt using private
    eph, nonce_e, ct_e, tag_e = ec_encrypt(pub, message)
    plaintext = ec_decrypt(priv, eph, nonce_e, ct_e, tag_e)
    assert plaintext == message, "ECC hybrid decryption produced wrong value"
    print("  ECC hybrid encryption succeeded (ecdhe + aes-gcm)")

    print("\n(You can replicate the long-term key steps with openssl as shown below)")
    print("  # generate private key")
    print("  openssl ecparam -name secp384r1 -genkey -noout -out priv.pem")
    print("  # extract public key")
    print("  openssl ec -in priv.pem -pubout -out pub.pem")

    # ------------------------------------------------------------------
    # symmetric algorithm correctness checks
    # ------------------------------------------------------------------
    nonce_c, ciphertext_c = chacha20_encrypt(chacha_key, message)
    assert chacha20_decrypt(chacha_key, nonce_c, ciphertext_c) == message

    nonce_a, ciphertext_a, tag_a = aes_gcm_encrypt(aes_key, message)
    assert aes_gcm_decrypt(aes_key, nonce_a, ciphertext_a, tag_a) == message

    # ------------------------------------------------------------------
    # performance comparison (rough)
    # ------------------------------------------------------------------
    chacha_time = benchmark(chacha20_encrypt, chacha_key, message)
    aes_time = benchmark(aes_gcm_encrypt, aes_key, message)

    print("Performance (average per operation):")
    print(f"  ChaCha20 encrypt: {chacha_time*1000:.3f} ms")
    print(f"  AES-GCM encrypt: {aes_time*1000:.3f} ms")
    print()

    # ------------------------------------------------------------------
    # brief security notes
    # ------------------------------------------------------------------
    print("Security notes:")
    print(" - ChaCha20 is a stream cipher; it guarantees confidentiality but" \
          " has no built-in integrity/fauthentication.  In practice it is" \
          " paired with Poly1305 (ChaCha20-Poly1305) for an AEAD construction.")
    print(" - AES-GCM is an authenticated cipher mode: it provides both" \
          " confidentiality and integrity in a single primitive.  Reusing a" \
          " nonce with either algorithm (ChaCha20-Poly1305 or AES-GCM)" \
          " completely breaks security and must be avoided.")

    # ------------------------------------------------------------------
    # post‑quantum key‑encapsulation demonstration
    # ------------------------------------------------------------------
    print("\nPost-quantum KEM demonstration (Kyber & NTRU)")
    try:
        # Kyber example
        pub_k, priv_k = kyber_keypair()
        ct_k, ss1 = kyber_encapsulate(pub_k)
        ss2 = kyber_decapsulate(priv_k, ct_k)
        assert ss1 == ss2
        print("  Kyber key exchange succeeded, shared secret size", len(ss1))

        # NTRU example
        pub_n, priv_n = ntru_keypair()
        ct_n, ss3 = ntru_encapsulate(pub_n)
        ss4 = ntru_decapsulate(priv_n, ct_n)
        assert ss3 == ss4
        print("  NTRU key exchange succeeded, shared secret size", len(ss3))

        print("  (requires 'pqcrypto' package: pip install pqcrypto)")

        # security discussion
        print()
        print("Post-quantum security notes:")
        print(" - Kyber (a lattice-based KEM) and NTRU are believed resistant" \
              " to quantum attacks such as Shor's algorithm.")
        print(" - These algorithms output a shared symmetric key; they are not" \
              " direct drop-in replacements for symmetric encryption modes." \
              " Instead, use them to agree on a key and then use AES-GCM" \
              " or ChaCha20-Poly1305 for data confidentiality.")
        print(" - The security proofs for lattice schemes assume certain" \
              " hard problems like LWE/NTRU are intractable even for" \
              " quantum adversaries.  Standardization efforts (e.g., NIST")
        print("   reflect current confidence but research is ongoing.")
    except ImportError as e:
        print("  post-quantum demo skipped; missing dependency:", e)

    # ------------------------------------------------------------------
    # homomorphic encryption demonstration (Paillier)
    # ------------------------------------------------------------------
    print("\nHomomorphic encryption demo (Paillier)")
    try:
        pub_h, priv_h = generate_paillier_keypair()
        # encrypt some integers
        c1 = paillier_encrypt(pub_h, 42)
        c2 = paillier_encrypt(pub_h, 100)
        # perform operations without decrypting
        sum_cipher = paillier_add(c1, c2)
        doubled = paillier_mul_const(c1, 2)
        # decrypt results
        assert paillier_decrypt(priv_h, sum_cipher) == 142
        assert paillier_decrypt(priv_h, doubled) == 84
        print("  Paillier homomorphic addition and scalar multiplication succeeded")
        print("  (requires 'phe' library: pip install phe)")
        print("  -> 42 + 100 =", paillier_decrypt(priv_h, sum_cipher))
        print("  -> 42 * 2 =", paillier_decrypt(priv_h, doubled))
        print()
        print("Homomorphic notes:")
        print(" - Paillier supports addition of ciphertexts and multiplication by a" \
              " public constant.  It is additive homomorphic, not fully" \
              " homomorphic.  Executing arbitrary functions requires more" \
              " advanced schemes like BFV or CKKS.")
        print(" - All operations were done on encrypted data; the private key was" \
              " only used for final decryption.  This property enables" \
              " computation on confidential data without leakage.")
    except ImportError as e:
        print("  homomorphic demo skipped; missing dependency:", e)

    # ------------------------------------------------------------------
    # TLS handshake demonstration
    # ------------------------------------------------------------------
    print("\nTLS 1.3 handshake demo (local server/client)")
    thread = start_tls_server()
    response = tls_client()
    print("  client received:", response)
    print("  (run Wireshark and filter 'tls' while this runs to inspect packets)\n")
    print("TLS notes:")
    print(" - the server above is configured to allow TLS 1.3 only and uses a" \
          " temporary self-signed cert.  In practice, manage certificates and" \
          " use a robust server implementation.")
    print(" - you can also perform the handshake manually with openssl:\n" \
          "   openssl s_server -cert server.pem -key server.key -tls1_3 &\n" \
          "   openssl s_client -connect 127.0.0.1:8443 -tls1_3")

    # ------------------------------------------------------------------
    # zero-knowledge proof demonstration
    # ------------------------------------------------------------------
    print("\nZero-knowledge proof (Schnorr) demo")
    priv_key, pub_key = schnorr_generate_keys()
    proof = schnorr_prove(priv_key, pub_key)
    valid = schnorr_verify(pub_key, proof)
    print(f"  proof verification result: {valid}")
    print("ZKP notes:")
    print(" - the Schnorr protocol lets a prover show knowledge of a secret" \
          " scalar without revealing it.  This code uses NIST P-256 curve." \
          " The verification function above is a stub and always returns True" \
          " for simplicity; a real implementation would perform point math.")


if __name__ == "__main__":
    main()
