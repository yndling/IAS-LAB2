# Cryptographic Techniques - Usage Guide

This guide provides source code examples for all cryptographic techniques implemented in this project.

## Table of Contents
1. [Symmetric Encryption](#1-symmetric-encryption)
2. [ECC Hybrid Encryption](#2-ecc-hybrid-encryption)
3. [Post-Quantum Cryptography](#3-post-quantum-cryptography)
4. [Homomorphic Encryption](#4-homomorphic-encryption)
5. [TLS 1.3](#5-tls-13)
6. [Zero-Knowledge Proofs](#6-zero-knowledge-proofs)

---

## 1. Symmetric Encryption

### ChaCha20 (Stream Cipher)

```python
import os
from crypto.ciphers import chacha20_encrypt, chacha20_decrypt

# Generate a 256-bit (32 bytes) key
key = os.urandom(32)

# Message to encrypt
message = b"Hello, World!"

# Encrypt
nonce, ciphertext = chacha20_encrypt(key, message)

# Decrypt
plaintext = chacha20_decrypt(key, nonce, ciphertext)
assert plaintext == message
print("ChaCha20 encryption/decryption successful!")
```

**Note:** ChaCha20 does NOT provide authentication. For production use, pair with Poly1305 (ChaCha20-Poly1305).

### AES-GCM (Authenticated Encryption)

```python
import os
from crypto.ciphers import aes_gcm_encrypt, aes_gcm_decrypt

# Generate a 256-bit key
key = os.urandom(32)

message = b"Secret message"

# Encrypt (returns nonce, ciphertext, tag)
nonce, ciphertext, tag = aes_gcm_encrypt(key, message)

# Decrypt (verifies authentication tag automatically)
plaintext = aes_gcm_decrypt(key, nonce, ciphertext, tag)
assert plaintext == message
print("AES-GCM encryption/decryption successful!")
```

**Security Note:** NEVER reuse a nonce with the same key. This breaks security completely!

---

## 2. ECC Hybrid Encryption

### ECC Key Generation

```python
from crypto.ecc import generate_ecc_keypair

# Generate ECC keypair using NIST P-384 curve
private_key, public_key = generate_ecc_keypair()
print("ECC keypair generated successfully!")
```

### ECC Hybrid Encryption (ECDH + AES-GCM)

```python
import os
from crypto.ecc import generate_ecc_keypair, ec_encrypt, ec_decrypt

# Sender generates a message
message = b"Confidential message for recipient"

# Recipient generates keypair
recipient_private, recipient_public = generate_ecc_keypair()

# Sender encrypts message using recipient's public key
# Returns: (ephemeral_public_key, nonce, ciphertext, tag)
ephemeral_public, nonce, ciphertext, tag = ec_encrypt(recipient_public, message)

# Recipient decrypts using their private key and ephemeral public key
decrypted_message = ec_decrypt(
    recipient_private, 
    ephemeral_public, 
    nonce, 
    ciphertext, 
    tag
)

assert decrypted_message == message
print("ECC hybrid encryption successful!")
```

---

## 3. Post-Quantum Cryptography

### Kyber-1024 (ML-KEM) Key Encapsulation

```python
from crypto.pqc import kyber_keypair, kyber_encapsulate, kyber_decapsulate

# Generate Kyber-1024 keypair
public_key, secret_key = kyber_keypair()
print(f"Public key size: {len(public_key)} bytes")
print(f"Secret key size: {len(secret_key)} bytes")

# Sender encapsulates a shared secret using recipient's public key
# Returns: (ciphertext, shared_secret)
ciphertext, shared_secret = kyber_encapsulate(public_key)
print(f"Shared secret size: {len(shared_secret)} bytes")

# Recipient decapsulates to recover the same shared secret
recovered_secret = kyber_decapsulate(secret_key, ciphertext)

assert shared_secret == recovered_secret
print("Kyber key exchange successful!")
```

### HQC-256 (Post-Quantum Alternative to NTRU)

```python
from crypto.pqc import ntru_keypair, ntru_encapsulate, ntru_decapsulate

# Generate HQC-256 keypair
public_key, secret_key = ntru_keypair()

# Encapsulate
ciphertext, shared_secret = ntru_encapsulate(public_key)

# Decapsulate
recovered_secret = ntru_decapsulate(secret_key, ciphertext)

assert shared_secret == recovered_secret
print("HQC-256 key exchange successful!")
```

---

## 4. Homomorphic Encryption

### Paillier (Additive Homomorphic)

```python
from crypto.homomorphic import (
    generate_paillier_keypair,
    paillier_encrypt,
    paillier_decrypt,
    paillier_add,
    paillier_mul_const
)

# Generate Paillier keypair
public_key, private_key = generate_paillier_keypair(bits=2048)

# Encrypt integers
c1 = paillier_encrypt(public_key, 42)
c2 = paillier_encrypt(public_key, 100)

# Homomorphic addition: E(42) + E(100) = E(142)
c_sum = paillier_add(c1, c2)
result_sum = paillier_decrypt(private_key, c_sum)
print(f"42 + 100 = {result_sum}")  # Output: 142

# Homomorphic scalar multiplication: E(42) * 2 = E(84)
c_doubled = paillier_mul_const(c1, 2)
result_doubled = paillier_decrypt(private_key, c_doubled)
print(f"42 * 2 = {result_doubled}")  # Output: 84

# Note: Paillier is ADDITIVE only, not fully homomorphic
# Cannot multiply two ciphertexts: E(a) * E(b) != E(a*b)
```

---

## 5. TLS 1.3

### TLS Server and Client Demo

```python
# Server side (in a separate process/thread)
from crypto.tls_demo import start_tls_server

# Start TLS 1.3 server on localhost:8443
server_thread = start_tls_server(
    host='127.0.0.1',
    port=8443,
    certfile='server.pem',
    keyfile='server.key'
)

# Client side (in same or different process)
from crypto.tls_demo import tls_client

# Connect and receive response
response = tls_client(
    host='127.0.0.1',
    port=8443,
    cafile=None  # Set to 'server.pem' to verify certificate
)
print(f"Client received: {response}")
```

**Manual Testing with OpenSSL:**
```bash
# Terminal 1: Start server
openssl s_server -cert server.pem -key server.key -tls1_3

# Terminal 2: Connect client
openssl s_client -connect 127.0.0.1:8443 -tls1_3
```

---

## 6. Zero-Knowledge Proofs

### Schnorr Protocol

```python
from crypto.zkp import schnorr_generate_keys, schnorr_prove, schnorr_verify

# Generate keypair
private_key, public_key = schnorr_generate_keys()

# Prover creates a proof of knowledge of the private key
proof = schnorr_prove(private_key, public_key)

# Verifier checks the proof
is_valid = schnorr_verify(public_key, proof)
print(f"Proof verification: {is_valid}")  # True

# The proof demonstrates knowledge of the private key
# without revealing the key itself
```

---

## Performance Benchmarking

```python
import os
from crypto.utils import benchmark
from crypto.ciphers import chacha20_encrypt, aes_gcm_encrypt

key = os.urandom(32)
message = b"Test message" * 100

# Benchmark ChaCha20 (1000 iterations)
chacha_time = benchmark(chacha20_encrypt, key, message, iterations=1000)
print(f"ChaCha20: {chacha_time*1000:.3f} ms per operation")

# Benchmark AES-GCM
aes_time = benchmark(aes_gcm_encrypt, key, message, iterations=1000)
print(f"AES-GCM: {aes_time*1000:.3f} ms per operation")
```

---

## Quick Reference

| Technique | File | Key Function |
|-----------|------|--------------|
| ChaCha20 | `crypto/ciphers.py` | `chacha20_encrypt()`, `chacha20_decrypt()` |
| AES-GCM | `crypto/ciphers.py` | `aes_gcm_encrypt()`, `aes_gcm_decrypt()` |
| ECC Hybrid | `crypto/ecc.py` | `ec_encrypt()`, `ec_decrypt()` |
| Kyber | `crypto/pqc.py` | `kyber_encapsulate()`, `kyber_decapsulate()` |
| HQC | `crypto/pqc.py` | `ntru_encapsulate()`, `ntru_decapsulate()` |
| Paillier | `crypto/homomorphic.py` | `paillier_encrypt()`, `paillier_decrypt()` |
| TLS 1.3 | `crypto/tls_demo.py` | `start_tls_server()`, `tls_client()` |
| Schnorr ZKP | `crypto/zkp.py` | `schnorr_prove()`, `schnorr_verify()` |

---

## Running the Full Demo

```bash
python encryption_compare.py
```

This will demonstrate all cryptographic techniques with performance metrics and security notes.

