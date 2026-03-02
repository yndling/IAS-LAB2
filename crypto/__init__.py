# crypto package init
# This package provides simple cryptographic building blocks used by
# the demonstration script in encryption_compare.py.
# It exposes implementations of symmetric ciphers, an ECC hybrid wrapper
# and a small benchmarking helper.

from .ciphers import (
    chacha20_encrypt,
    chacha20_decrypt,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
)
from .ecc import (
    generate_ecc_keypair,
    ec_encrypt,
    ec_decrypt,
)
from .pqc import (
    kyber_keypair,
    kyber_encapsulate,
    kyber_decapsulate,
    ntru_keypair,
    ntru_encapsulate,
    ntru_decapsulate,
)
from .homomorphic import (
    generate_paillier_keypair,
    paillier_encrypt,
    paillier_decrypt,
    paillier_add,
    paillier_mul_const,
)
from .tls_demo import (
    start_tls_server,
    tls_client,
)
from .zkp import (
    schnorr_generate_keys,
    schnorr_prove,
    schnorr_verify,
)
from .utils import benchmark
