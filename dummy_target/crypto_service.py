import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

# RSA 2048 implementation
key = rsa.newkeys(2048)

# AES GCM for DB encryption
aesgcm = AESGCM(AESGCM.generate_key(bit_length=128))

# SHA256 Hashing
digest = hashes.Hash(hashes.SHA256())

