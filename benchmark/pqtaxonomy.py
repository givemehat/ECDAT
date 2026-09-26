"""Quantum-vulnerability taxonomy shared by the annotator and the harness.

This module is the *definition* of what "quantum-vulnerable cryptographic use" means for
this benchmark. It is deliberately separate from `engine/scanner.py`: the labels must not be
derived from the detector's own rule table, or the benchmark would be measuring the detector
against itself.

Two break models, matching the stance documented in `engine/mosca.py`
(`quantum_break_model`) but re-derived here from the published literature rather than imported:

  shor     -- a sufficiently large quantum computer running Shor's algorithm recovers the
              secret key / breaks the signature outright, retroactively (harvest-now-decrypt-later).
              Applies to every public-key primitive: RSA, DSA, DH, ECDH, ECDSA, EdDSA, ElGamal.
  grover   -- Grover's algorithm gives a quadratic speed-up only. Effective security is halved
              (AES-256 -> 128 bits). NOT retroactive: a ciphertext recorded today is not made
              readable by the arrival of a CRQC. This is why ECDAT refuses to apply Mosca's
              inequality to symmetric primitives.

import re  # noqa: E402


Nothing else is labelled: a PRNG (`SecureRandom`, `random`), a keystore container format
(`JKS`), an IV, a salt, a PBKDF parameter object and a password are all *not* quantum-vulnerable
primitives, and a line that merely operates on a primitive chosen elsewhere names no primitive.
"""

import re

SHOR = "shor"
GROVER = "grover"
NOT_AFFECTED = "not-affected"

# ---------------------------------------------------------------------------------------------
# Public-key primitives. Shor-broken.
# ---------------------------------------------------------------------------------------------
SHOR_TOKENS = (
    "RSA", "DSA", "DSS", "DH", "DIFFIE", "DIFFIE-HELLMAN", "ECDH", "ECDSA", "EDDSA", "ECNR",
    "ED25519", "ED448", "X25519", "X448", "CURVE25519", "ELGAMAL", "SECP256R1",
    "PRIME256V1", "SECP384R1", "SECP521R1", "NISTP256", "NISTP384", "NISTP521",
)

# ---------------------------------------------------------------------------------------------
# Symmetric ciphers, hashes and MACs. Grover-weakened.
# ---------------------------------------------------------------------------------------------
GROVER_TOKENS = (
    "AES", "DES", "DESEDE", "3DES", "BLOWFISH", "RC2", "RC4", "IDEA", "CAMELLIA", "ARIA",
    "CHACHA20", "CHACHA", "SALSA20", "SERPENT", "TWOFISH", "SM4",
    "MD2", "MD4", "MD5", "SHA1", "SHA-1", "SHA", "HMAC", "RIPEMD", "SKEIN", "BLAKE",
)

# Tokens that look like crypto but are explicitly NOT primitives, and must never be labelled.
# Kept as a documented negative list so the annotator's exclusions are auditable.
NOT_PRIMITIVES = (
    "JKS", "PKCS12", "P12", "BKS", "KEYSTORE", "UTF-8", "HTTP", "HTTPS", "TLS", "SSL",
)


def _norm(token):
    return str(token).upper().replace("_", "-")


def classify(token):
    """Return (primitive_name, break_model) for an algorithm token.

    `token` is a single algorithm word or a JCA transformation string such as
    "DES/ECB/PKCS5Padding"; only the leading component names the primitive.

    Matching is PREFIX-FIRST. A plain substring test would classify "ecdh-sha2-nistp256" as
    Diffie-Hellman (because "DH" is a substring) and "hmac-md5" as MD5, both of which are
    wrong labels. Only when no token matches at the start does a delimited substring test run,
    which is what lets "ssh-ed25519" resolve to Ed25519.
    """
    if not token:
        return None, NOT_AFFECTED
    # A JCA transformation is "ALG/MODE/PADDING" -- the primitive is the first component.
    head = _norm(str(token).split("/")[0]).strip()
    if not head:
        return None, NOT_AFFECTED
    if head in NOT_PRIMITIVES:
        return None, NOT_AFFECTED

    for tokens, model in ((SHOR_TOKENS, SHOR), (GROVER_TOKENS, GROVER)):
        by_length = sorted(tokens, key=len, reverse=True)
        for t in by_length:                                   # 1. prefix match
            if head.startswith(_norm(t)):
                return _canonical(head, t), model
        for t in by_length:                                   # 2. delimited substring match
            pat = _norm(t) if len(t) > 3 else r"(?<![A-Z0-9])%s(?![A-Z0-9])" % _norm(t)
            if re.search(pat, head):
                return _canonical(head, t), model
    return None, NOT_AFFECTED



def _canonical(head, token):
    """Normalise a matched token to a stable, readable primitive name for the label file."""
    t = _norm(token)
    explicit = {
        "RSA": "RSA", "DSA": "DSA", "DH": "Diffie-Hellman",
        "DIFFIE-HELLMAN": "Diffie-Hellman", "DIFFIE": "Diffie-Hellman",
        "ECDH": "ECDH", "ECDSA": "ECDSA", "EDDSA": "EdDSA", "ECNR": "ECNR",
        "ED25519": "Ed25519", "ED448": "Ed448",
        "X25519": "X25519", "X448": "X448", "CURVE25519": "Curve25519",
        "ELGAMAL": "ElGamal", "SECP256R1": "secp256r1", "PRIME256V1": "secp256r1",
        "SECP384R1": "secp384r1", "SECP521R1": "secp521r1",
        "AES": "AES", "DES": "DES", "DESEDE": "3DES", "3DES": "3DES",
        "BLOWFISH": "Blowfish", "RC2": "RC2", "RC4": "RC4", "IDEA": "IDEA",
        "CAMELLIA": "Camellia", "ARIA": "ARIA", "CHACHA20": "ChaCha20",
        "CHACHA": "ChaCha20", "SALSA20": "Salsa20", "SM4": "SM4",
        "MD2": "MD2", "MD4": "MD4", "MD5": "MD5",
        "HMAC": "HMAC", "RIPEMD": "RIPEMD", "SKEIN": "Skein", "BLAKE": "BLAKE",
    }
    if t in explicit:
        return explicit[t]
    if t in ("SHA", "SHA1", "SHA-1"):
        # Keep the concrete digest: SHA-1 and SHA-256 are different labels.
        return head if head.startswith("SHA-") else "SHA-1"
    return head


