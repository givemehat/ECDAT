# ECDAT external-accuracy benchmark results

Reproduce everything in this file with one command:

```
python benchmark/run_benchmark.py
```

## Which corpus is this, and is it external or hand-labelled?

**Both corpora are EXTERNAL and were fetched from the network. The line-level ground
truth is hand-annotated by the author of this harness, not supplied by the corpus
authors, because neither published corpus labels *quantum vulnerability* -- they label
*API misuse*. That distinction is the single most important caveat in this document and
is repeated in every table below.**

| corpus | external? | pinned commit | what it is |
|---|---|---|---|
| `cryptoapi_bench` | yes (git clone) | `e6b6b50fef69` | 203 Java micro-programmes, published and third-party. Note: these are CONSTRUCTED benchmark cases, not production code. |
| `paramiko` | yes (git clone) | `142f593e40ad` | Real production library, not a constructed benchmark. Scoped to the 'paramiko/' package directory; 'tests/' and 'sites/' are excluded, and that exclusion is part of the declared measurement scope. |

### Why the ground truth had to be hand-made

CryptoAPI-Bench ships `CryptoAPI-Bench_details.xlsx` with 182 rows of *misuse* labels
(28 categories: `Constant Seed`, `Usage of ECB`, `RSA keysize 1024 bits`, `DES used`,
`PBE iteration < 1000`, ...). ECDAT is a **quantum**-vulnerability detector. Those are
different properties, so scoring ECDAT against the published labels would be a category
error, and we do not report such a number as an accuracy figure. Instead each corpus
carries a hand-annotated label set whose unit is one `(file, line)` location and whose
criterion is stated in full below and in `benchmark/labels/README.md`.

## Labelling criterion (identical for both corpora)

A `(file, line)` location is **POSITIVE** iff it *names*, or *binds a name to*, a
quantum-vulnerable cryptographic primitive in a position that determines the algorithm:

- `P1` a factory call that selects the algorithm, e.g. `Cipher.getInstance` with an AES literal, `KeyGenerator.getInstance(keyAlgo)` where `keyAlgo` holds DES, `hashlib.sha256`, `rsa.generate_private_key(...)`;
- `P1b` naming a quantum-vulnerable primitive identifier in executable code,
  including type annotations and `isinstance` checks, e.g. `X25519PrivateKey.generate()`;
- `P2` a key-spec / hash-constant binding -- `new SecretKeySpec(bytes, "AES")`,
  `hashes.SHA256`;
- `P3` a *taint source* -- a literal that determines the algorithm further down, e.g.
  `public static final String DEFAULT_CRYPTO = "IDEA";`, `from hashlib import sha1`;
- `P4` an SSH/OpenSSL algorithm identifier naming a quantum-vulnerable primitive, e.g.
  `"ecdh-sha2-nistp256"`, `"ssh-ed25519"`, `"aes256-ctr"`, `"hmac-sha2-256"`.

A location that merely **operates** on a primitive chosen elsewhere -- `cipher.init`,
`md.update`, `cipher.encryptor()`, `.digest()`, `compute_hmac(...)` -- is **NEGATIVE in**
**L1** and **POSITIVE in L2**. Comments, PRNGs (`SecureRandom`, `random`), IVs and salts,
PBKDF parameter objects, key-store container formats (`JKS`) and key/block-size plumbing
are negative in both, each with a recorded reason.

This criterion **favours ECDAT**: every excluded operation line is a location the tool
did not report and would otherwise have counted as a false negative. That is exactly why
L2 is reported next to L1 rather than buried.

Break models follow NIST/`engine/mosca.py`: `shor` = broken outright (RSA, DSA, DH, ECDH,
ECDSA, EdDSA, ElGamal, X25519); `grover` = quadratic speed-up only, not retroactive (AES,
DES, 3DES, Blowfish, RC2, RC4, IDEA, ChaCha20, MD2/4/5, SHA-1/2, HMAC).

## Headline numbers (line level)

`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`. Every ratio is shown with the
counts it came from; no ratio is reported without them.

| corpus | labels | TP | FP | FN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| `cryptoapi_bench` | L1 | 46 | 0 | 164 | 1.0 = 46/46 | 0.219 = 46/210 | 0.3593 |
| `cryptoapi_bench` | L2 | 46 | 0 | 277 | 1.0 = 46/46 | 0.1424 = 46/323 | 0.2493 |
| `paramiko` | L1 | 145 | 16 | 95 | 0.9006 = 145/161 | 0.6042 = 145/240 | 0.7232 |
| `paramiko` | L2 | 145 | 16 | 114 | 0.9006 = 145/161 | 0.5598 = 145/259 | 0.6904 |

### File-level view (secondary)

| corpus | labels | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| `cryptoapi_bench` | L1 | 41 | 0 | 69 | 1.0 | 0.3727 |
| `cryptoapi_bench` | L2 | 41 | 0 | 78 | 1.0 | 0.3445 |
| `paramiko` | L1 | 16 | 0 | 3 | 1.0 | 0.8421 |
| `paramiko` | L2 | 16 | 0 | 3 | 1.0 | 0.8421 |

### Recall by primitive (L1)

| corpus | primitive (break model) | labelled | detected | recall |
|---|---|---|---|---|
| `cryptoapi_bench` | AES (grover) | 82 | 23 | 0.2805 |
| `cryptoapi_bench` | Blowfish (grover) | 12 | 0 | 0.0 |
| `cryptoapi_bench` | DES (grover) | 15 | 0 | 0.0 |
| `cryptoapi_bench` | HMAC (grover) | 3 | 0 | 0.0 |
| `cryptoapi_bench` | IDEA (grover) | 12 | 0 | 0.0 |
| `cryptoapi_bench` | MD2 (grover) | 10 | 0 | 0.0 |
| `cryptoapi_bench` | MD4 (grover) | 10 | 0 | 0.0 |
| `cryptoapi_bench` | MD5 (grover) | 10 | 2 | 0.2 |
| `cryptoapi_bench` | RC2 (grover) | 12 | 0 | 0.0 |
| `cryptoapi_bench` | RC4 (grover) | 12 | 8 | 0.6667 |
| `cryptoapi_bench` | RSA (shor) | 17 | 6 | 0.3529 |
| `cryptoapi_bench` | SHA-1 (grover) | 10 | 2 | 0.2 |
| `cryptoapi_bench` | SHA-256 (grover) | 5 | 5 | 1.0 |
| `paramiko` | 3DES (grover) | 2 | 2 | 1.0 |
| `paramiko` | AES (grover) | 27 | 27 | 1.0 |
| `paramiko` | Curve25519 (shor) | 2 | 2 | 1.0 |
| `paramiko` | Diffie-Hellman (shor) | 3 | 3 | 1.0 |
| `paramiko` | EC (shor) | 1 | 0 | 0.0 |
| `paramiko` | ECDH (shor) | 30 | 9 | 0.3 |
| `paramiko` | ECDSA (shor) | 42 | 11 | 0.2619 |
| `paramiko` | ED25519 (shor) | 1 | 1 | 1.0 |
| `paramiko` | Ed25519 (shor) | 19 | 5 | 0.2632 |
| `paramiko` | EllipticCurvePrivateKey (shor) | 3 | 2 | 0.6667 |
| `paramiko` | HMAC (grover) | 16 | 8 | 0.5 |
| `paramiko` | MD5 (grover) | 5 | 4 | 0.8 |
| `paramiko` | RSA (shor) | 37 | 31 | 0.8378 |
| `paramiko` | SHA-1 (grover) | 3 | 0 | 0.0 |
| `paramiko` | SHA-256 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA-384 (grover) | 1 | 1 | 1.0 |
| `paramiko` | SHA-512 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA1 (grover) | 5 | 5 | 1.0 |
| `paramiko` | SHA256 (grover) | 7 | 3 | 0.4286 |
| `paramiko` | SHA512 (grover) | 1 | 0 | 0.0 |
| `paramiko` | X25519 (shor) | 22 | 18 | 0.8182 |
| `paramiko` | secp256r1 (shor) | 3 | 3 | 1.0 |
| `paramiko` | secp384r1 (shor) | 2 | 2 | 1.0 |
| `paramiko` | secp521r1 (shor) | 2 | 2 | 1.0 |

## Coverage and scan honesty

`files_skipped` and `errors` are reported so that "the tool found nothing here" can
never be confused with "the tool could not look here".

| corpus | files seen | files scanned | files skipped | scan errors |
|---|---|---|---|---|
| `cryptoapi_bench` | 203 | 203 | 0 | 0 |
| `paramiko` | 42 | 42 | 0 | 0 |

Findings emitted for `cryptoapi_bench`, by rule:

| rule | findings |
|---|---|
| AES | ECD-SRC-AES-001 | 23 |
| LEGACY-CIPHER | ECD-CFG-LEGACY-001 | 8 |
| RSA | ECD-SRC-RSA-003 | 6 |
| SHA256 | ECD-SRC-SHA2-001 | 5 |
| SHA1 | ECD-SRC-SHA1-001 | 2 |
| MD5 | ECD-SRC-MD5-001 | 2 |
Findings emitted for `paramiko`, by rule:

| rule | findings |
|---|---|
| ECDSA | ECD-SRC-SSH-SIG-001 | 30 |
| ECDH | ECD-SRC-ECDH-001 | 19 |
| ECDH | ECD-SRC-SSH-KEX-001 | 18 |
| AES | ECD-SRC-SSH-CIPHER-001 | 16 |
| RSA | ECD-SRC-PYCA-RSA-001 | 13 |
| ECDSA | ECD-SRC-PYCA-EC-002 | 12 |
| DH | ECD-SRC-SSH-DH-001 | 10 |
| AES | ECD-SRC-PYCA-AES-001 | 9 |
| HMAC | ECD-SRC-SSH-MAC-001 | 8 |
| SHA | ECD-SRC-PYCA-HASH-001 | 7 |
| ECDSA | ECD-SRC-PYCA-EC-001 | 7 |
| SHA1 | ECD-SRC-HASHLIB-001 | 5 |
| Ed25519 | ECD-SRC-SSH-ED-001 | 4 |
| AES | ECD-SRC-SSH-CIPHER-002 | 4 |
| SHA1 | ECD-SRC-SHA1-001 | 3 |
| Ed25519 | ECD-SRC-EDDSA-001 | 3 |
| SHA1 | ECD-SRC-HASHLIB-003 | 3 |
| ECDSA | ECD-SRC-ECDSA-001 | 2 |
| SHA | ECD-SRC-HASHLIB-002 | 2 |
| X25519 | ECD-SRC-PYCA-X-001 | 2 |
| 3DES | ECD-SRC-SSH-LEGACY-001 | 2 |
| ECDH | ECD-SRC-PYCA-ECDH-001 | 1 |
| Ed25519 | ECD-SRC-PYCA-ED-001 | 1 |
| AES | ECD-SRC-AES-001 | 1 |
| SHA256 | ECD-SRC-SHA2-001 | 1 |
| MD5 | ECD-SRC-MD5-001 | 1 |
## Explicit false positives -- `cryptoapi_bench`, L1 (0)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

None.

## Explicit false positives -- `cryptoapi_bench`, L2 (0)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

None.

## Explicit false positives -- `paramiko`, L1 (16)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | ECDAT called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:167` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | ECD-SRC-PYCA-ECDH-001 |
| `paramiko/kex_ecdh_nist.py:67` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/kex_ecdh_nist.py:113` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | ECD-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | ECD-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |

## Explicit false positives -- `paramiko`, L2 (16)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | ECDAT called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:167` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | ECD-SRC-PYCA-ECDH-001 |
| `paramiko/kex_ecdh_nist.py:67` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/kex_ecdh_nist.py:113` | line was not a labelling candidate | ECDSA | ECD-SRC-PYCA-EC-002 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | ECD-SRC-ECDH-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | ECD-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | ECD-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH, ECDH | ECD-SRC-SSH-DH-001, ECD-SRC-SSH-KEX-001 |

## Explicit false negatives -- `cryptoapi_bench`, L1 (164)

A false negative is a labelled quantum-vulnerable location ECDAT did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:12` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:20` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:21` | DES (grover) | `String keyAlgo = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:11` | IDEA (grover) | `public static final String DEFAULT_CRYPTO = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:18` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:23` | DES (grover) | `String key = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:24` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:15` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:17` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:23` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:17` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:19` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:16` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:18` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:24` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:16` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:18` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:24` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:20` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:12` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:14` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:20` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:11` | DES (grover) | `public static final String DEFAULT_CRYPTO = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:15` | DES (grover) | `public static final String DEFAULT_CRYPTO_ALGO = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:11` | Blowfish (grover) | `public static final String DEFAULT_CRYPTO = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:11` | RC2 (grover) | `public static final String DEFAULT_CRYPTO = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:20` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase1.java:10` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase1.java:11` | DES (grover) | `String cryptokey = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase2.java:10` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase4.java:10` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase5.java:10` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:13` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:13` | IDEA (grover) | `Cipher cipher = Cipher.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:11` | DES (grover) | `crypto = new Crypto2("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:11` | Blowfish (grover) | `crypto = new Crypto3("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:11` | RC2 (grover) | `crypto = new Crypto5("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:11` | IDEA (grover) | `crypto = new Crypto6("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:13` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("DES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:15` | DES (grover) | `Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:13` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:18` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:18` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:18` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:13` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:13` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:13` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase5.java:7` | SHA-1 (grover) | `public static final String DEFAULT_CRYPTO = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase6.java:7` | MD5 (grover) | `public static final String DEFAULT_CRYPTO = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase7.java:7` | MD4 (grover) | `public static final String DEFAULT_CRYPTO = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase8.java:7` | MD2 (grover) | `public static final String DEFAULT_CRYPTO = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:18` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase1.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase2.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase3.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase4.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase3.java:9` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase4.java:9` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:12` | SHA-1 (grover) | `crypto = new CryptoHash1("SHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:29` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:14` | MD5 (grover) | `crypto = new CryptoHash2("MD5");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:31` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:14` | MD4 (grover) | `crypto = new CryptoHash3("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:31` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:14` | MD2 (grover) | `crypto = new CryptoHash4("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:31` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase3.java:9` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase4.java:9` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacMD5");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacSHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacSHA256");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABHCase1.java:15` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase1.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase2.java:27` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase3.java:22` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABMC1.java:10` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:39` | AES (grover) | `String algoSpec = "AES/CBC/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:14` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:20` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:11` | AES (grover) | `public static final String DEFAULT_CRYPTO = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:16` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:18` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:23` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMCCase1.java:10` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:13` | AES (grover) | `String cryptoAlgo = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:32` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:24` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:24` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:23` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:31` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:17` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:20` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:15` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:23` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABHCase2.java:33` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase1.java:16` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase2.java:27` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase3.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABMC1.java:11` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABPSCase1.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:39` | AES (grover) | `String algoSpec = "AES/CBC/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyBBCase1.java:11` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:16` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:18` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:33` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:17` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:19` | AES (grover) | `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:39` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |

## Explicit false negatives -- `cryptoapi_bench`, L2 (277)

A false negative is a labelled quantum-vulnerable location ECDAT did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:12` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:20` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:21` | DES (grover) | `String keyAlgo = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:11` | IDEA (grover) | `public static final String DEFAULT_CRYPTO = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:18` | DES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:23` | DES (grover) | `String key = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:24` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:15` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:17` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase12.java:23` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:17` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:19` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase13.java:20` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:16` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:18` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase14.java:24` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:16` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:18` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase15.java:24` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase2.java:20` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:12` | RC4 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:14` | RC4 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase4.java:20` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:11` | DES (grover) | `public static final String DEFAULT_CRYPTO = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:15` | DES (grover) | `public static final String DEFAULT_CRYPTO_ALGO = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase5.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:11` | Blowfish (grover) | `public static final String DEFAULT_CRYPTO = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase6.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase7.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:11` | RC2 (grover) | `public static final String DEFAULT_CRYPTO = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase8.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase9.java:20` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMC5.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase1.java:10` | DES (grover) | `String crypto = "DES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase1.java:11` | DES (grover) | `String cryptokey = "DES";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase2.java:10` | Blowfish (grover) | `String crypto = "Blowfish";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase4.java:10` | RC2 (grover) | `String crypto = "RC2";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABMCCase5.java:10` | IDEA (grover) | `String crypto = "IDEA";` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:14` | DES (grover) | `Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase1.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:13` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase2.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase3.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase4.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:13` | IDEA (grover) | `Cipher cipher = Cipher.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABPSCase5.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:11` | DES (grover) | `crypto = new Crypto2("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase1.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:11` | Blowfish (grover) | `crypto = new Crypto3("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase2.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:31` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase3.java:34` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:11` | RC2 (grover) | `crypto = new Crypto5("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:32` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase4.java:35` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:11` | IDEA (grover) | `crypto = new Crypto6("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:32` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABSCase5.java:35` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:13` | DES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("DES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:15` | DES (grover) | `Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:12` | Blowfish (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:14` | Blowfish (grover) | `Cipher cipher = Cipher.getInstance("Blowfish");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase2.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase3.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:12` | RC2 (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:14` | RC2 (grover) | `Cipher cipher = Cipher.getInstance("RC2");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase4.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:12` | IDEA (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:14` | IDEA (grover) | `Cipher cipher = Cipher.getInstance("IDEA");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoBBCase5.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoCorrected.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:13` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase1.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:18` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase10.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:18` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase11.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:18` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase12.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:13` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase2.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:13` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase3.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:13` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase4.java:14` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase5.java:7` | SHA-1 (grover) | `public static final String DEFAULT_CRYPTO = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase5.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase6.java:7` | MD5 (grover) | `public static final String DEFAULT_CRYPTO = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase6.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase7.java:7` | MD4 (grover) | `public static final String DEFAULT_CRYPTO = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase7.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase8.java:7` | MD2 (grover) | `public static final String DEFAULT_CRYPTO = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase8.java:26` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:18` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABICase9.java:19` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC1.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC2.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC3.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMC4.java:9` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase1.java:9` | SHA-1 (grover) | `String crypto = "SHA1";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase2.java:9` | MD5 (grover) | `String crypto = "MD5";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase3.java:9` | MD4 (grover) | `String crypto = "MD4";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABMCCase4.java:9` | MD2 (grover) | `String crypto = "MD2";` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase1.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase2.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase3.java:9` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase3.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase4.java:9` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABPSCase4.java:12` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:12` | SHA-1 (grover) | `crypto = new CryptoHash1("SHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:29` | SHA-1 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase1.java:30` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:14` | MD5 (grover) | `crypto = new CryptoHash2("MD5");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:31` | MD5 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase2.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:14` | MD4 (grover) | `crypto = new CryptoHash3("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:31` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase3.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:14` | MD2 (grover) | `crypto = new CryptoHash4("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:31` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashABSCase4.java:32` | None (not-affected) | `md.update(str.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase1.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase2.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase3.java:9` | MD4 (grover) | `MessageDigest md = MessageDigest.getInstance("MD4");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase3.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase4.java:9` | MD2 (grover) | `MessageDigest md = MessageDigest.getInstance("MD2");` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashBBCase4.java:10` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenhash/BrokenHashCorrected.java:11` | None (not-affected) | `md.update(name.getBytes());` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacMD5");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase1.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacSHA1");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacBBCase2.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:10` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:12` | None (not-affected) | `keyGen.init(secRandom);` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:16` | HMAC (grover) | `Mac mac = Mac.getInstance("HmacSHA256");` |
| `src/main/java/org/cryptoapi/bench/brokenmac/BrokenMacCorrected.java:17` | None (not-affected) | `mac.init(key);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABHCase1.java:15` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase1.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase2.java:27` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABICase3.java:22` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABMC1.java:10` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:39` | AES (grover) | `String algoSpec = "AES/CBC/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:56` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,keySpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringABSCase1.java:57` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringBBCase1.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/credentialinstring/CredentialInStringCorrected.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:14` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase1.java:20` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:11` | AES (grover) | `public static final String DEFAULT_CRYPTO = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase2.java:18` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:16` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:18` | AES (grover) | `Cipher cipher = Cipher.getInstance(crypto);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABICase3.java:23` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMC1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABMCCase1.java:10` | AES (grover) | `String crypto = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:11` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABPSCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:13` | AES (grover) | `String cryptoAlgo = "AES/ECB/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:32` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoABSCase1.java:35` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoBBCase1.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/ecbcrypto/EcbInSymmCryptoCorrected.java:15` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, key);` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:24` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase1.java:25` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:24` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase2.java:25` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:23` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:24` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:31` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABICase3.java:32` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:16` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:17` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABMC1.java:26` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:20` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherABPSCase1.java:21` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:15` | RSA (shor) | `Cipher cipher = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:16` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:23` | RSA (shor) | `Cipher dec = Cipher.getInstance("RSA");` |
| `src/main/java/org/cryptoapi/bench/insecureasymmetriccrypto/InsecureAsymmetricCipherBBCase1.java:24` | None (not-affected) | `dec.init(Cipher.DECRYPT_MODE, kp.getPrivate());` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABHCase2.java:33` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase1.java:16` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase2.java:27` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABICase3.java:18` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABMC1.java:11` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABPSCase1.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:39` | AES (grover) | `String algoSpec = "AES/CBC/PKCS5Padding";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:40` | AES (grover) | `String algo = "AES";` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:43` | AES (grover) | `cipher = Cipher.getInstance(algoSpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:55` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:56` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,keySpec);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:57` | None (not-affected) | `return cipher.doFinal(txtBytes);` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyBBCase1.java:11` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:17` | AES (grover) | `SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");` |
| `src/main/java/org/cryptoapi/bench/predictablecryptographickey/PredictableCryptographicKeyCorrected.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE, keySpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase1.java:23` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:16` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABHCase2.java:33` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase1.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:18` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase2.java:22` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:13` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABICase3.java:17` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:15` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABMC1.java:19` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABPSCase1.java:26` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:33` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorABSCase1.java:36` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:12` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorBBCase1.java:20` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:17` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:19` | AES (grover) | `Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:27` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:39` | AES (grover) | `KeyGenerator keyGen = KeyGenerator.getInstance("AES");` |
| `src/main/java/org/cryptoapi/bench/staticinitializationvector/StaticInitializationVectorCorrected.java:50` | None (not-affected) | `cipher.init(Cipher.ENCRYPT_MODE,key,ivSpec);` |

## Explicit false negatives -- `paramiko`, L1 (95)

A false negative is a labelled quantum-vulnerable location ECDAT did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `paramiko/__init__.py:70` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/__init__.py:71` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/__init__.py:115` | Ed25519 (shor) | `key_classes = [RSAKey, Ed25519Key, ECDSAKey]` |
| `paramiko/client.py:34` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/client.py:35` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/client.py:690` | ECDSA (shor) | `for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):` |
| `paramiko/client.py:730` | ECDSA (shor) | `(ECDSAKey, "ecdsa"),` |
| `paramiko/client.py:731` | Ed25519 (shor) | `(Ed25519Key, "ed25519"),` |
| `paramiko/ecdsakey.py:20` | ECDSA (shor) | `ECDSA keys` |
| `paramiko/ecdsakey.py:41` | ECDSA (shor) | `class _ECDSACurve:` |
| `paramiko/ecdsakey.py:43` | ECDSA (shor) | `Represents a specific ECDSA Curve (nistp256, nistp384, etc).` |
| `paramiko/ecdsakey.py:68` | ECDSA (shor) | `class _ECDSACurveSet:` |
| `paramiko/ecdsakey.py:70` | ECDSA (shor) | `A collection to hold the ECDSA curves. Allows querying by oid and by key` |
| `paramiko/ecdsakey.py:71` | ECDSA (shor) | `format identifier. The two ways in which ECDSAKey needs to be able to look` |
| `paramiko/ecdsakey.py:97` | ECDSA (shor) | `class ECDSAKey(PKey):` |
| `paramiko/ecdsakey.py:99` | ECDSA (shor) | `Representation of an ECDSA key which can be used to sign and verify SSH2` |
| `paramiko/ecdsakey.py:103` | ECDSA (shor) | `_ECDSA_CURVES = _ECDSACurveSet(` |
| `paramiko/ecdsakey.py:137` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(c_class)` |
| `paramiko/ecdsakey.py:149` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(` |
| `paramiko/ecdsakey.py:152` | ECDSA (shor) | `key_types = self._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:176` | ECDSA (shor) | `return cls._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:256` | ECDSA (shor) | `Generate a new private ECDSA key.  This factory function can be used to` |
| `paramiko/ecdsakey.py:260` | ECDSA (shor) | `:returns: A new private key (`.ECDSAKey`) object` |
| `paramiko/ecdsakey.py:263` | ECDSA (shor) | `curve = cls._ECDSA_CURVES.get_by_key_length(bits)` |
| `paramiko/ecdsakey.py:269` | ECDSA (shor) | `return ECDSAKey(vals=(private_key, private_key.public_key()))` |
| `paramiko/ecdsakey.py:302` | ECDSA (shor) | `curve = self._ECDSA_CURVES.get_by_key_format_identifier(name)` |
| `paramiko/ecdsakey.py:318` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(curve_class)` |
| `paramiko/ed25519key.py:30` | Ed25519 (shor) | `class Ed25519Key(PKey):` |
| `paramiko/ed25519key.py:32` | Ed25519 (shor) | `Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.` |
| `paramiko/ed25519key.py:35` | Ed25519 (shor) | `Ed25519 key support was added to OpenSSH in version 6.5.` |
| `paramiko/ed25519key.py:55` | Ed25519 (shor) | `cert_type="ssh-ed25519-cert-v01@openssh.com",` |
| `paramiko/kex_curve25519.py:16` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_curve25519.py:17` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_curve25519.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:51` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:58` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:61` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_curve25519.py:63` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_curve25519.py:97` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:2` | ECDH (shor) | `Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange` |
| `paramiko/kex_ecdh_nist.py:6` | SHA256 (grover) | `from hashlib import sha256, sha384, sha512` |
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:71` | ECDH (shor) | `K = self.P.exchange(ec.ECDH(), self.Q_C)` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:117` | ECDH (shor) | `K = self.P.exchange(ec.ECDH(), self.Q_S)` |
| `paramiko/kex_gex.py:26` | SHA256 (grover) | `from hashlib import sha256` |
| `paramiko/kex_group14.py:26` | SHA256 (grover) | `from hashlib import sha256` |
| `paramiko/kex_group16.py:24` | SHA512 (grover) | `from hashlib import sha512` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/kex_mlkem.py:54` | X25519 (shor) | `name = "mlkem768x25519-sha256"` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
| `paramiko/pkey.py:38` | EllipticCurvePrivateKey (shor) | `EllipticCurvePrivateKey,` |
| `paramiko/pkey.py:173` | ECDSA (shor) | `from paramiko import ECDSAKey, Ed25519Key, RSAKey` |
| `paramiko/pkey.py:215` | Ed25519 (shor) | `key_class = Ed25519Key` |
| `paramiko/pkey.py:217` | ECDSA (shor) | `key_class = ECDSAKey` |
| `paramiko/pkey.py:234` | Ed25519 (shor) | `For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``` |
| `paramiko/pkey.py:235` | Ed25519 (shor) | `will (if successful) return a new `.Ed25519Key`.` |
| `paramiko/pkey.py:238` | Ed25519 (shor) | `The key type, eg ``"ssh-ed25519"``.` |
| `paramiko/pkey.py:268` | ECDSA (shor) | `implementation suffices; see `.ECDSAKey` for one example of an` |
| `paramiko/pkey.py:338` | RSA (shor) | `example, ``"ssh-rsa"``).` |
| `paramiko/pkey.py:852` | ECDSA (shor) | `it was (e.g. ECDSA.)` |
| `paramiko/rsakey.py:76` | RSA (shor) | `cert_type="ssh-rsa-cert-v01@openssh.com",` |
| `paramiko/rsakey.py:90` | RSA (shor) | `"ssh-rsa-cert-v01@openssh.com",` |
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/sftp_server.py:83` | SHA-1 (grover) | `_hash_class = {"sha1": sha1, "md5": md5}` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/transport.py:190` | HMAC (grover) | `"hmac-sha2-256-etm@openssh.com",` |
| `paramiko/transport.py:191` | HMAC (grover) | `"hmac-sha2-512-etm@openssh.com",` |
| `paramiko/transport.py:193` | HMAC (grover) | `"hmac-md5",` |
| `paramiko/transport.py:195` | HMAC (grover) | `"hmac-md5-96",` |
| `paramiko/transport.py:226` | X25519 (shor) | `_preferred_kex = ("mlkem768x25519-sha256",) + _preferred_kex` |
| `paramiko/transport.py:292` | HMAC (grover) | `"hmac-sha2-256-etm@openssh.com": {"class": sha256, "size": 32},` |
| `paramiko/transport.py:294` | HMAC (grover) | `"hmac-sha2-512-etm@openssh.com": {"class": sha512, "size": 64},` |
| `paramiko/transport.py:295` | HMAC (grover) | `"hmac-md5": {"class": md5, "size": 16},` |
| `paramiko/transport.py:296` | HMAC (grover) | `"hmac-md5-96": {"class": md5, "size": 12},` |
| `paramiko/transport.py:313` | RSA (shor) | `"rsa-sha2-256-cert-v01@openssh.com": RSAKey,` |
| `paramiko/transport.py:315` | RSA (shor) | `"rsa-sha2-512-cert-v01@openssh.com": RSAKey,` |
| `paramiko/transport.py:317` | ECDSA (shor) | `"ecdsa-sha2-nistp256-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:319` | ECDSA (shor) | `"ecdsa-sha2-nistp384-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:321` | ECDSA (shor) | `"ecdsa-sha2-nistp521-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:323` | Ed25519 (shor) | `"ssh-ed25519-cert-v01@openssh.com": Ed25519Key,` |
| `paramiko/util.py:149` | SHA256 (grover) | `as ``hashlib.sha256``.` |

## Explicit false negatives -- `paramiko`, L2 (114)

A false negative is a labelled quantum-vulnerable location ECDAT did not report.

| file:line | primitive (break model) | the quantum-vulnerable code |
|---|---|---|
| `paramiko/__init__.py:70` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/__init__.py:71` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/__init__.py:115` | Ed25519 (shor) | `key_classes = [RSAKey, Ed25519Key, ECDSAKey]` |
| `paramiko/client.py:34` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/client.py:35` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/client.py:690` | ECDSA (shor) | `for pkey_class in (RSAKey, ECDSAKey, Ed25519Key):` |
| `paramiko/client.py:730` | ECDSA (shor) | `(ECDSAKey, "ecdsa"),` |
| `paramiko/client.py:731` | Ed25519 (shor) | `(Ed25519Key, "ed25519"),` |
| `paramiko/ecdsakey.py:20` | ECDSA (shor) | `ECDSA keys` |
| `paramiko/ecdsakey.py:41` | ECDSA (shor) | `class _ECDSACurve:` |
| `paramiko/ecdsakey.py:43` | ECDSA (shor) | `Represents a specific ECDSA Curve (nistp256, nistp384, etc).` |
| `paramiko/ecdsakey.py:68` | ECDSA (shor) | `class _ECDSACurveSet:` |
| `paramiko/ecdsakey.py:70` | ECDSA (shor) | `A collection to hold the ECDSA curves. Allows querying by oid and by key` |
| `paramiko/ecdsakey.py:71` | ECDSA (shor) | `format identifier. The two ways in which ECDSAKey needs to be able to look` |
| `paramiko/ecdsakey.py:97` | ECDSA (shor) | `class ECDSAKey(PKey):` |
| `paramiko/ecdsakey.py:99` | ECDSA (shor) | `Representation of an ECDSA key which can be used to sign and verify SSH2` |
| `paramiko/ecdsakey.py:103` | ECDSA (shor) | `_ECDSA_CURVES = _ECDSACurveSet(` |
| `paramiko/ecdsakey.py:137` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(c_class)` |
| `paramiko/ecdsakey.py:149` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_key_format_identifier(` |
| `paramiko/ecdsakey.py:152` | ECDSA (shor) | `key_types = self._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:176` | ECDSA (shor) | `return cls._ECDSA_CURVES.get_key_format_identifier_list()` |
| `paramiko/ecdsakey.py:256` | ECDSA (shor) | `Generate a new private ECDSA key.  This factory function can be used to` |
| `paramiko/ecdsakey.py:260` | ECDSA (shor) | `:returns: A new private key (`.ECDSAKey`) object` |
| `paramiko/ecdsakey.py:263` | ECDSA (shor) | `curve = cls._ECDSA_CURVES.get_by_key_length(bits)` |
| `paramiko/ecdsakey.py:269` | ECDSA (shor) | `return ECDSAKey(vals=(private_key, private_key.public_key()))` |
| `paramiko/ecdsakey.py:302` | ECDSA (shor) | `curve = self._ECDSA_CURVES.get_by_key_format_identifier(name)` |
| `paramiko/ecdsakey.py:318` | ECDSA (shor) | `self.ecdsa_curve = self._ECDSA_CURVES.get_by_curve_class(curve_class)` |
| `paramiko/ed25519key.py:30` | Ed25519 (shor) | `class Ed25519Key(PKey):` |
| `paramiko/ed25519key.py:32` | Ed25519 (shor) | `Representation of an `Ed25519 <https://ed25519.cr.yp.to/>`_ key.` |
| `paramiko/ed25519key.py:35` | Ed25519 (shor) | `Ed25519 key support was added to OpenSSH in version 6.5.` |
| `paramiko/ed25519key.py:55` | Ed25519 (shor) | `cert_type="ssh-ed25519-cert-v01@openssh.com",` |
| `paramiko/kex_curve25519.py:16` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_curve25519.py:17` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_curve25519.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:51` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:58` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:61` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_curve25519.py:63` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_curve25519.py:90` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_curve25519.py:97` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:129` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_ecdh_nist.py:2` | ECDH (shor) | `Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange` |
| `paramiko/kex_ecdh_nist.py:6` | SHA256 (grover) | `from hashlib import sha256, sha384, sha512` |
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:71` | ECDH (shor) | `K = self.P.exchange(ec.ECDH(), self.Q_C)` |
| `paramiko/kex_ecdh_nist.py:91` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:117` | ECDH (shor) | `K = self.P.exchange(ec.ECDH(), self.Q_S)` |
| `paramiko/kex_ecdh_nist.py:137` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_gex.py:26` | SHA256 (grover) | `from hashlib import sha256` |
| `paramiko/kex_gex.py:236` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_gex.py:278` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:26` | SHA256 (grover) | `from hashlib import sha256` |
| `paramiko/kex_group14.py:117` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:141` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_group16.py:24` | SHA512 (grover) | `from hashlib import sha512` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/kex_mlkem.py:54` | X25519 (shor) | `name = "mlkem768x25519-sha256"` |
| `paramiko/kex_mlkem.py:141` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:160` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_mlkem.py:194` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:212` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
| `paramiko/pkey.py:38` | EllipticCurvePrivateKey (shor) | `EllipticCurvePrivateKey,` |
| `paramiko/pkey.py:173` | ECDSA (shor) | `from paramiko import ECDSAKey, Ed25519Key, RSAKey` |
| `paramiko/pkey.py:215` | Ed25519 (shor) | `key_class = Ed25519Key` |
| `paramiko/pkey.py:217` | ECDSA (shor) | `key_class = ECDSAKey` |
| `paramiko/pkey.py:234` | Ed25519 (shor) | `For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``` |
| `paramiko/pkey.py:235` | Ed25519 (shor) | `will (if successful) return a new `.Ed25519Key`.` |
| `paramiko/pkey.py:238` | Ed25519 (shor) | `The key type, eg ``"ssh-ed25519"``.` |
| `paramiko/pkey.py:268` | ECDSA (shor) | `implementation suffices; see `.ECDSAKey` for one example of an` |
| `paramiko/pkey.py:338` | RSA (shor) | `example, ``"ssh-rsa"``).` |
| `paramiko/pkey.py:403` | None (not-affected) | `b64ed = encodebytes(hashy.digest())` |
| `paramiko/pkey.py:852` | ECDSA (shor) | `it was (e.g. ECDSA.)` |
| `paramiko/rsakey.py:76` | RSA (shor) | `cert_type="ssh-rsa-cert-v01@openssh.com",` |
| `paramiko/rsakey.py:90` | RSA (shor) | `"ssh-rsa-cert-v01@openssh.com",` |
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/sftp_server.py:83` | SHA-1 (grover) | `_hash_class = {"sha1": sha1, "md5": md5}` |
| `paramiko/sftp_server.py:350` | None (not-affected) | `sum_out += hash_obj.digest()` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/transport.py:190` | HMAC (grover) | `"hmac-sha2-256-etm@openssh.com",` |
| `paramiko/transport.py:191` | HMAC (grover) | `"hmac-sha2-512-etm@openssh.com",` |
| `paramiko/transport.py:193` | HMAC (grover) | `"hmac-md5",` |
| `paramiko/transport.py:195` | HMAC (grover) | `"hmac-md5-96",` |
| `paramiko/transport.py:226` | X25519 (shor) | `_preferred_kex = ("mlkem768x25519-sha256",) + _preferred_kex` |
| `paramiko/transport.py:292` | HMAC (grover) | `"hmac-sha2-256-etm@openssh.com": {"class": sha256, "size": 32},` |
| `paramiko/transport.py:294` | HMAC (grover) | `"hmac-sha2-512-etm@openssh.com": {"class": sha512, "size": 64},` |
| `paramiko/transport.py:295` | HMAC (grover) | `"hmac-md5": {"class": md5, "size": 16},` |
| `paramiko/transport.py:296` | HMAC (grover) | `"hmac-md5-96": {"class": md5, "size": 12},` |
| `paramiko/transport.py:313` | RSA (shor) | `"rsa-sha2-256-cert-v01@openssh.com": RSAKey,` |
| `paramiko/transport.py:315` | RSA (shor) | `"rsa-sha2-512-cert-v01@openssh.com": RSAKey,` |
| `paramiko/transport.py:317` | ECDSA (shor) | `"ecdsa-sha2-nistp256-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:319` | ECDSA (shor) | `"ecdsa-sha2-nistp384-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:321` | ECDSA (shor) | `"ecdsa-sha2-nistp521-cert-v01@openssh.com": ECDSAKey,` |
| `paramiko/transport.py:323` | Ed25519 (shor) | `"ssh-ed25519-cert-v01@openssh.com": Ed25519Key,` |
| `paramiko/transport.py:1896` | None (not-affected) | `out = sofar = hash_algo(m.asbytes()).digest()` |
| `paramiko/transport.py:1902` | None (not-affected) | `digest = hash_algo(m.asbytes()).digest()` |
| `paramiko/transport.py:1924` | None (not-affected) | `return cipher.encryptor()` |
| `paramiko/transport.py:1926` | None (not-affected) | `return cipher.decryptor()` |
| `paramiko/util.py:149` | SHA256 (grover) | `as ``hashlib.sha256``.` |
| `paramiko/util.py:166` | None (not-affected) | `digest = hash_obj.digest()` |


## Limitations, stated plainly

1. **The ground truth is ours, not the corpus authors'.** It was annotated by the author
   of this harness. Every label records its verbatim source line, and the harness re-reads
   each one from the pinned corpus and aborts on mismatch, so the label set is auditable
   and tamper-evident -- but it is still one annotator's judgement, with no second
   annotator and no inter-annotator agreement figure. We do not claim otherwise.
2. **CryptoAPI-Bench is a constructed benchmark.** Its 203 files are small, deliberately
   written Java micro-programmes, not production code. It is genuinely third-party and
   peer-reviewed, but it is not evidence about messy real-world code. `paramiko` is
   included precisely because it is real production code.
3. **The L1 criterion favours the tool.** Operation lines (`cipher.init`, `.digest()`) are
   excluded from L1 and included in L2. L2 is the lower bound on recall; read it before
   quoting a recall number.
4. **ECDAT was run with `enable_ml=False`.** The optional PyTorch classifier is therefore
   absent from these numbers, and `dl_confidence` is not populated. This is deliberate: the
   benchmark must be hermetic and reproducible on a machine with no model file.
5. **Regex-rule coverage is the whole story here.** Every number above is a measurement of
   the hand-written rule table plus primitive naming. Nothing in this benchmark validates
   the CBOM, the Mosca arithmetic, or the recommender.
6. **Line-level matching is strict.** A finding one line away from a labelled positive is a
   false positive AND that positive is a false negative. The file-level table is given as
   a coarser cross-check for exactly that reason.

