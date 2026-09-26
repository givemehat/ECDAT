# Ground-truth labels

Two files, one per corpus:

| file | corpus | unit | positives | negatives audited |
|---|---|---|---|---|
| `cryptoapi_bench_pq.json` | CryptoAPI-Bench (external, SecDev 2019) | one `(file, line)` | see `annotation.positive_labels` | see `annotation.negative_labels_audited` |
| `paramiko_pq.json` | paramiko (external, real production code) | one `(file, line)` | see `annotation.positive_labels` | see `annotation.negative_labels_audited` |

## Who wrote these, and how

They were annotated by the author of this harness, by reading every file in scope. They are
**not** the corpora authors' labels. That is a deliberate substitution and it is the single most
important caveat in this benchmark:

- CryptoAPI-Bench ships `CryptoAPI-Bench_details.xlsx` with 182 rows of **API-misuse** labels
  (`Constant Seed`, `Usage of ECB`, `RSA keysize 1024 bits`, `DES used`, `PBE iteration < 1000`,
  ...). ECDAT detects **quantum**-vulnerable primitives. Scoring one against the other would be a
  category error, so no number in `RESULTS.md` is derived from that spreadsheet.
- paramiko ships no labels at all.

## Criterion

A `(file, line)` location is **POSITIVE** iff it names, or binds a name to, a quantum-vulnerable
cryptographic primitive in a position that determines the algorithm:

| rule | what it captures | example |
|---|---|---|
| `P1` | a factory call that selects the algorithm | `Cipher.getInstance("AES/CBC/PKCS5Padding")`, `KeyGenerator.getInstance(keyAlgo)` where `keyAlgo` holds `DES`, `hashlib.sha256`, `rsa.generate_private_key(...)` |
| `P1b` | naming a primitive identifier in executable code, including type annotations and `isinstance` checks | `X25519PrivateKey.generate()`, `asymmetric.ed25519.Ed25519PrivateKey` |
| `P2` | a key-spec / hash-constant binding | `new SecretKeySpec(bytes, "AES")`, `hashes.SHA256` |
| `P3` | a taint source: a literal that determines the algorithm further down | `public static final String DEFAULT_CRYPTO = "IDEA";`, `from hashlib import sha1` |
| `P4` | an SSH/OpenSSL algorithm identifier naming a primitive | `"ecdh-sha2-nistp256"`, `"ssh-ed25519"`, `"aes256-ctr"`, `"hmac-sha2-256"` |

`P1b` is deliberately over-inclusive: counting a type annotation can only *lower* the measured
recall, never inflate it, and it avoids an arbitrary line between "using" and "mentioning" a
primitive.

### Label set L1 (primary) vs L2 (sensitivity variant)

A line that merely **operates** on a primitive chosen elsewhere -- `cipher.init`, `md.update`,
`cipher.encryptor()`, `.digest()`, `compute_hmac(...)` -- is:

- **NEGATIVE in L1** (it names no primitive), and
- **POSITIVE in L2** (it is part of a quantum-vulnerable cryptographic use).

`run_benchmark.py` reports **both**. L2 is the lower bound on recall. Read L2 before quoting a
recall figure; L1 alone flatters the tool.

### Always negative, with a recorded reason

comments; `import` of a non-primitive; PRNGs (`SecureRandom`, `random`); IVs and salts;
PBKDF parameter objects; key-store container formats (`JKS`); key/block/IV-size plumbing and
byte-length constants; a binding whose name is never read anywhere in the corpus; and helper
calls whose primitive is fixed by the caller.

### Break models

- `shor` -- broken outright by Shor's algorithm, so data captured today is retroactively
  readable: RSA, DSA/DSS, Diffie-Hellman, ECDH, ECDSA, EdDSA, ElGamal, X25519/X448.
- `grover` -- quadratic speed-up only, effective security halved, **not** retroactive: AES, DES,
  3DES, Blowfish, RC2, RC4, IDEA, ChaCha20, MD2/MD4/MD5, SHA-1, SHA-2, HMAC.

The definitions live in `../pqtaxonomy.py`, deliberately separate from `engine/scanner.py`.

## Auditability

Each label records the **verbatim source line** in its `code` field plus a `reason`.
`run_benchmark.py` re-reads every one of them from the pinned corpus and **aborts** on any
mismatch, so the label set cannot silently drift away from the code it describes. Labels are
frozen data: the harness measures against the committed JSON and never re-derives them.

## Known weaknesses of this label set

- One annotator. No second annotator, so there is **no inter-annotator agreement figure**, and
  none is claimed.
- Scope for paramiko is the `paramiko/` package directory only; `tests/` and `sites/` are
  excluded. That exclusion is part of the declared scope, and recall is relative to it.
- The completeness argument for the Java corpus rests on enumerating all 55 distinct string
  literals in the corpus and confirming that every algorithm-bearing one is covered; the
  remaining lines are structural (verified by normalising them into shapes).
