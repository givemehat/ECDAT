# IndraMesh external-accuracy benchmark results

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
| `paramiko` | yes (git clone) | `142f593e40ad` | Real production library, not a constructed benchmark. Scoped to the 'paramiko/' package directory; 'tests/' and 'sites/' are excluded, and that exclusion is part of the declared measurement scope. |

### Why the ground truth had to be hand-made

CryptoAPI-Bench ships `CryptoAPI-Bench_details.xlsx` with 182 rows of *misuse* labels
(28 categories: `Constant Seed`, `Usage of ECB`, `RSA keysize 1024 bits`, `DES used`,
`PBE iteration < 1000`, ...). IndraMesh is a **quantum**-vulnerability detector. Those are
different properties, so scoring IndraMesh against the published labels would be a category
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

This criterion **favours IndraMesh**: every excluded operation line is a location the tool
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
| `paramiko` | L1 | 172 | 17 | 68 | 0.9101 = 172/189 | 0.7167 = 172/240 | 0.8019 |
| `paramiko` | L2 | 172 | 17 | 87 | 0.9101 = 172/189 | 0.6641 = 172/259 | 0.7679 |

### File-level view (secondary)

| corpus | labels | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|---|
| `paramiko` | L1 | 16 | 0 | 3 | 1.0 | 0.8421 |
| `paramiko` | L2 | 16 | 0 | 3 | 1.0 | 0.8421 |

### Recall by primitive (L1)

| corpus | primitive (break model) | labelled | detected | recall |
|---|---|---|---|---|
| `paramiko` | 3DES (grover) | 2 | 2 | 1.0 |
| `paramiko` | AES (grover) | 27 | 27 | 1.0 |
| `paramiko` | Curve25519 (shor) | 2 | 2 | 1.0 |
| `paramiko` | Diffie-Hellman (shor) | 3 | 3 | 1.0 |
| `paramiko` | EC (shor) | 1 | 0 | 0.0 |
| `paramiko` | ECDH (shor) | 30 | 11 | 0.3667 |
| `paramiko` | ECDSA (shor) | 42 | 14 | 0.3333 |
| `paramiko` | ED25519 (shor) | 1 | 1 | 1.0 |
| `paramiko` | Ed25519 (shor) | 19 | 7 | 0.3684 |
| `paramiko` | EllipticCurvePrivateKey (shor) | 3 | 3 | 1.0 |
| `paramiko` | HMAC (grover) | 16 | 16 | 1.0 |
| `paramiko` | MD5 (grover) | 5 | 4 | 0.8 |
| `paramiko` | RSA (shor) | 37 | 35 | 0.9459 |
| `paramiko` | SHA-1 (grover) | 3 | 1 | 0.3333 |
| `paramiko` | SHA-256 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA-384 (grover) | 1 | 1 | 1.0 |
| `paramiko` | SHA-512 (grover) | 3 | 3 | 1.0 |
| `paramiko` | SHA1 (grover) | 5 | 5 | 1.0 |
| `paramiko` | SHA256 (grover) | 7 | 6 | 0.8571 |
| `paramiko` | SHA512 (grover) | 1 | 1 | 1.0 |
| `paramiko` | X25519 (shor) | 22 | 20 | 0.9091 |
| `paramiko` | secp256r1 (shor) | 3 | 3 | 1.0 |
| `paramiko` | secp384r1 (shor) | 2 | 2 | 1.0 |
| `paramiko` | secp521r1 (shor) | 2 | 2 | 1.0 |

## Coverage and scan honesty

`files_skipped` and `errors` are reported so that "the tool found nothing here" can
never be confused with "the tool could not look here".

| corpus | files seen | files scanned | files skipped | scan errors |
|---|---|---|---|---|
| `paramiko` | 42 | 42 | 0 | 0 |

Findings emitted for `paramiko`, by rule:

| rule | findings |
|---|---|
| ECDSA | IM-SRC-SSH-SIG-001 | 30 |
| ECDH | IM-SRC-ECDH-001 | 22 |
| AES | IM-SRC-SSH-CIPHER-001 | 14 |
| RSA | IM-SRC-PYCA-RSA-001 | 13 |
| HMAC | IM-SRC-SSH-MAC-001 | 12 |
| ECDH | IM-SRC-SSH-KEX-001 | 11 |
| DH | IM-SRC-SSH-DH-001 | 10 |
| AES | IM-SRC-PYCA-AES-001 | 9 |
| SHA | IM-SRC-PYCA-HASH-001 | 7 |
| ECC | IM-SRC-PYCA-EC-001 | 7 |
| SHA256 | IM-SRC-HASHLIB-004 | 6 |
| RSA | IM-SRC-SSHNAME-002 | 6 |
| SHA1 | IM-SRC-HASHLIB-001 | 4 |
| ECC | IM-SRC-PYCA-ECTYPE-001 | 4 |
| Ed25519 | IM-SRC-SSH-ED-001 | 4 |
| MD5 | IM-SRC-SSH-MAC-002 | 4 |
| AES | IM-SRC-SSH-CIPHER-002 | 4 |
| HMAC | IM-SRC-SSHNAME-004 | 4 |
| SHA1 | IM-SRC-SHA1-001 | 3 |
| X25519 | IM-SRC-SSH-HYBRID-001 | 3 |
| Ed25519 | IM-SRC-EDDSA-001 | 3 |
| MD5 | IM-SRC-HASHLIB-003 | 3 |
| ECDSA | IM-SRC-SSHNAME-001 | 3 |
| ECDSA | IM-SRC-ECDSA-001 | 2 |
| Ed25519 | IM-SRC-SSHNAME-003 | 2 |
| SHA | IM-SRC-HASHLIB-002 | 2 |
| X25519 | IM-SRC-PYCA-X-001 | 2 |
| ECDH | IM-SRC-PYCA-ECDH-002 | 2 |
| AES | IM-SRC-JAVA-CONST-001 | 2 |
| ECDH | IM-SRC-SSHNAME-005 | 2 |
| 3DES | IM-SRC-SSH-LEGACY-001 | 2 |
| ECDH | IM-SRC-PYCA-ECDH-001 | 1 |
| Ed25519 | IM-SRC-PYCA-ED-001 | 1 |
| AES | IM-SRC-AES-001 | 1 |
| SHA256 | IM-SRC-SHA2-001 | 1 |
| MD5 | IM-SRC-MD5-001 | 1 |
| SHA1 | IM-SRC-SSH-HASH-NAME-001 | 1 |
## Explicit false positives -- `paramiko`, L1 (17)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001, IM-SRC-PYCA-ECDH-001 |
| `paramiko/kex_curve25519.py:37` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:112` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/pkey.py:128` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/pkey.py:134` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |

## Explicit false positives -- `paramiko`, L2 (17)

A false positive is a finding at a `(file, line)` that the labels record as NOT
a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim
from the label file, so each row can be checked against the source.

| file:line | why the labels exclude it | IndraMesh called it | rule |
|---|---|---|---|
| `paramiko/ecdsakey.py:305` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001, IM-SRC-PYCA-ECDH-001 |
| `paramiko/kex_curve25519.py:37` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_group14.py:45` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:30` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_group16.py:35` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/kex_mlkem.py:59` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:60` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:61` | byte-length constant naming a component size, not a primitive | ECDH | IM-SRC-ECDH-001 |
| `paramiko/kex_mlkem.py:112` | line was not a labelling candidate | ECDH | IM-SRC-ECDH-001 |
| `paramiko/pkey.py:128` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/pkey.py:134` | no quantum-vulnerable primitive is named on this line | AES | IM-SRC-JAVA-CONST-001 |
| `paramiko/rsakey.py:139` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/rsakey.py:167` | line was not a labelling candidate | RSA | IM-SRC-PYCA-RSA-001 |
| `paramiko/transport.py:219` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:221` | line was not a labelling candidate | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:328` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |
| `paramiko/transport.py:329` | no quantum-vulnerable primitive is named on this line | DH | IM-SRC-SSH-DH-001 |

## Explicit false negatives -- `paramiko`, L1 (68)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

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
| `paramiko/kex_curve25519.py:16` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_curve25519.py:17` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_curve25519.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:51` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_curve25519.py:58` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_curve25519.py:61` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_curve25519.py:63` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_curve25519.py:97` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:2` | ECDH (shor) | `Ephemeral Elliptic Curve Diffie-Hellman (ECDH) key exchange` |
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
| `paramiko/pkey.py:173` | ECDSA (shor) | `from paramiko import ECDSAKey, Ed25519Key, RSAKey` |
| `paramiko/pkey.py:215` | Ed25519 (shor) | `key_class = Ed25519Key` |
| `paramiko/pkey.py:217` | ECDSA (shor) | `key_class = ECDSAKey` |
| `paramiko/pkey.py:234` | Ed25519 (shor) | `For example, ``PKey.from_type_string("ssh-ed25519", <public bytes>)``` |
| `paramiko/pkey.py:235` | Ed25519 (shor) | `will (if successful) return a new `.Ed25519Key`.` |
| `paramiko/pkey.py:238` | Ed25519 (shor) | `The key type, eg ``"ssh-ed25519"``.` |
| `paramiko/pkey.py:268` | ECDSA (shor) | `implementation suffices; see `.ECDSAKey` for one example of an` |
| `paramiko/pkey.py:338` | RSA (shor) | `example, ``"ssh-rsa"``).` |
| `paramiko/pkey.py:852` | ECDSA (shor) | `it was (e.g. ECDSA.)` |
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
| `paramiko/util.py:149` | SHA256 (grover) | `as ``hashlib.sha256``.` |

## Explicit false negatives -- `paramiko`, L2 (87)

A false negative is a labelled quantum-vulnerable location IndraMesh did not report.

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
| `paramiko/kex_ecdh_nist.py:15` | ECDH (shor) | `_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)` |
| `paramiko/kex_ecdh_nist.py:16` | ECDH (shor) | `c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]` |
| `paramiko/kex_ecdh_nist.py:35` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:38` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_INIT)` |
| `paramiko/kex_ecdh_nist.py:47` | ECDH (shor) | `self.transport._expect_packet(_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:50` | ECDH (shor) | `if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):` |
| `paramiko/kex_ecdh_nist.py:52` | ECDH (shor) | `elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):` |
| `paramiko/kex_ecdh_nist.py:55` | ECDH (shor) | `"KexECDH asked to handle packet type {:d}".format(ptype)` |
| `paramiko/kex_ecdh_nist.py:91` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_ecdh_nist.py:98` | ECDH (shor) | `m.add_byte(c_MSG_KEXECDH_REPLY)` |
| `paramiko/kex_ecdh_nist.py:137` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_gex.py:236` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_gex.py:278` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:117` | None (not-affected) | `self.transport._set_K_H(K, self.hash_algo(hm.asbytes()).digest())` |
| `paramiko/kex_group14.py:141` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_mlkem.py:9` | ECDH (shor) | `ECDH/X25519 key agreement; the final shared secret is the hash of the` |
| `paramiko/kex_mlkem.py:49` | X25519 (shor) | `Combines ML-KEM-768 (FIPS 203) with X25519. The shared secret is` |
| `paramiko/kex_mlkem.py:51` | X25519 (shor) | ```K_CL`` is the X25519 shared secret.` |
| `paramiko/kex_mlkem.py:141` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:160` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/kex_mlkem.py:194` | None (not-affected) | `K_bytes = self.hash_algo(k_pq + k_cl).digest()` |
| `paramiko/kex_mlkem.py:212` | None (not-affected) | `H = self.hash_algo(hm.asbytes()).digest()` |
| `paramiko/pkey.py:37` | EC (shor) | `from cryptography.hazmat.primitives.asymmetric.ec import (` |
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
| `paramiko/rsakey.py:184` | RSA (shor) | `key = rsa.generate_private_key(` |
| `paramiko/sftp_file.py:376` | SHA-1 (grover) | `For example, ``check('sha1', 0, 1024, 512)`` will return a string of` |
| `paramiko/sftp_file.py:382` | SHA-1 (grover) | `the name of the hash algorithm to use (normally ``"sha1"`` or` |
| `paramiko/sftp_file.py:383` | MD5 (grover) | ```"md5"``)` |
| `paramiko/sftp_server.py:350` | None (not-affected) | `sum_out += hash_obj.digest()` |
| `paramiko/transport.py:97` | ECDSA (shor) | `from paramiko.ecdsakey import ECDSAKey` |
| `paramiko/transport.py:98` | Ed25519 (shor) | `from paramiko.ed25519key import Ed25519Key` |
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
4. **IndraMesh was run with `enable_ml=False`.** The optional PyTorch classifier is therefore
   absent from these numbers, and `dl_confidence` is not populated. This is deliberate: the
   benchmark must be hermetic and reproducible on a machine with no model file.
5. **Regex-rule coverage is the whole story here.** Every number above is a measurement of
   the hand-written rule table plus primitive naming. Nothing in this benchmark validates
   the CBOM, the Mosca arithmetic, or the recommender.
6. **Line-level matching is strict.** A finding one line away from a labelled positive is a
   false positive AND that positive is a false negative. The file-level table is given as
   a coarser cross-check for exactly that reason.

