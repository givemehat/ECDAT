"""Tests for the scanning engine.

Regressions encoded here (all fixed 2026-09-25):
  * ECC and SHA-256 patterns were DEFINED BUT NEVER EXECUTED -- the loop only tested RSA and
    AES_GCM. The brief's own demo target is "a real repository that uses RSA and ECC".
  * `import torch` at module scope made the scanner unimportable without PyTorch
  * `except Exception: pass` made "could not read" indistinguishable from "clean"
  * binary scanning shelled out to `strings`, which does not exist on Windows
  * container images were not scanned at all
  * the AES key size was never extracted, so AES-256 was misreported
"""
import io
import os
import tarfile

import pytest

from engine.scanner import ECDATScanner, RULES, BINARY_MARKERS


@pytest.fixture
def scanner():
    # enable_ml=False keeps these tests hermetic: no torch, no model file, regex only.
    return ECDATScanner(enable_ml=False)


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


# ------------------------------------------------------------------ the dead-code regression

def test_every_rule_is_actually_executed(tmp_path, scanner):
    """Each rule in the table must be reachable: give it a positive sample and assert a hit."""
    samples = {
        "ECD-SRC-RSA-001": "key = rsa.newkeys(2048)",
        "ECD-SRC-RSA-002": "sig = pkcs1_15.new(key).sign(h)",
        "ECD-SRC-RSA-003": 'KeyPairGenerator.getInstance("RSA")',
        "ECD-SRC-ECDH-001": "priv = ec.generate_private_key(ec.SECP256R1())",
        "ECD-SRC-ECDSA-001": 'Signature.getInstance("SHA256withECDSA")',
        "ECD-SRC-ECC-001": 'kpg = KeyPairGenerator.getInstance("EC")',
        "ECD-SRC-EDDSA-001": "sk = Ed25519PrivateKey.generate()",
        "ECD-SRC-DSA-001": "EVP_PKEY_DSA *pkey = NULL;",
        "ECD-SRC-DH-001": "DH_get_2048_256();",
        "ECD-SRC-AES-001": "aesgcm = AESGCM(key)",
        "ECD-SRC-CHACHA-001": "AEADChaCha20Poly1305()",
        "ECD-SRC-SHA2-001": "digest = hashes.Hash(hashes.SHA256())",
        "ECD-SRC-SHA1-001": 'MessageDigest.getInstance("SHA-1")',
        "ECD-SRC-MD5-001": "hashlib.md5(data)",
        "ECD-CFG-TLS-001": "ssl_protocols TLSv1.2 TLSv1.3;",
        "ECD-CFG-LEGACY-001": "ciphers = RC4-SHA:DES-CBC3-SHA",
        # --- the recall rules, added against measured misses on paramiko (a real SSH library).
        # The samples are the actual source lines the benchmark said we failed on, so each rule
        # is pinned to the evidence that motivated it rather than to an invented string.
        "ECD-SRC-PYCA-AES-001": '"cipher": algorithms.AES,',
        "ECD-SRC-PYCA-HASH-001": "self.hash_object = hashes.SHA256",
        "ECD-SRC-PYCA-HASH-002": "h = hashes.SHA1",
        "ECD-SRC-PYCA-EC-001": "_ECDSACurve(ec.SECP256R1, \"nistp256\")",
        "ECD-SRC-PYCA-EC-002": "def private_key(self) -> ec.EllipticCurvePrivateKey:",
        "ECD-SRC-PYCA-ECDH-001": "kex = exchanges.ECDH()",
        "ECD-SRC-PYCA-ED-001": "k = ed25519.Ed25519PrivateKey.generate()",
        "ECD-SRC-PYCA-RSA-001": "n = rsa.RSAPrivateNumbers(p, q, d, dmp1, dmq1, iqmp)",
        "ECD-SRC-PYCA-X-001": "from cryptography.hazmat.primitives.asymmetric.x25519 import (",
        "ECD-SRC-HASHLIB-001": "from hashlib import sha1",
        "ECD-SRC-HASHLIB-002": "hash_algo = hashlib.sha256",
        "ECD-SRC-HASHLIB-003": "from hashlib import md5",
        "ECD-SRC-SSH-KEX-001": 'kex = "ecdh-sha2-nistp256"',
        "ECD-SRC-SSH-SIG-001": '"rsa-sha2-256": SSH_AGENT_RSA_SHA2_256,',
        "ECD-SRC-SSH-ED-001": 'PREF = "ssh-ed25519"',
        "ECD-SRC-SSH-CIPHER-001": 'C = "aes256-ctr"',
        "ECD-SRC-SSH-CIPHER-002": '"aes128-gcm@openssh.com"',
        "ECD-SRC-SSH-MAC-001": '"hmac-sha2-256"',
        "ECD-SRC-SSH-DH-001": 'name = "diffie-hellman-group-exchange-sha256"',
        "ECD-SRC-SSH-LEGACY-001": '"3des-cbc"',
    }
    assert set(samples) == {r["id"] for r in RULES}, "a rule has no positive test"
    unreachable = []
    for rule_id, snippet in samples.items():
        p = _write(str(tmp_path / f"{rule_id}.txt.py"), snippet)
        fired = {f["rule_id"] for f in scanner._match_rules(p, snippet)}
        if rule_id not in fired:
            unreachable.append(rule_id)
    assert not unreachable, f"rules defined but never fire: {unreachable}"


def test_ecc_is_detected(tmp_path, scanner):
    p = _write(str(tmp_path / "kex.py"),
               "from cryptography.hazmat.primitives.asymmetric import ec\n"
               "priv = ec.generate_private_key(ec.SECP256R1())\n")
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "ECDH" in names, "ECC/ECDH detection is the brief's stated demo target"


def test_sha256_is_detected(tmp_path, scanner):
    p = _write(str(tmp_path / "h.py"), "d = hashes.Hash(hashes.SHA256())\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert any(f["name"] == "SHA256" for f in findings)


# ------------------------------------------------------------------ metadata correctness

def test_rsa_key_size_extracted(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"),
               "key = rsa.generate_private_key(public_exponent=65537, key_size=4096)\n")
    findings = scanner.scan_directory(str(tmp_path))
    rsa = [f for f in findings if f["name"] == "RSA"]
    assert rsa and rsa[0]["key_length"] == 4096


def test_aes_key_size_extracted(tmp_path, scanner):
    p = _write(str(tmp_path / "a.c"), "EVP_aes_256_gcm();\n")
    findings = scanner.scan_directory(str(tmp_path))
    aes = [f for f in findings if f["name"] == "AES"]
    assert aes and aes[0]["key_length"] == 256, "AES-256 must not be reported as AES-128"


def test_curve_resolves_to_key_size_and_primitive(tmp_path, scanner):
    p = _write(str(tmp_path / "kex.py"),
               "priv = ec.generate_private_key(ec.SECP256R1())\n")
    findings = scanner.scan_directory(str(tmp_path))
    hit = [f for f in findings if f["name"] == "ECDH"][0]
    assert hit["primitive"] == "key-agreement"
    assert hit["key_length"] == 256


def test_provenance_is_recorded(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"),
               "\n\nkey = rsa.newkeys(2048)\n")
    findings = scanner.scan_directory(str(tmp_path))
    hit = [f for f in findings if f["name"] == "RSA"][0]
    assert hit["line"] == 3
    assert hit["rule_id"] == "ECD-SRC-RSA-001"
    assert hit["scanner"] == "source-scanner"
    assert hit["evidence_class"] == "discovered"


# ------------------------------------------------------------------ honesty about failures

def test_unreadable_file_is_recorded_not_silently_ignored(tmp_path, scanner):
    """Regression: `except Exception: pass` meant an unreadable file looked identical to a clean
    file, so 'no findings' could have meant 'nothing was examined'."""
    bad = tmp_path / "bad.py"
    bad.write_bytes(b"\xff\xfe\x00\x00invalid utf8")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings == []
    assert scanner.errors, "unreadable file must be recorded"
    assert "bad.py" in scanner.errors[0]["file"]
    assert scanner.coverage["files_skipped"] == 1


def test_missing_path_is_recorded(scanner):
    assert scanner.scan_directory(str("/definitely/not/here/123456")) == []
    assert scanner.errors


def test_empty_file_is_clean_not_an_error(tmp_path, scanner):
    _write(str(tmp_path / "empty.py"), "")
    assert scanner.scan_directory(str(tmp_path)) == []
    assert scanner.errors == []


def test_coverage_manifest_lists_what_was_never_in_scope(tmp_path, scanner):
    _write(str(tmp_path / "v.py"), "key = rsa.newkeys(2048)\n")
    scanner.scan_directory(str(tmp_path))
    manifest = scanner.coverage_manifest()
    assert manifest["files_scanned"] >= 1
    assert manifest["never_in_scope"], "coverage gaps must be stated explicitly"
    joined = " ".join(manifest["never_in_scope"]).lower()
    for expected in ("network", "hsm", "saas", "silicon"):
        assert expected in joined


def test_scanner_works_without_torch(tmp_path, scanner):
    """Regression: `import torch` at module scope made scanning impossible without PyTorch."""
    p = _write(str(tmp_path / "v.py"), "key = rsa.newkeys(2048)\n")
    assert scanner.scan_directory(str(tmp_path)), "regex-only mode must still work"
    assert scanner.ml is None or not scanner.ml.available


# ------------------------------------------------------------------ binaries

def test_binary_markers_detected_without_external_strings(tmp_path, scanner):
    """Regression: scanning shelled out to `strings`, absent on Windows, and the failure was
    swallowed. Extraction is now pure Python."""
    p = tmp_path / "libfoo.so"
    p.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 16 + b"OpenSSL 3.0.13 libcrypto\x00" + b"\x00" * 8)
    findings = scanner.scan_directory(str(tmp_path))
    assert any(f["type"] == "library" and "OpenSSL" in f["name"] for f in findings)


def test_binary_without_markers_produces_nothing(tmp_path, scanner):
    p = tmp_path / "plain.bin"
    p.write_bytes(b"\x00\x01\x02" * 200)
    assert scanner.scan_directory(str(tmp_path)) == []


# ------------------------------------------------------------------ containers

def test_container_image_is_scanned(tmp_path, scanner):
    """Regression: container images were not scanned at all, though the brief requires them."""
    src = tmp_path / "src" / "layer"
    src.mkdir(parents=True)
    _write(str(src / "app.py"), "key = rsa.newkeys(2048)\n")
    _write(str(src / "tls.conf"), "ssl_protocols TLSv1.2;\n")
    lib = src / "libcrypto.so"
    lib.write_bytes(b"\x7fELF" + b"\x00" * 8 + b"libcrypto 3.0.13\x00")

    image = tmp_path / "image.tar"
    with tarfile.open(image, "w") as tf:
        tf.add(str(src / "app.py"), arcname="app/app.py")
        tf.add(str(src / "tls.conf"), arcname="app/tls.conf")
        tf.add(str(lib), arcname="usr/lib/libcrypto.so")

    findings = scanner.scan_directory(str(image))
    names = {f["name"] for f in findings}
    assert "RSA" in names, "container layer source must be scanned"
    assert "TLS" in names
    assert any("image.tar" in f["file"] for f in findings)
    # image evidence is presence, not usage
    for f in findings:
        if "image.tar" in f["file"]:
            assert f["evidence_class"] == "configured"


def test_corrupt_container_is_reported_not_crashed(tmp_path, scanner):
    bad = tmp_path / "notanimage.tar"
    bad.write_bytes(b"this is not a tar archive at all")
    assert scanner.scan_directory(str(bad)) == []
    assert scanner.errors and "notanimage" in scanner.errors[0]["file"]


# ------------------------------------------------------------------ dedup

def test_duplicate_findings_are_collapsed(tmp_path, scanner):
    p = _write(str(tmp_path / "v.py"), "a = rsa.newkeys(2048)\nb = rsa.newkeys(2048)\n")
    findings = scanner.scan_directory(str(tmp_path))
    rsa = [f for f in findings if f["name"] == "RSA"]
    assert len({f["line"] for f in rsa}) == len(rsa), "same line should not appear twice"

