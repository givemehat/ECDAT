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
        # A bare `ec.generate_private_key(ec.SECP256R1())` no longer matches this rule: it is a
        # generic key-pair generator that cannot say which operation follows, and matching it
        # here made one line report as BOTH ECDH and ECDSA. The curve is still found, by
        # ECD-SRC-PYCA-EC-001.
        "ECD-SRC-ECDH-001": "shared = kex.exchange(peer_public_key)",
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
        # ECD-SRC-PYCA-EC-002 was removed as a strict subset of -001: the curve was reported
        # twice from two rule_ids, and the second carried no extra information. The dedup key
        # includes rule_id, so two rules with the same name never collapse.
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
        # --- the Java pack, added against MEASURED CryptoAPI-Bench misses (recall 0.219, FP=0).
        # Each sample is a real call shape from the corpus, not an invented string.
        "ECD-SRC-JAVA-LEGACY-001": 'String t = "DES/ECB/PKCS5Padding";',
        "ECD-SRC-JAVA-KEYGEN-001": "KeyGenerator kg = KeyGenerator.getInstance(\"AES\");",
        "ECD-SRC-JAVA-SECRETKEY-001": 'SecretKeySpec ks = new SecretKeySpec(keyBytes, "AES");',
        "ECD-SRC-JAVA-CIPHER-001": 'Cipher c = Cipher.getInstance("Blowfish");',
        "ECD-SRC-JAVA-MAC-001": 'Mac mac = Mac.getInstance("HmacSHA256");',
        # MD2/MD4 only. MD5 is deliberately NOT here: ECD-SRC-MD5-001 already owns it, and
        # matching it again published the same algorithm twice from two rule_ids.
        "ECD-SRC-JAVA-DIGEST-001": 'MessageDigest md = MessageDigest.getInstance("MD4");',
        "ECD-SRC-JAVA-EC-001": 'new ECGenParameterSpec("secp256r1")',
        "ECD-SRC-JAVA-DSA-001": 'KeyPairGenerator.getInstance("DSA")',
        "ECD-SRC-JAVA-CONST-001": 'String a = "AES/GCM/NoPadding";',
        "ECD-SRC-JAVA-CONST-003": 'String t = "RSA/ECB/PKCS1Padding";',
        "ECD-SRC-JAVA-CONST-004": 'String h = "SHA-256";',
        "ECD-SRC-JAVA-WEAKRNG-001": "Random r = new java.util.Random();",
        # --- PHP and Ruby, which previously had NO rules and were not even scanned.
        "ECD-PHP-AES-001": "openssl_encrypt($data, 'aes-256-gcm', $key);",
        "ECD-PHP-AES-002": "openssl_cipher_iv_length('aes-256-cbc');",
        "ECD-PHP-KEM-001": "openssl_public_encrypt($data, $pubkey);",
        "ECD-PHP-SIG-001": "openssl_sign($data, $sig, $privkey);",
        "ECD-PHP-SODIUM-001": "sodium_crypto_aead_chacha20_ietf_encrypt($m, $aad, $npub, $k);",
        "ECD-PHP-SODIUM-002": "sodium_crypto_aead_aes256gcm_encrypt($m, $aad, $npub, $k);",
        "ECD-PHP-SIG-002": "sodium_crypto_sign_keypair();",
        "ECD-PHP-HASH-001": "$h = hash('sha1', $data);",
        "ECD-PHP-WEAKRNG-001": "$t = mt_rand();",
        "ECD-RB-AES-001": "c = OpenSSL::Cipher.new('aes-256-gcm')",
        "ECD-RB-AES-002": "c = OpenSSL::Cipher.new('chacha20')",
        "ECD-RB-LEGACY-001": "c = OpenSSL::Cipher.new('bf-cbc')",
        "ECD-RB-RSA-001": "k = OpenSSL::PKey::RSA.new(2048)",
        # A real call site. The pattern needs the receiver named (`OpenSSL::PKey::X.sign(...)
        # ), which is why the sample must be a call and not a bare class reference.
        "ECD-RB-SIG-001": "sig = OpenSSL::PKey::RSA.new.sign(digest, priv)",
        "ECD-RB-EC-001": "k = OpenSSL::PKey::EC.generate('prime256v1')",
        "ECD-RB-DH-001": "dh = OpenSSL::PKey::DH.new(2048)",
        "ECD-RB-MAC-001": "h = OpenSSL::HMAC.digest('SHA256', key, data)",
        "ECD-RB-HASH-001": "d = Digest::SHA1.hexdigest(data)",
        "ECD-RB-HASH-002": "d = Digest::SHA256.hexdigest(data)",
        # `SecureRandom.hex` deliberately does NOT match this rule -- a rule that fired on the
        # secure generator too would make the finding meaningless.
        "ECD-RB-WEAKRNG-001": "token = Kernel.rand(16)",
            "ECD-KEY-PEM-001": "-----BEGIN RSA PRIVATE KEY-----",
            "ECD-KEY-PGP-001": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "ECD-PROTO-TLS-001": "ssl_protocols TLSv1.2",
            "ECD-CLOUD-KMS-001": "boto3.client('kms')",
            "ECD-CLOUD-AZURE-001": "azure.keyvault",
            "ECD-CLOUD-GCP-001": "google-cloud-kms",
            "ECD-HARDWARE-PKCS11-001": "SunPKCS11",
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
    # The snippet ends in `.exchange(peer_public_key)`, which is an actual key-agreement call.
    # A BARE `ec.generate_private_key(ec.SECP256R1())` no longer produces an ECDH finding: it is
    # a generic key-pair generator, and typing it as ECDH made the same line also report as
    # ECDSA -- so one statement produced two mutually exclusive primitives and two targets.
    p = _write(str(tmp_path / "kex.py"),
               "from cryptography.hazmat.primitives.asymmetric import ec\n"
               "priv = ec.generate_private_key(ec.SECP256R1())\n"
               "shared = priv.exchange(peer_public_key)\n")
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "ECDH" in names, "ECC/ECDH detection is the brief's stated demo target"


def test_a_bare_key_pair_generator_is_not_reported_as_two_primitives(tmp_path, scanner):
    """A key-pair generator must not yield BOTH a key-agreement and a signature.

    It used to match the ECDH rule AND the PYCA ECDSA rules at once, so the recommender offered
    ML-KEM and ML-DSA for a single statement. The fix was NOT to stop detecting it -- that cost
    measured recall -- but to stop the downstream rename that guessed "signature" out of nearby
    prose. Both facts are still reported; the contradictory one is gone.
    """
    p = _write(str(tmp_path / "kex.py"),
               "priv = ec.generate_private_key(ec.SECP256R1())\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings, "the curve and its key agreement must still be detected"
    primitives = {f["primitive"] for f in findings}
    assert "signature" not in primitives, (
        "a key-pair generator does not establish a signature")
    assert "key-agreement" in primitives, (
        "a P-256 key pair IS key agreement; the finding must not be thrown away to avoid a "
        "duplicate -- dropping it cost measured recall on the paramiko corpus")


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
    """The curve resolves to a key size, and the key-agreement CALL resolves to the primitive.

    These are two different lines and the tool reports them as two different facts, which is the
    point: `ec.SECP256R1()` says the algorithm, `.exchange(peer_public_key)` says the operation.
    Neither line supports the other's conclusion on its own, so neither is stretched to do it.
    """
    p = _write(str(tmp_path / "kex.py"),
               "priv = ec.generate_private_key(ec.SECP256R1())\n"
               "shared = priv.exchange(peer_public_key)\n")
    findings = scanner.scan_directory(str(tmp_path))

    # The exchange line is key agreement, and is not given a key size it cannot see.
    ecdh = [f for f in findings if f["name"] == "ECDH"]
    assert ecdh, "an actual .exchange(peer_public_key) call is key agreement"
    assert ecdh[0]["primitive"] == "key-agreement"

    # The curve line carries the size.
    curves = [f for f in findings if f.get("key_length") == 256]
    assert curves, "SECP256R1 must resolve to a 256-bit key"


def test_a_curve_object_alone_is_not_called_a_signature(tmp_path, scanner):
    """A bare `ec.SECP256R1()` must not be reported as `signature`.

    It was renamed "ECDSA / signature" whenever no TLS token happened to be nearby. That is a
    coin-flip presented as a finding, and it is why one line could be reported as both ECDH and
    ECDSA. With no use context the operation is simply not stated.
    """
    p = _write(str(tmp_path / "kex.py"), "curve = ec.SECP256R1()\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings, "the curve itself must still be detected"
    for f in findings:
        assert f["primitive"] != "signature", (
            "a curve object does not establish that it is used for signing")


# --------------------------------------------------------------------------------------------
# PHP and Ruby. Both had ZERO rules AND were not in SOURCE_EXTENSIONS, so a PHP or Rails codebase
# produced no findings whatsoever. Precision matters more here than coverage: both languages use
# `#` as their PRIMARY comment style, so without comment stripping every rule in these packs
# would fire on prose and the tool would report a comment as a cryptographic algorithm.
# --------------------------------------------------------------------------------------------

PHP_REAL = (
    "<?php\n"
    "$c = openssl_encrypt($d, 'aes-256-gcm', $k);\n"
    "openssl_public_encrypt($d, $pub);\n"
    "$h = hash('sha1', $d);\n"
    "mt_rand();\n"
)

RUBY_REAL = (
    "c = OpenSSL::Cipher.new('aes-256-gcm')\n"
    "k = OpenSSL::PKey::RSA.new(2048)\n"
    "d = Digest::SHA1.hexdigest(data)\n"
    "t = Kernel.rand(16)\n"
)

# Every line names a real algorithm. Not one of them is a CALL. A tool that reports these is
# reporting prose as an inventory, which is worse than reporting nothing.
PHP_DECOY = (
    "<?php\n"
    "// encrypt with aes-256-gcm in production\n"
    "# TODO: replace sha1 with something better\n"
    "$aesMode = 'aes-128-cbc';\n"
    "echo \"we use RSA and SHA-256\";\n"
)

RUBY_DECOY = (
    "# switch to OpenSSL::Cipher.new('aes-256-gcm') later\n"
    "=begin\n"
    "OpenSSL::PKey::RSA.new(2048)\n"
    "=end\n"
    "x = 1 # Digest::SHA1.hexdigest(data)\n"
)


def test_php_crypto_calls_are_detected(tmp_path, scanner):
    _write(str(tmp_path / "app.php"), PHP_REAL)
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "AES" in names and "RSA" in names, f"expected openssl_* detection, got {names}"
    assert "PRNG" in names, "mt_rand() is not a cryptographic generator and must be flagged"


def test_php_comments_and_prose_are_not_findings(tmp_path, scanner):
    _write(str(tmp_path / "notes.php"), PHP_DECOY)
    assert scanner.scan_directory(str(tmp_path)) == [], (
        "a PHP comment or a bare cipher string in an echo is not a cryptographic call site")


def test_ruby_crypto_calls_are_detected(tmp_path, scanner):
    _write(str(tmp_path / "app.rb"), RUBY_REAL)
    findings = scanner.scan_directory(str(tmp_path))
    names = {f["name"] for f in findings}
    assert "AES" in names and "RSA" in names, f"expected OpenSSL:: detection, got {names}"
    aes = [f for f in findings if f["name"] == "AES"][0]
    assert aes["key_length"] == 256, "aes-256-gcm must resolve to a 256-bit key"


def test_ruby_comments_and_block_comments_are_not_findings(tmp_path, scanner):
    _write(str(tmp_path / "notes.rb"), RUBY_DECOY)
    assert scanner.scan_directory(str(tmp_path)) == [], (
        "Ruby `#` comments and =begin/=end blocks are prose, not call sites")


def test_secure_random_is_not_flagged_as_a_weak_generator(tmp_path, scanner):
    """`SecureRandom` is the CORRECT call. A weak-RNG rule that also fired on it would make the
    finding meaningless, so the negative lookbehind on the Ruby rule is load-bearing."""
    _write(str(tmp_path / "good.rb"), "token = SecureRandom.hex(16)\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert not [f for f in findings if f["name"] == "PRNG"], (
        "SecureRandom must never be reported as a non-cryptographic generator")


def test_a_python_sign_call_is_not_a_ruby_signature_finding(tmp_path, scanner):
    """A language pack must not fire on ANOTHER language.

    `ECD-RB-SIG-001` originally matched a bare `.sign(`/`.verify(`, which fired on paramiko's
    `self.key.sign(...)` -- an SSH host-key operation in Python, reported as an RSA signature.
    That was 6 false positives on the Python corpus, and the benchmark caught them. The rule now
    requires an explicit `OpenSSL::PKey::` receiver, which is what makes it a Ruby signal.
    """
    _write(str(tmp_path / "auth.py"),
           "sig = self.key.sign(data)\n"
           "ok = self.key.verify(sig, data)\n"
           "key.sign_pss('SHA256', digest)\n")
    findings = scanner.scan_directory(str(tmp_path))
    assert findings == [], (
        "a Python .sign()/.verify() call must not be reported by the Ruby pack: %r"
        % [(f["rule_id"], f["name"]) for f in findings])


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

