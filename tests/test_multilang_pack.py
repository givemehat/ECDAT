"""Go / Rust / JavaScript / TypeScript rule pack -- positives and adversarial decoys.

Every positive sample here was checked against the real API surface: Go names against pkg.go.dev,
Rust against docs.rs, Node against the crypto and tls module indexes. Several of these regexes
were WRONG on the first pass, and the samples are what caught them:

  * the type is `rsa.PSSOptions`, not `rsa.PssOptions` -- the camel-case spelling matched nothing;
  * Node's 3DES name is `des-ede3-cbc`, which the shorter bare `des` alternative shadowed, so the
    one variant that actually mattered was the single case that failed to fire.

The decoy half matters more than the positive half. A regex that matches a real API and also
matches that API's name inside a comment, or inside a similarly-named variable, is not a rule --
it is a noise generator. The KNOWN string-literal limitation is asserted explicitly below rather
than left implicit: the engine blanks COMMENTS but does not parse string literals, so a call
quoted inside a string still matches. That is pre-existing and engine-wide (Python and Ruby
behave identically), so it is documented here instead of being silently tolerated.

Rule identifiers follow the existing project convention and were written from scratch against the
published API surfaces; no third-party scanner's identifiers or patterns were consulted.
"""

import pytest

from engine.scanner import ECDATScanner, RULES

_ALL_IDS = {r["id"] for r in RULES}

# (label, filename, content, rule_ids that MUST fire)
POSITIVES = [
    # --- Go (stdlib crypto/*) -------------------------------------------------------------------
    ("go des", "a.go", "b, _ := des.NewCipher(key)", ["ECD-GO-CIPHER-001"]),
    ("go 3des", "a.go", "c, _ := des.NewTripleDESCipher(key)", ["ECD-GO-CIPHER-001"]),
    ("go rc4", "a.go", "c, _ := rc4.NewCipher(key)", ["ECD-GO-CIPHER-002"]),
    ("go chacha20poly1305", "a.go", "aead, _ := chacha20poly1305.New(key)", ["ECD-GO-CIPHER-003"]),
    ("go md5", "a.go", "h := md5.New()", ["ECD-GO-HASH-001"]),
    ("go sha1 import", "a.go", 'import "crypto/sha1"', ["ECD-GO-HASH-002"]),
    ("go ecdsa", "a.go", "r, s, _ := ecdsa.Sign(rnd, priv, digest)", ["ECD-GO-SIG-001"]),
    ("go rsa pkcs1v15", "a.go", "err := rsa.SignPKCS1v15(rnd, priv, crypto.SHA256, d)",
     ["ECD-GO-SIG-002"]),
    ("go rsa pss", "a.go", "o := &rsa.PSSOptions{}", ["ECD-GO-SIG-003"]),
    ("go ed25519", "a.go", "pub, _, _ := ed25519.GenerateKey(rnd)", ["ECD-GO-SIG-004"]),
    ("go ecdh", "a.go", "k, _ := ecdh.P256().GenerateKey(rnd)", ["ECD-GO-KEX-001"]),
    ("go math/rand", "a.go", 'import "math/rand"', ["ECD-GO-RNG-001"]),
    ("go math/rand qualified", "a.go", "n := rand.Intn(100)", ["ECD-GO-RNG-001"]),
    # --- Rust (ring / rustcrypto) -----------------------------------------------------------------
    ("rust aes-gcm", "a.rs", "use aes_gcm::Aes256Gcm;", ["ECD-RUST-CIPHER-002"]),
    ("rust md5", "a.rs", "let h = md5::Md5::new();", ["ECD-RUST-HASH-001"]),
    ("rust sha1", "a.rs", "let h = sha1::Sha1::new();", ["ECD-RUST-HASH-002"]),
    ("rust ecdsa", "a.rs", "let k = ecdsa::SigningKey::from_bytes(&b)?;", ["ECD-RUST-SIG-001"]),
    ("rust ed25519", "a.rs", "let kp = Ed25519KeyPair::generate();", ["ECD-RUST-SIG-002"]),
    ("rust rsa", "a.rs", "let k = rsa::RsaPrivateKey::new(n, e);", ["ECD-RUST-SIG-003"]),
    ("rust thread_rng", "a.rs", "let mut r = thread_rng();", ["ECD-RUST-RNG-001"]),
    # --- JavaScript / TypeScript (Node crypto, WebCrypto) ----------------------------------------
    ("js 3des", "a.js", "createCipheriv('des-ede3-cbc', k, iv)", ["ECD-JS-CIPHER-001"]),
    ("js rc4", "a.js", "crypto.createCipheriv('rc4', key, iv)", ["ECD-JS-CIPHER-002"]),
    ("js md5", "a.js", "crypto.createHash('md5')", ["ECD-JS-HASH-001"]),
    ("js sha1", "a.js", "crypto.createHmac('sha1', key)", ["ECD-JS-HASH-002"]),
    ("js rsa-sha1", "a.js", "crypto.createSign('RSA-SHA1')", ["ECD-JS-SIG-001"]),
    ("js rsa verify", "a.js", "crypto.createVerify('RSA')", ["ECD-JS-SIG-001"]),
    ("js rsa-pss", "a.js", "s = crypto.constants.RSA_PKCS1_PSS_PADDING;", ["ECD-JS-SIG-002"]),
    ("js ecdsa", "a.js", "crypto.createSign('ecdsa-with-SHA256')", ["ECD-JS-SIG-003"]),
]

# The same failure mode as the bare `\bMD5\b` bug, generalised.
#
# Rules are NOT filtered by file extension, so a rule in the Rust pack containing an unqualified
# token will happily match that token in a .java, .py or .c file. A bare `MD5` did exactly that
# and put a second MD5 finding on `MessageDigest.getInstance("MD5")` -- one that _finalise
# cannot collapse, because the dedup key includes rule_id. The existing duplicate-guard test
# caught it, but only by accident, on the one sample that happened to use the word.
#
# The `allowed` column records which PRE-EXISTING rules may legitimately fire. `MessageDigest
# .getInstance("MD5")` and `hashlib.md5(...)` are genuine MD5 detections owned by
# ECD-SRC-MD5-001, so those rows allow it; the point of the row is that the new packs must
# not ALSO fire. A row that listed an empty `allowed` would be asserting that MD5 is
# undetectable in Java, which is false.
CROSS_LANGUAGE = [
    ("md5 token in java", "x.java", 'MessageDigest.getInstance("MD5");', ("ECD-SRC-MD5-001",)),
    ("md5 token in python", "x.py", "hashlib.md5(data)", ("ECD-SRC-MD5-001",)),
    ("sha1 token in c", "x.c", "SHA1_CTX ctx;", ()),
    ("ecdsa token in java", "x.java", 'KeyPairGenerator.getInstance("ECDSA");', ()),
    ("rsa-shal in python", "x.py", 'alg = "RSA-SHA1"', ()),
    ("aes-gcm token in go", "x.go", "// uses aes_gcm elsewhere", ()),
    ("thread_rng in python", "x.py", "# thread_rng equivalent", ()),
    ("modp5 in java", "x.java", 'String g = "modp5";', ()),
    ("rsa padding in java", "x.java", "Cipher.getInstance(\"RSA/ECB/PKCS1Padding\");",
     ("ECD-SRC-JAVA-CIPHER-001",)),
]

# (label, filename, content, pre-existing rules allowed to fire)
DECOYS = [
    # Comments are blanked before matching, so a named API in prose is not code.
    ("go api in comment", "a.go", "// TODO: move off rc4.NewCipher and des.NewCipher", ()),
    ("js api in comment", "a.js", "// never use Math.random() for a session token", ()),
    ("rust primitive in comment", "a.rs", "// we deliberately avoid SHA1 and MD5 here", ()),
    # The SAFE counterpart of each weak primitive. A rule set that flags the broken variant and
    # not the good one is over-broad, which is the more common way a scanner becomes noise.
    ("go aes is fine", "a.go", "b, _ := aes.NewCipher(key)", ()),
    ("go crypto/rand is correct", "a.go", "rand.Read(buf)", ()),
    ("js aes-256-gcm is fine", "a.js", "crypto.createCipheriv('aes-256-gcm', k, iv)", ()),
    ("js ed25519 is not rsa", "a.js", "crypto.createSign('ED25519')", ()),
    ("js strong dh group is fine", "a.js", "crypto.createDiffieHellman('modp2048');",
     ("ECD-SRC-ECDH-001",)),
    ("js absent minVersion is safe", "a.conf", "const o = { rejectUnauthorized: true };", ()),
    # A variable whose name merely CONTAINS a matched token. `\brand\.` in the Go PRNG rule is
    # qualified precisely so that `brand` cannot trigger it.
    ("go brand is not rand", "a.go", "brand := computeBrand();", ()),
    # A WebCrypto digest is a real detection, but it must not be reported as a signature.
    ("js digest is not a signature", "a.js", "crypto.subtle.digest('SHA-256', buf)", ()),
]


@pytest.fixture
def scanner():
    return ECDATScanner(enable_ml=False)


@pytest.mark.parametrize("label,filename,content,expected", POSITIVES,
                         ids=[p[0] for p in POSITIVES])
def test_multilang_positive_fires(scanner, tmp_path, label, filename, content, expected):
    """Each new rule must fire on a realistic call site for that API."""
    path = tmp_path / filename
    path.write_text(content + "\n", encoding="utf-8")
    fired = {f["rule_id"] for f in scanner._match_rules(str(path), content)} & _ALL_IDS
    missing = set(expected) - fired
    assert not missing, "%s: expected %s, got %s" % (label, sorted(expected), sorted(fired))


@pytest.mark.parametrize("label,filename,content,allowed", DECOYS, ids=[d[0] for d in DECOYS])
def test_multilang_decoy_silent(scanner, tmp_path, label, filename, content, allowed):
    """A decoy must produce no finding from the NEW packs, and nothing else either.

    The `allowed` column is empty for every current decoy. It exists so that a decoy which is
    genuinely detected by a pre-existing rule can be recorded as such instead of being deleted
    to make a test pass.
    """
    path = tmp_path / filename
    path.write_text(content + "\n", encoding="utf-8")
    fired = {f["rule_id"] for f in scanner._match_rules(str(path), content)} & _ALL_IDS
    new_fired = {r for r in fired if r.startswith(("ECD-GO-", "ECD-RUST-", "ECD-JS-"))}
    assert not new_fired, "%s: new pack fired %s" % (label, sorted(new_fired))
    assert fired == set(allowed), "%s: expected exactly %s, got %s" % (
        label, sorted(allowed), sorted(fired))


@pytest.mark.parametrize("label,filename,content,allowed", CROSS_LANGUAGE,
                         ids=[c[0] for c in CROSS_LANGUAGE])
def test_multilang_no_cross_language_leak(scanner, tmp_path, label, filename, content, allowed):
    """A token owned by one language's pack must not fire inside another language's file.

    This is the generalisation of the bare-`\\bMD5\\b` defect. Because rules are matched against
    text without regard to the file's extension, an unqualified token in a language pack silently
    becomes a rule for every other language too.
    """
    path = tmp_path / filename
    path.write_text(content + "\n", encoding="utf-8")
    fired = {f["rule_id"] for f in scanner._match_rules(str(path), content)} & _ALL_IDS
    new_fired = {r for r in fired if r.startswith(("ECD-GO-", "ECD-RUST-", "ECD-JS-"))}
    assert not new_fired, "%s (%s): the new packs leaked into %s: %s" % (
        label, content, filename, sorted(new_fired))
    assert fired == set(allowed), "%s: expected exactly %s, got %s" % (
        label, sorted(allowed), sorted(fired))


def test_no_duplicate_rule_for_existing_primitives():
    """Guard the deliberate omissions from the new packs.

    A language pack that re-matches a primitive an existing rule already owns does not add
    coverage -- it adds a second component at the same (file, line), and _finalise cannot
    collapse those because the dedup key includes rule_id. Five such rules were written in the
    first pass and all five were removed after the decoy run surfaced them. This test records
    which rule owns each primitive so re-adding a language alias fails loudly.
    """
    owned = {
        "ChaCha20Poly1305": "ECD-SRC-CHACHA-001",
        "X25519": "ECD-SRC-ECDH-001",
        "DiffieHellman": "ECD-SRC-ECDH-001",
        "Math.random": "ECD-SRC-JAVA-WEAKRNG-001",
        "minVersion": "ECD-CFG-TLS-001",
    }
    for token, owner in owned.items():
        assert owner in _ALL_IDS, "the owning rule %s no longer exists" % owner

    new_packs = [r for r in RULES
                 if r["id"].startswith(("ECD-GO-", "ECD-RUST-", "ECD-JS-"))]
    for rule in new_packs:
        for token, owner in owned.items():
            assert token not in rule["regex"], (
                "%s re-matches %s, which %s already owns" % (rule["id"], token, owner))


def test_string_literal_limitation_is_documented_not_accidental(tmp_path):
    """Pin the known engine-wide limitation so it is a decision, not a surprise.

    The engine blanks comments but does not parse string literals, so a crypto call quoted
    inside a string still matches. This is pre-existing for every language, not specific to the
    new pack. The test exists to make the behaviour EXPLICIT: if string handling is ever added,
    this fails and forces a deliberate decision about re-measuring the corpora.

    Written under `tmp_path`: `_match_rules` takes a path, and passing a bare relative name here
    litters the repository root with a.go/b.py/b.rb on every run.
    """
    sc = ECDATScanner(enable_ml=False)
    cases = [
        ("b.py", 'x = "hashlib.md5(data)"', "ECD-SRC-MD5-001"),   # pre-existing, Python
        ("b.rb", "puts \"OpenSSL::Cipher.new('aes-256-gcm')\"", "ECD-RB-AES-001"),
        ("a.go", 'log.Print("call des.NewCipher(key) later")', "ECD-GO-CIPHER-001"),
    ]
    for filename, content, expected in cases:
        path = tmp_path / filename
        path.write_text(content + "\n", encoding="utf-8")
        fired = {f["rule_id"] for f in sc._match_rules(str(path), content)} & _ALL_IDS
        assert expected in fired, (
            "%s: string-literal behaviour changed, so the limitation is no longer uniform; "
            "re-measure the corpora before changing this" % filename)


def test_every_new_rule_has_a_positive_sample():
    """No rule in the Go/Rust/JS packs may exist without a test that proves it fires."""
    covered = {rid for _, _, _, ids in POSITIVES for rid in ids}
    new_packs = {r["id"] for r in RULES
                 if r["id"].startswith(("ECD-GO-", "ECD-RUST-", "ECD-JS-"))}
    assert new_packs, "the new packs are missing entirely"
    assert not (new_packs - covered), "rules with no positive sample: %s" % sorted(
        new_packs - covered)
