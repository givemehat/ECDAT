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
    # Go 1.24 crypto/mlkem, FIPS 203. The x/crypto corpus carries a real hybrid ML-KEM-768 +
    # X25519 SSH key exchange in ssh/mlkem.go, and before these rules it scored ZERO findings.
    ("go mlkem768", "a.go", "dk, err := mlkem.NewDecapsulationKey768(seed)", ["ECD-GO-PQKEM-001"]),
    ("go mlkem1024", "a.go", "dk, err := mlkem.NewDecapsulationKey1024(seed)", ["ECD-GO-PQKEM-002"]),
    # NO mlkem512 sample. FIPS 203 has three parameter sets, but Go's crypto/mlkem ships only
    # 768 and 1024, so an ML-KEM-512 rule asserted an API no implementation exposes. A test
    # asserting a rule fires on a non-existent API is a test that protects a fiction.
    # --- Go SSH mode-table and import/declaration idioms (loop 8) -------------------------------
    ("go cipherModes AES128", "a.go",
     "cipherModes[CipherAES128CTR] = &cipherMode{16, aes.BlockSize, nil}",
     ["ECD-GO-SSHTBL-AES"]),
    ("go cipherModes RC4", "a.go", "cipherModes[InsecureCipherRC4128] = &cipherMode{16, 0, nil}",
     ["ECD-GO-SSHTBL-RC4"]),
    ("go cipherModes 3DES", "a.go", "cipherModes[InsecureCipherTripleDESCBC] = &cipherMode{24, 0, nil}",
     ["ECD-GO-SSHTBL-3DES"]),
    ("go macModes HMAC", "a.go", "macModes[HMACSHA512ETM] = &macMode{64, true, nil}",
     ["ECD-GO-SSHTBL-MAC"]),
    ("go import aes", "a.go", '\t"crypto/aes"', ["ECD-GO-IMPORT-007"]),
    ("go import sha512", "a.go", '\t"crypto/sha512"', ["ECD-GO-IMPORT-010"]),
    ("go hash binding", "a.go", "Hash:      crypto.SHA256,", ["ECD-GO-HASHBIND-001"]),
    ("go chacha receiver decl", "a.go",
     "func (c *chacha20Poly1305Cipher) readCipherPacket(n uint32) {", ["ECD-GO-DECL-001"]),
    ("go newAESCTR decl", "a.go", "func newAESCTR(key, iv []byte) (cipher.Stream, error) {",
     ["ECD-GO-DECL-002"]),
    ("go poly1305 verify", "a.go", "if !poly1305.Verify(&mac, c.buf[:n], &k) {", ["ECD-GO-DECL-006"]),
    ("go import md5", "a.go", '\t"crypto/md5"', ["ECD-GO-IMPORT-001"]),
    ("go import sha1", "a.go", '\t"crypto/sha1"', ["ECD-GO-IMPORT-002"]),
    ("go import sha256", "a.go", '\t"crypto/sha256"', ["ECD-GO-IMPORT-003"]),
    ("go import hmac", "a.go", '\t"crypto/hmac"', ["ECD-GO-IMPORT-004"]),
    ("go import des", "a.go", '\t"crypto/des"', ["ECD-GO-IMPORT-005"]),
    ("go import rc4", "a.go", '\t"crypto/rc4"', ["ECD-GO-IMPORT-006"]),
    ("go import chacha20", "a.go", '\t"golang.org/x/crypto/chacha20"', ["ECD-GO-IMPORT-008"]),
    ("go import curve25519", "a.go", '\t"golang.org/x/crypto/curve25519"', ["ECD-GO-IMPORT-009"]),
    ("go newTripleDES decl", "a.go", "func newTripleDESCBCCipher(key, iv, macKey []byte) {",
     ["ECD-GO-DECL-003"]),
    ("go newRC4 decl", "a.go", "func newRC4(key, iv []byte) (cipher.Stream, error) {",
     ["ECD-GO-DECL-004"]),
    ("go curve25519 var", "a.go", "var c25519kp curve25519KeyPair", ["ECD-GO-DECL-005"]),
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

# Three defects found by running the tool over golang.org/x/crypto, NOT by reading the rules.
# All three are the same shape as the leak class above -- a token that is right in one language
# and wrong in another -- but each was found by real production code rather than by inspection,
# which is the argument for keeping a corpus at all.
#
# Line 1 is the decisive one: `c.rand()` is a method on an OTR Conversation that returns a
# crypto/rand io.Reader. It is a CSPRNG wrapper, and the PHP and Ruby PRNG rules were both
# reporting it as a WEAK generator. ECD-PHP-WEAKRNG-001's lookbehind omitted `.` while
# ECD-RB-WEAKRNG-001's had it -- two rules with one idea and two different guards.
CORPUS_FOUND = [
    ("go c.rand() is a CSPRNG wrapper", "otr.go",
     "_, err := io.ReadFull(c.rand(), buf)", ()),
    ("go method decl is not a weak PRNG", "otr.go",
     "func (c *Conversation) rand() io.Reader {", ("ECD-PHP-WEAKRNG-001", "ECD-RB-WEAKRNG-001")),
    # `pk.ecdh` is a PublicKey STRUCT FIELD in the OpenPGP code. `pk.ecdh.parse(r)` and
    # `pk.ecdh.serialize(w)` are packet serialisation, not the crypto/ecdh package. The Go pack's
    # `\becdh\.\w+\(` matched all three, so the corpus reported ECDH where there is none.
    ("go ecdh struct field is not the package", "x.go",
     "if err = pk.ecdh.parse(r); err != nil {", ()),
    ("go ecdh serialize is not the package", "x.go",
     "return pk.ecdh.serialize(w)", ()),
    # X25519 is owned by ECD-SRC-ECDH-001. The Go pack briefly also matched `ecdh.X25519()`,
    # which put two ECDH components on one line -- the same duplicate class as loop 4's TLS.
    ("go ecdh.X25519 not duplicated", "x.go",
     "curve := ecdh.X25519()", ("ECD-SRC-ECDH-001",)),
    # ML-KEM is the positive case: FIPS 203, NIST category 3, and entirely invisible before.
    ("go mlkem768 detected", "x.go",
     "dk, err := mlkem.NewDecapsulationKey768(seed)", ("ECD-GO-PQKEM-001",)),
    ("go mlkem1024 detected", "x.go",
     "dk, err := mlkem.NewDecapsulationKey1024(seed)", ("ECD-GO-PQKEM-002",)),
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


@pytest.mark.parametrize("label,filename,content,allowed", CORPUS_FOUND,
                         ids=[c[0] for c in CORPUS_FOUND])
def test_defects_found_by_the_go_corpus(scanner, tmp_path, label, filename, content, allowed):
    """Regression guard for defects that only real production code exposed.

    Each row is a line copied from golang.org/x/crypto at the pinned commit. They are kept
    verbatim rather than paraphrased so a future change that re-breaks one of them fails here
    instead of surviving until the next corpus run.
    """
    path = tmp_path / filename
    path.write_text(content + "\n", encoding="utf-8")
    fired = {f["rule_id"] for f in scanner._match_rules(str(path), content)} & _ALL_IDS
    assert fired == set(allowed), "%s: expected exactly %s, got %s" % (
        label, sorted(allowed), sorted(fired))


def test_mlkem_is_a_standardised_algorithm_not_a_weak_primitive():
    """ML-KEM must be reported as ML-KEM, never collapsed into a weak-ECDH finding.

    ECDAT already classifies ML-KEM-768 at NIST category 3 in engine/cbom.py. A Go estate using
    `crypto/mlkem` therefore has a POST-QUANTUM key exchange in production, and reporting it as
    generic ECDH -- or as nothing at all -- is the difference between "already migrated" and
    "needs migration".

    Only the parameter sets Go ACTUALLY SHIPS are asserted. FIPS 203 defines three, but
    crypto/mlkem exposes only 768 and 1024; an earlier version of this test asserted a 512 rule
    fires, which protected a rule matching `mlkem.GenerateKey512` -- an API that does not exist.
    """
    sc = ECDATScanner(enable_ml=False)
    for level, rule in (("768", "ECD-GO-PQKEM-001"), ("1024", "ECD-GO-PQKEM-002")):
        content = "dk, err := mlkem.NewDecapsulationKey%s(seed)" % level
        found = {f["name"] for f in sc._match_rules("x.go", content)}
        assert "ML-KEM-%s" % level in found, "ML-KEM-%s not named correctly: %s" % (level, found)
        assert "ECDH" not in found, "ML-KEM-%s must not be reported as ECDH" % level
        assert rule in {f["rule_id"] for f in sc._match_rules("x.go", content)}

    # Go does not expose ML-KEM-512, and neither do we.
    gone = {f["rule_id"] for f in sc._match_rules("x.go", "k, _ := mlkem.GenerateKey512()")}
    assert not gone, "an ML-KEM-512 rule exists for an API Go does not ship: %s" % gone


def test_ssh_cipher_wire_names_are_not_mislabelled_as_aes():
    """Two ciphers were being reported as name=AES while sitting in a rule declared as AES.

    `ECD-SRC-SSH-CIPHER-001` listed `3des-cbc` and `ECD-SRC-SSH-CIPHER-002` listed
    `chacha20-poly1305@openssh.com`, so `InsecureCipherTripleDESCBC = "3des-cbc"` and
    `CipherChaCha20Poly1305 = "chacha20-poly1305@openssh.com"` both came out as AES. 3DES now
    belongs to ECD-SRC-SSH-LEGACY-001 and ChaCha20 has its own rule, so the names must be right.
    Found by adversarial review against real x/crypto lines, not by reading the patterns.
    """
    sc = ECDATScanner(enable_ml=False)
    for wire, want, must_not in (
            ('"chacha20-poly1305@openssh.com"', "ChaCha20", "AES"),
            ('"3des-cbc"', "3DES", "AES"),
            ('"aes128-ctr"', "AES", "3DES")):
        found = sc._match_rules("x.go", wire)
        names = {f["name"] for f in found}
        assert want in names, "%s should be reported as %s, got %s" % (wire, want, names)
        assert must_not not in names, (
            "%s must not be reported as %s (it was, via a rule declared for another cipher)"
            % (wire, must_not))


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
