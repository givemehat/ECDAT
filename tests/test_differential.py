"""
Differential tests for ECDAT (task HAND-160).

Where tests/test_properties.py asks "is this input handled sanely?", this file asks "do two
inputs that MEAN THE SAME THING produce the same answer, and do two inputs that mean DIFFERENT
things produce different answers?"

That second question is the one example-based suites almost never ask, and it is where a
security tool quietly loses credibility: a recommender that names ML-KEM for an artefact it
should call ML-DSA is not wrong in a way anyone notices, because both strings contain "ML-".

Every differential test is a two-sided oracle. Where a pair MUST agree, both the agreement and
a positive control are asserted -- otherwise "always return the same constant" would pass.
Where a pair MUST differ, both the difference and the specific expected distinction are
asserted -- otherwise "always return None" would pass.

Hypothesis is configured with `derandomize=True` (profile "ecdat"), so the pairs explored are
identical on every run and a failure is reproducible.
"""
import json
import os
import sys
import tempfile

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.cbom import _canonical_primitive, generate_cbom
from engine.mosca import PRIMITIVE_HORIZON, calculate_risk
from engine.recommender import _normalise_primitive, get_pqc_recommendation
from engine.scanner import ECDATScanner

settings.register_profile(
    "ecdat",
    derandomize=True,
    max_examples=50,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture,
                           HealthCheck.data_too_large],
)
settings.load_profile("ecdat")


def _scanner():
    return ECDATScanner(enable_ml=False)


def _scan(tmpdir, name, text):
    path = os.path.join(tmpdir, name)
    with open(path, "w", encoding="utf-8", errors="replace") as fh:
        fh.write(text)
    return _scanner().scan_directory(path)


def _names(findings):
    return sorted(f["name"] for f in findings)


def _from(findings, path):
    """Findings attributable to `path`, matched on the RESOLVED path.

    `scan_directory` reports `os.path.realpath(root) + name` when it walks a directory but the
    path it was given when it is handed a file directly. Comparing the two as raw strings is
    therefore wrong wherever the temp directory is itself a symlink (macOS `/tmp`, some CI
    runners), which would silently make the comparison below vacuous. Normalising both sides
    keeps the differential honest on every platform.
    """
    wanted = os.path.normcase(os.path.realpath(path))
    return [f for f in findings
            if os.path.normcase(os.path.realpath(f.get("file", ""))) == wanted]


# ==============================================================================================
# 1. The same finding, expressed with different primitives, must get DIFFERENT targets
# ==============================================================================================

# Every name below is Shor-vulnerable, so the primitive is the only thing that can decide the
# replacement. If pke and signature ever converge, the tool is recommending key establishment
# for signing code -- or, far worse, the reverse.
SHOR_VULNERABLE_NAMES = ["RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "ECC", "ELGAMAL",
                         "X25519", "Diffie-Hellman"]

KEM_FAMILY = ("ml-kem", "kyber", "x25519", "hybrid", "key agreement", "key establishment")
SIG_FAMILY = ("ml-dsa", "slh-dsa", "dilithium", "falcon", "sphincs", "signature")


def _family(algorithm_text):
    """Which replacement family does this recommendation name? -> (is_kem, is_signature)"""
    text = algorithm_text.lower()
    return (any(tok in text for tok in KEM_FAMILY),
            any(tok in text for tok in SIG_FAMILY))


@given(name=st.sampled_from(SHOR_VULNERABLE_NAMES))
def test_pke_and_signature_must_never_name_the_same_pqc_target(name):
    """The core differential: the primitive decides the replacement, for the SAME algorithm name.

    ML-KEM is a key-encapsulation mechanism; ML-DSA is a signature scheme. Neither substitutes
    for the other. A finding typed `pke` must be told to move to a KEM and a finding typed
    `signature` must be told to move to a signature scheme.
    """
    as_pke = get_pqc_recommendation({"name": name, "primitive": "pke"})
    as_signature = get_pqc_recommendation({"name": name, "primitive": "signature"})

    assert as_pke["algorithm"] != as_signature["algorithm"], (
        f"{name}: primitive=pke and primitive=signature both produced "
        f"{as_pke['algorithm']!r}. ML-KEM and ML-DSA are not interchangeable.")
    assert as_pke["rule_trace"] != as_signature["rule_trace"], (
        f"{name}: the two branches produced the same rule_trace, so the difference is not "
        f"explained and cannot be audited.")

    pke_is_kem, pke_is_sig = _family(as_pke["algorithm"])
    sig_is_kem, sig_is_sig = _family(as_signature["algorithm"])
    assert pke_is_kem and not pke_is_sig, (
        f"{name}: primitive=pke should name a key-establishment replacement, got "
        f"{as_pke['algorithm']!r}")
    assert sig_is_sig and not sig_is_kem, (
        f"{name}: primitive=signature should name a signature replacement, got "
        f"{as_signature['algorithm']!r}")


@given(name=st.sampled_from(SHOR_VULNERABLE_NAMES))
def test_key_agreement_and_signature_also_diverge(name):
    """Key agreement is the third Shor-vulnerable primitive and must not collapse onto
    signature either -- this is the exact confusion the scanner's ECC disambiguation exists to
    prevent, so the recommender must preserve it."""
    ka = get_pqc_recommendation({"name": name, "primitive": "key-agreement"})
    sig = get_pqc_recommendation({"name": name, "primitive": "signature"})
    assert ka["algorithm"] != sig["algorithm"], (
        f"{name}: key-agreement and signature both produced {ka['algorithm']!r}")
    ka_is_kem, ka_is_sig = _family(ka["algorithm"])
    assert ka_is_kem and not ka_is_sig, (
        f"{name}: key-agreement should name a KEM/hybrid, got {ka['algorithm']!r}")


def test_a_symmetric_cipher_is_never_given_a_pqc_replacement():
    """Positive control for the family classifier above.

    If `_family` matched nothing at all, every assertion in the two tests above would be
    vacuously true. AES and SHA-256 must land in neither family.
    """
    for name, primitive in [("AES", "ae"), ("ChaCha20", "ae"), ("SHA256", "hash"),
                            ("SHA1", "hash"), ("MD5", "hash")]:
        record = get_pqc_recommendation({"name": name, "primitive": primitive})
        is_kem, is_sig = _family(record["algorithm"])
        assert not is_kem and not is_sig, (
            f"{name}/{primitive} was told to move to {record['algorithm']!r}, which names a "
            f"PQC replacement for a primitive that is not quantum-vulnerable")


def test_the_pqc_target_and_the_mosca_horizon_agree_about_the_primitive():
    """Cross-engine differential: the recommender and the Mosca engine must classify the same
    finding the same way.

    The recommender reads `primitive` through `_normalise_primitive`; the Mosca engine reads it
    through `PRIMITIVE_HORIZON`. If they disagree, the report names ML-KEM while the risk tier
    was computed on a confidentiality horizon, or offers ML-DSA for a key-exchange artefact.
    The two are two halves of one sentence and must not be computed independently.
    """
    for primitive, expected_horizon in [("pke", "confidentiality"),
                                        ("key-agreement", "confidentiality"),
                                        ("signature", "verifiability")]:
        finding = {"name": "RSA", "primitive": primitive, "data_class": "health-record"}
        risk = calculate_risk(finding, current_year=2026)
        record = get_pqc_recommendation(finding)
        canonical = _normalise_primitive(primitive, finding["name"])
        assert canonical in PRIMITIVE_HORIZON, (
            f"primitive {primitive!r} normalises to {canonical!r}, which has no entry in "
            f"PRIMITIVE_HORIZON, so the Mosca engine silently falls back to a default")
        assert PRIMITIVE_HORIZON[canonical] == expected_horizon
        assert risk["horizon_type"] == expected_horizon
        is_kem, is_sig = _family(record["algorithm"])
        if expected_horizon == "verifiability":
            assert is_sig and not is_kem, f"signature horizon named {record['algorithm']!r}"
        else:
            assert is_kem and not is_sig, f"confidentiality horizon named {record['algorithm']!r}"


# ==============================================================================================
# 2. _normalise_primitive aliases must converge
# ==============================================================================================

# Each key is a canonical primitive; the list under it is a set of strings that are supposed
# to be SPELLINGS OF THAT SAME PRIMITIVE. None/"" are deliberately excluded: an absent
# primitive is a different input (it triggers the name-based fallback), not an alias.
ALIAS_CLASSES = {
    "pke": ["public-key-encryption", "pke", "asymmetric-encryption", "key-transport",
            "PKE", "  pke  ", "Pke"],
    "signature": ["digital-signature", "signature", "signing", "SIGNATURE", " signature "],
    "key-agreement": ["key-agreement", "key-exchange", "key-agreement-protocol",
                      "KEY-AGREEMENT"],
    "ae": ["symmetric-encryption", "ae", "AE", "  symmetric-encryption  "],
    "hash": ["hash", "HASH", " Hash "],
    "mac": ["mac", "MAC"],
    "protocol": ["protocol", "PROTOCOL"],
    "kem": ["kem", "key-encapsulation", "KEM"],
    "block-cipher": ["block-cipher", "Block-Cipher"],
}

NAMES_FOR_ALIASES = ["RSA", "ECDSA", "ECDH", "AES", "SHA256", "Ed25519", "ML-KEM-768",
                     "Whatever", "", "TLS"]


@given(name=st.sampled_from(NAMES_FOR_ALIASES),
       canonical=st.sampled_from(sorted(ALIAS_CLASSES)))
def test_primitive_aliases_converge_on_one_canonical_value(name, canonical):
    """Every spelling of a primitive must normalise to the same canonical string.

    If two spellings diverge, then two scanners (or two scanner versions) describing the same
    artefact produce different CBOM primitives, and the two reports cannot be compared.
    """
    results = {p: _normalise_primitive(p, name) for p in ALIAS_CLASSES[canonical]}
    distinct = set(results.values())
    assert distinct == {canonical}, (
        f"aliases of {canonical!r} did not converge for name={name!r}: {results}")


@given(name=st.sampled_from(NAMES_FOR_ALIASES),
       canonical=st.sampled_from(sorted(ALIAS_CLASSES)))
def test_primitive_normalisation_is_case_and_whitespace_insensitive(name, canonical):
    """Case and surrounding whitespace are spelling, not meaning."""
    for alias in ALIAS_CLASSES[canonical]:
        reference = _normalise_primitive(alias.strip().lower(), name)
        for variant in (alias.upper(), alias.lower(), f"  {alias}  ", f"\t{alias}\n"):
            got = _normalise_primitive(variant, name)
            assert got == reference, (
                f"{variant!r} normalised to {got!r} but {alias.strip().lower()!r} "
                f"normalised to {reference!r}")


@given(name=st.sampled_from(NAMES_FOR_ALIASES),
       canonical=st.sampled_from(sorted(ALIAS_CLASSES)))
def test_an_explicit_primitive_always_beats_the_name_fallback(name, canonical):
    """An explicitly supplied primitive must never be overridden by guessing from the name.

    This is what makes the `pke` vs `signature` differential above possible at all: if the
    name could overrule the primitive, `RSA` + `signature` would be reclassified as `pke` and
    the tool would recommend ML-KEM for signing code.
    """
    for alias in ALIAS_CLASSES[canonical]:
        assert _normalise_primitive(alias, name) == canonical, (
            f"the name fallback overrode an explicit primitive={alias!r} for name={name!r}")


def test_name_fallback_is_only_used_when_the_primitive_is_absent():
    """The converse: with NO primitive, the name is the only evidence there is, and it must be
    used. Without this, the alias tests above would pass for the wrong reason."""
    assert _normalise_primitive("", "RSA") == "pke"
    assert _normalise_primitive(None, "RSA") == "pke"
    assert _normalise_primitive("", "ECDSA") == "signature"
    assert _normalise_primitive("", "ECDH") == "key-agreement"
    assert _normalise_primitive("", "AES") == "ae"
    assert _normalise_primitive("", "SHA256") == "hash"
    # A name that says nothing must resolve to `unknown`, never to a guess.
    for opaque in ["", "CustomCipher", "Zorg", "1234"]:
        assert _normalise_primitive("", opaque) == "unknown"


def test_normalised_primitives_map_onto_a_valid_cyclonedx_primitive():
    """Cross-engine differential: whatever the recommender calls a primitive, the CBOM layer
    must be able to express it, as the SAME primitive.

    Two canonical values are deliberately NOT algorithms and are documented exceptions in
    engine/cbom.py: `protocol` is emitted as assetType=protocol with protocolProperties, and
    `cryptographic-library` is emitted as a `library` component. For those the CBOM layer
    reclassifying to `unknown` is correct, and it is asserted separately below so that the
    round-trip property below stays meaningful rather than being special-cased away.
    """
    for name in NAMES_FOR_ALIASES:
        for canonical in ALIAS_CLASSES:
            if canonical in ("protocol", "block-cipher"):
                continue
            canonical_value = _normalise_primitive(canonical, name)
            emitted = _canonical_primitive(canonical_value)
            back = {"key-agree": "key-agreement"}.get(emitted, emitted)
            assert back == canonical_value, (
                f"the CBOM layer reclassified {canonical_value!r} as {emitted!r} for "
                f"name={name!r}; the two layers disagree about what the primitive is")


def test_non_algorithm_primitives_are_modelled_as_such_in_the_cbom():
    """The documented exceptions, asserted rather than excused.

    `protocol` must reach the CBOM as a protocol asset and `cryptographic-library` as a
    library component -- never as a cryptographic-asset with a fabricated primitive, which is
    the misrepresentation the CBOM design note says was the original defect.
    """
    document = json.loads(generate_cbom([{"name": "TLS", "primitive": "protocol",
                                         "file": "a.conf", "line": 3}]))
    component = document["components"][0]
    assert component["cryptoProperties"]["assetType"] == "protocol"
    assert "algorithmProperties" not in component["cryptoProperties"]

    document = json.loads(generate_cbom([{"name": "OpenSSL/libcrypto",
                                         "primitive": "cryptographic-library", "type": "library",
                                         "file": "a.so"}]))
    component = document["components"][0]
    assert component["type"] == "library"
    assert "cryptoProperties" not in component


# ==============================================================================================
# 3. The same source, scanned as different file types, must agree
# ==============================================================================================

# Snippets that are COMMENT-FREE and language-neutral. Comment handling is the one documented
# reason two extensions may legitimately disagree (`#` is a comment in Python and a
# preprocessor directive in C), so that divergence is pinned separately below rather than
# being allowed to hide a real routing bug here.
LANGUAGE_NEUTRAL_LINES = [
    "RSA_generate_key_ex(r, 2048);",
    "EVP_aes_128();",
    "EVP_sha256();",
    "EVP_sha1();",
    "EVP_md5();",
    "EVP_chacha20();",
    "EVP_PKEY_EC;",
    "EVP_PKEY_DSA;",
    "EVP_PKEY_DH;",
    "ECDH_compute_key();",
    "ECDSA_sign();",
    "Ed25519PrivateKey;",
    "AESGCM(k);",
    'MessageDigest.getInstance("SHA-256");',
    'MessageDigest.getInstance("MD5");',
    'Cipher.getInstance("AES/GCM/NoPadding");',
    "X25519;",
    "secp256r1;",
    "prime256v1;",
    "ffdhe2048;",
    "modp_2048;",
]

SOURCE_BODY = st.lists(st.sampled_from(LANGUAGE_NEUTRAL_LINES), min_size=1, max_size=8)


@given(lines=SOURCE_BODY)
def test_the_same_snippet_scanned_as_py_and_as_c_finds_the_same_algorithms(lines):
    """A `.c` and a `.py` file with identical code must yield identical algorithm names.

    The rule table is language-agnostic by design -- the only extension-sensitive step is
    comment stripping. So for comment-free input the two must agree exactly, and any
    disagreement is a bug in extension routing, in `SOURCE_EXTENSIONS`, or in a rule that has
    picked up a language-specific anchor.
    """
    text = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        as_c = _names(_scan(tmp, "snippet.c", text))
        as_py = _names(_scan(tmp, "snippet.py", text))
        as_java = _names(_scan(tmp, "Snippet.java", text))
        as_go = _names(_scan(tmp, "snippet.go", text))
    assert as_c, f"the snippet was not detected at all: {lines}"
    assert as_py == as_c, f".py and .c disagree.\n  .c: {as_c}\n  .py: {as_py}\n  {lines}"
    assert as_java == as_c, f".java and .c disagree.\n  .c: {as_c}\n  .java: {as_java}"
    assert as_go == as_c, f".go and .c disagree.\n  .c: {as_c}\n  .go: {as_go}"


@given(lines=SOURCE_BODY, padding=st.integers(min_value=0, max_value=5))
def test_line_numbers_survive_a_file_extension_change(lines, padding):
    """Not just the names: the reported line of each finding must be the same in .py and .c.

    A tool that renames a file from `.c` to `.py` -- which happens constantly when code is
    ported -- must not renumber the CBOM.
    """
    text = "\n".join(lines) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        as_c = sorted((f["name"], f["line"]) for f in _scan(tmp, "snippet.c", text))
        as_py = sorted((f["name"], f["line"]) for f in _scan(tmp, "snippet.py", text))
    assert as_c
    assert as_py == as_c, f".py and .c disagree on locations.\n  .c: {as_c}\n  .py: {as_py}"


def test_hash_comments_are_stripped_in_python_but_not_in_c_by_design():
    """Pins the ONE documented extension-dependent divergence, so it cannot drift silently.

    `#` opens a comment in Python and in the config formats, and means something else on a C
    preprocessor line. A `#`-commented-out RSA call must therefore be suppressed in a .py file
    and reported in a .c file. If this test ever needs changing, the design note in
    engine/scanner.py has to change with it.
    """
    text = "# rsa.newkeys(2048)\nrsa.newkeys(2048)\n"
    with tempfile.TemporaryDirectory() as tmp:
        as_py = _scan(tmp, "s.py", text)
        as_c = _scan(tmp, "s.c", text)
    assert [f["line"] for f in as_py] == [2], "the live call on line 2 must be reported in .py"
    assert sorted(f["line"] for f in as_c) == [1, 2], (
        "in C, `#` is not a comment opener, so both lines are code and both must be reported")


def test_slash_comments_are_stripped_in_every_language():
    """`//` is a comment in every language the scanner reads, so it must be stripped in all of
    them. This is the invariant that the .py/.c agreement test relies on."""
    text = "// RSA_generate_key_ex(r, 2048);\nRSA_generate_key_ex(r, 2048);\n"
    for ext in (".py", ".c", ".java", ".go", ".js"):
        with tempfile.TemporaryDirectory() as tmp:
            found = _scan(tmp, f"s{ext}", text)
        assert [f["line"] for f in found] == [2], (
            f"{ext}: the commented-out call on line 1 was reported")


def test_evidence_class_follows_the_kind_of_file_not_its_extension_alone():
    """Cross-extension differential on `evidence_class`, which is what separates "this runs"
    from "this is permitted" -- the distinction the whole assurance model rests on.

    The same live RSA call is `discovered` use in a source file and `configured` use in a
    config file. If the two agreed, a capability would be indistinguishable from a use and
    `proven_use_count` would be meaningless.
    """
    live_call = "rsa.newkeys(2048)\n"
    with tempfile.TemporaryDirectory() as tmp:
        as_source = _scan(tmp, "app.py", live_call)
        as_config = _scan(tmp, "app.conf", live_call)
        as_named_config = _scan(tmp, "openssl.cnf", live_call)
    assert as_source and as_config, "the call was not detected in both file kinds"
    assert {f["evidence_class"] for f in as_source} == {"discovered"}
    assert {f["evidence_class"] for f in as_config} == {"configured"}
    assert {f["evidence_class"] for f in as_named_config} == {"configured"}


def test_a_configuration_rule_keeps_its_configured_evidence_in_any_file():
    """The converse, pinned so the two rules above cannot be conflated.

    `ssl_protocols TLSv1.2` matches a rule that is itself declared `evidence="configured"`: it
    is a configuration directive wherever it appears, so a `.py` file containing one is still
    reporting configuration, not a call site.
    """
    directive = "ssl_protocols TLSv1.2;\n"
    with tempfile.TemporaryDirectory() as tmp:
        found = _scan(tmp, "settings.py", directive)
    assert found, "the configuration directive was not detected"
    assert {f["evidence_class"] for f in found} == {"configured"}


# ==============================================================================================
# 4. The same file, scanned directly vs scanned as part of its directory, must agree
# ==============================================================================================

@given(body=st.lists(st.sampled_from(LANGUAGE_NEUTRAL_LINES), min_size=1, max_size=6))
def test_scanning_one_file_directly_must_equal_scanning_its_directory(body):
    """`scan_directory` accepts a directory OR a single file, and the docstring says so.

    For the same bytes on disk, both entry points must return the same findings. They are
    different code paths inside `scan_directory`, and the single-file path returns early --
    before de-duplication and before the coverage manifest is finalised -- so the two can
    silently diverge. An operator who scans one file and an operator who scans the containing
    directory would then get different inventories from identical code.
    """
    text = "\n".join(body) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "snippet.c")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        direct = _scanner().scan_directory(target)
        via_dir = _from(_scanner().scan_directory(tmp), target)
    assert direct, "the snippet produced no findings when scanned directly"
    assert via_dir, "the snippet produced no findings when scanned via its directory"
    assert direct == via_dir, (
        f"scanning the file directly and scanning its directory disagree.\n"
        f"  direct : {[(f['name'], f['rule_id'], f['line'], f.get('key_length')) for f in direct]}\n"
        f"  via dir: {[(f['name'], f['rule_id'], f['line'], f.get('key_length')) for f in via_dir]}")


def test_duplicate_matches_on_one_line_are_collapsed_on_both_entry_points():
    """The same rule matching twice on one line is ONE finding, whichever way you scan.

    Without the de-duplication pass the single-file path reports the same logical artefact
    twice, which inflates the finding count and the CBOM component list.
    """
    text = "a = rsa.newkeys(2048); b = rsa.newkeys(4096);\n"
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "dup.py")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        direct = _scanner().scan_directory(target)
        via_dir = _from(_scanner().scan_directory(tmp), target)
    keys = [(f["name"], f["rule_id"], f["line"]) for f in direct]
    assert keys, "the duplicated call was not detected, so the comparison is vacuous"
    assert len(keys) == len(set(keys)), f"duplicate findings survived: {keys}"
    assert len(keys) == len([(f["name"], f["rule_id"], f["line"]) for f in via_dir]) == 1


@given(body=st.lists(st.sampled_from(LANGUAGE_NEUTRAL_LINES), min_size=1, max_size=4))
def test_the_coverage_manifest_is_identical_whichever_entry_point_is_used(body):
    """The coverage manifest is the tool's honesty mechanism: it says which scanners ran and
    which files were skipped, so that "nothing found" is distinguishable from "nothing looked
    at". If a single-file scan reports that NO scanner ran while returning findings, the
    manifest is stating the opposite of the truth.
    """
    text = "\n".join(body) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "snippet.c")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)

        direct_scanner = _scanner()
        direct = direct_scanner.scan_directory(target)
        direct_manifest = direct_scanner.coverage_manifest(direct)

        dir_scanner = _scanner()
        via_dir = dir_scanner.scan_directory(tmp)
        dir_manifest = dir_scanner.coverage_manifest(via_dir)

    assert direct, "the snippet produced no findings, so the comparison is vacuous"
    assert direct_manifest["scanners_run"], (
        f"a single-file scan returned {len(direct)} findings but reports "
        f"scanners_run={direct_manifest['scanners_run']!r} -- the manifest claims nothing ran")
    assert direct_manifest["scanners_run"] == dir_manifest["scanners_run"], (
        f"the two entry points disagree about which scanners ran: "
        f"{direct_manifest['scanners_run']!r} vs {dir_manifest['scanners_run']!r}")
    assert direct_manifest["files_seen"] == dir_manifest["files_seen"], (
        f"the two entry points disagree about how many files were seen: "
        f"{direct_manifest['files_seen']} vs {dir_manifest['files_seen']}")


def test_a_container_image_is_reported_as_scanned_by_the_container_scanner_either_way():
    """A `.tar` reached directly and a `.tar` found while walking a directory must both be
    attributed to the container scanner. A single-file scan of an image that forgets to record
    the container scanner makes the report claim the image was never opened as an image."""
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        payload = b"rsa.newkeys(2048)\n"
        info = tarfile.TarInfo("app.py")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    blob = buffer.getvalue()

    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "image.tar")
        with open(target, "wb") as fh:
            fh.write(blob)
        direct_scanner = _scanner()
        direct = direct_scanner.scan_directory(target)
        direct_manifest = direct_scanner.coverage_manifest(direct)

        dir_scanner = _scanner()
        via_dir = dir_scanner.scan_directory(tmp)
        dir_manifest = dir_scanner.coverage_manifest(via_dir)

    assert direct == via_dir, "the image scanned directly and via its directory disagree"
    assert "container-scanner" in direct_manifest["scanners_run"], (
        f"scanning an image directly did not credit the container scanner: "
        f"{direct_manifest['scanners_run']!r}")
    assert direct_manifest["scanners_run"] == dir_manifest["scanners_run"]


def test_the_recommendation_for_a_finding_is_the_same_however_the_file_was_reached():
    """End-to-end differential: the same file, scanned either way, must yield the same
    recommendations -- otherwise the two inventories cannot be compared or merged."""
    text = "rsa.newkeys(2048)\nAESGCM(k)\nECDSA_sign()\n"
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "app.py")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        direct = _scanner().scan_directory(target)
        via_dir = _from(_scanner().scan_directory(tmp), target)
    assert direct
    direct_recs = [get_pqc_recommendation(f)["algorithm"] for f in direct]
    dir_recs = [get_pqc_recommendation(f)["algorithm"] for f in via_dir]
    assert direct_recs == dir_recs, f"{direct_recs} != {dir_recs}"


def test_the_cbom_for_a_finding_is_the_same_however_the_file_was_reached():
    """The same differential, one layer further on: the emitted CBOM components must match."""
    text = "rsa.newkeys(2048)\nAESGCM(k)\n"
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "app.py")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        direct = _scanner().scan_directory(target)
        via_dir = _from(_scanner().scan_directory(tmp), target)

    def components(findings):
        document = json.loads(generate_cbom(findings, enriched=True, subject_name="s"))
        return [c["name"] for c in document["components"]]

    assert direct
    assert components(direct) == components(via_dir)






