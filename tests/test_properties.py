"""
Property-based tests for the ECDAT engines (task HAND-160).

WHY hypothesis AND a seeded harness
------------------------------------
`pip show hypothesis` reported "Package(s) not found" on a fresh checkout, so hypothesis was
installed for this task (6.168.1) and is used for the *generative* properties. It is configured
with ``derandomize=True`` (profile "ecdat" below), which makes the example sequence a pure
function of the test file: a CI run and a local run explore exactly the same inputs, so a
failure is always reproducible. Determinism is worth more than extra random exploration here --
this tool's output goes into a signed, diffed inventory.

The systematic cross-products (recommender totality, CBOM schema) do NOT use hypothesis at all.
They are exhaustive ``itertools.product`` enumerations over a declared input domain, because
the brief asks for the FULL cross-product, not a sample, and an exhaustive enumeration is both
complete and trivially reproducible.

Every property below is falsifiable. Where one is currently RED it is because the engine has a
real defect; the assertion has deliberately NOT been weakened and the test has NOT been marked
xfail. Minimal reproducers are in the accompanying bug report.
"""
import itertools
import json
import os
import sys
import tempfile
from decimal import Decimal

import jsonschema
import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.cbom import generate_cbom
from engine.fspolicy import resolve_within
from engine.mosca import calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.scanner import ECDATScanner

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(ROOT, "schemas", "bom-1.7.schema.json")

# Deterministic hypothesis: identical examples on every run, in CI and locally.
settings.register_profile(
    "ecdat",
    derandomize=True,
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture,
                           HealthCheck.data_too_large],
)
settings.load_profile("ecdat")


# ==============================================================================================
# Input domains
# ==============================================================================================

# Printable ASCII plus the characters that actually stress the scanner: comment openers and
# closers, quote characters, backslashes, newlines, NUL, and multi-byte code points.
TEXT_ALPHABET = (
    "".join(chr(c) for c in range(32, 127))
    + "\n\r\t\x00\x0b\x0c\\'\"`#/*"
    + "\u00e9\u00fc\u4e2d\U0001F600 "
)

TEXT = st.text(alphabet=TEXT_ALPHABET, max_size=3000)

SOURCE_EXTS = st.sampled_from([".py", ".c", ".java", ".js", ".go", ".rs", ".cs", ".conf",
                               ".yaml", ".json", ".toml", ".txt", ".md", ".properties"])

# --- recommender input domain (exhaustive, not sampled) ---------------------------------------
REC_NAMES = [
    "RSA", "ECDSA", "ECDH", "Ed25519", "DSA", "DH", "AES", "ChaCha20", "SHA256", "SHA1",
    "MD5", "TLS", "LEGACY-CIPHER", "ML-KEM-768", "ML-DSA-44", "OpenSSL/libcrypto", "",
    None, 0, 123, -1, 3.5, True, [], {}, ("RSA",), "  ", "\u00e9\u00e8", "x" * 512,
]
REC_PRIMITIVES = [
    "pke", "signature", "key-agreement", "ae", "hash", "mac", "block-cipher", "kem", "protocol",
    "cryptographic-library", "unknown", "public-key-encryption", "digital-signature",
    "symmetric-encryption", "key-transport", "asymmetric-encryption", "key-exchange",
    "key-encapsulation", "signing", "library", "neural-detected", "nonsense", "",
    "  PKE  ", None, 0, 1, True, [], {}, 3.5, "pke; DROP TABLE",
]
REC_USES = ["tls", "signing", "at-rest", "encryption", "storage", "", "  ", None, 0, 1, True,
            [], {}, "at rest"]
REC_EVIDENCE = ["discovered", "configured", "declared", "negotiated", "observed", "capability",
                "dependency", "certified", "", None, 0, 1, True, [], {}]

# --- CBOM finding domain ---------------------------------------------------------------------
CBOM_NAMES = ["RSA", "ECDSA", "ECDH", "AES", "ChaCha20", "SHA256", "SHA1", "MD5", "Ed25519",
              "DSA", "DH", "TLS", "LEGACY-CIPHER", "ML-KEM-768", "OpenSSL/libcrypto", "unknown"]
CBOM_PRIMITIVES = ["pke", "signature", "key-agreement", "ae", "hash", "protocol",
                   "cryptographic-library", "unknown", "kem", "mac", "block-cipher",
                   "public-key-encryption", "digital-signature", "nonsense"]
CBOM_KEY_SIZES = [None, 128, 192, 256, 384, 521, 2048, 4096, "2048"]
# Real cipher modes. Only a subset of these is in the CycloneDX `mode` enum.
CBOM_MODES = ["GCM", "gcm", "CBC", "CTR", "OFB", "CFB", "ECB", "CCM", "other", "unknown",
              "XTS", "GCM-SIV", "EAX", "OCB", "SIV", "KW", "wrap"]

# --- fspolicy path components ----------------------------------------------------------------
PATH_COMPONENTS = [
    "..", ".", "", " ", "sub", "a.py", "etc", "passwd", "Windows", "System32", "config",
    "SAM", "Users", "home", "root", "etc\\passwd", "~", "~root", "....//", "..\\..",
    "sub\\..\\..", "link", "link.py", "trailing..", "..trailing", "a..b", "....",
    "\u03a9", "sp ace", "C:", "C:\\", "\\\\server\\share", "%2e%2e", "\x00", "\n",
]
def _write(tmpdir, name, data, binary=False):
    path = os.path.join(tmpdir, name)
    parent = os.path.dirname(path)
    if parent and not os.path.isdir(parent):
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb" if binary else "w",
              **({} if binary else {"encoding": "utf-8", "errors": "replace"})) as fh:
        fh.write(data)
    return path


_VALIDATOR = None


def _schema_validator():
    """Compiled once: rebuilding the validator re-parses the whole 1.7 schema every call."""
    global _VALIDATOR
    if _VALIDATOR is None:
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            schema = json.load(fh)
        _VALIDATOR = jsonschema.validators.validator_for(schema)(schema)
    return _VALIDATOR


def _schema_errors(document):
    errors = sorted(_schema_validator().iter_errors(document),
                    key=lambda e: list(e.absolute_path))
    return "\n".join(
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}" for e in errors[:6])


def _scanner():
    return ECDATScanner(enable_ml=False)


def _same_file(a, b):
    """Compare two paths after resolution.

    `scan_directory` reports `realpath(root) + name` when it walks a directory but the path it
    was handed when it is given a file directly, so a raw string comparison is wrong wherever
    the temp directory is itself a symlink -- which would silently make the cross-entry-point
    comparisons vacuous on macOS and on some CI runners.
    """
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


# ==============================================================================================
# 1. SCANNER -- determinism
# ==============================================================================================

@given(text=TEXT, ext=SOURCE_EXTS)
def test_scanning_the_same_file_twice_yields_identical_output(text, ext):
    """Scanning is a pure function of file content: same bytes in, same findings out.

    A scanner whose output drifts between runs cannot back a signed or diffed inventory, so
    this is a correctness property, not a nicety.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, f"sample{ext}", text)
        first = _scanner().scan_directory(path)
        second = _scanner().scan_directory(path)
        third = _scanner().scan_directory(path)
    assert first == second == third


@given(text=TEXT, ext=SOURCE_EXTS)
def test_scanning_is_independent_of_unrelated_files_in_the_directory(text, ext):
    """Findings for one file must not depend on what else sits beside it.

    Catches cross-file state leaking between scans: a cache keyed too loosely, a module-level
    regex carrying last-match state, a coverage counter folded into the finding.
    """
    with tempfile.TemporaryDirectory() as tmp:
        alone = _write(tmp, "alone.py", "rsa.newkeys(2048)\n")
        expected = _scanner().scan_directory(alone)
        _write(tmp, "noise.c", text)
        _write(tmp, "noise2.conf", text)
        with_noise = [f for f in _scanner().scan_directory(tmp) if _same_file(f["file"], alone)]
    assert expected, "the RSA call was not detected, so the comparison is vacuous"
    assert with_noise, "the target file produced no findings when scanned via its directory"
    assert expected == with_noise


# ==============================================================================================
# 2. SCANNER -- totality
# ==============================================================================================

@given(text=TEXT, ext=SOURCE_EXTS)
def test_scanning_arbitrary_text_never_raises(text, ext):
    """Any text at all is a legal input. The scanner returns a list; it does not raise."""
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, f"sample{ext}", text)
        result = _scanner().scan_directory(path)
    assert isinstance(result, list)
    for finding in result:
        assert isinstance(finding, dict)
        assert "name" in finding and "primitive" in finding and "rule_id" in finding


@given(text=TEXT, ext=SOURCE_EXTS)
def test_every_finding_carries_the_keys_the_downstream_engines_require(text, ext):
    """The recommender, the CBOM and the Mosca engine read specific keys. A finding missing one
    is a latent crash three modules downstream, where the stack trace points nowhere useful."""
    required = {"file", "name", "primitive", "rule_id", "scanner", "evidence_class", "uses"}
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, f"sample{ext}", text)
        result = _scanner().scan_directory(path)
    for finding in result:
        missing = required - set(finding)
        assert not missing, f"finding missing {missing}: {finding}"


# ==============================================================================================
# 3. SCANNER -- line-number sanity (this is what guards comment blanking)
# ==============================================================================================

@given(text=TEXT, ext=SOURCE_EXTS)
def test_finding_line_is_within_the_files_line_count(text, ext):
    """1 <= line <= the file's real line count, for every finding that carries a line.

    `_strip_comments` blanks comments rather than deleting them precisely so that byte offsets
    -- and therefore line numbers -- survive. This is the invariant that justifies the choice.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, f"sample{ext}", text)
        result = _scanner().scan_directory(path)
    line_count = text.count("\n") + 1
    for finding in result:
        line = finding.get("line")
        if line is None:
            continue
        assert isinstance(line, int) and not isinstance(line, bool), \
            f"line must be an int, got {line!r} in {finding}"
        assert line >= 1, f"line {line} < 1 in {finding}"
        assert line <= line_count, \
            f"line {line} exceeds the file's {line_count} lines in {finding}"


# A rule hit that must fire, preceded by each comment construct the scanner strips.
_COMMENT_PREFIXES = [
    "/* {pad} */\n",
    "/*\n{pad}\n*/\n",
    "/*\n{pad}\n*/\n{pad}\n",
    '"""\n{pad}\n"""\n',
    "'''\n{pad}\n'''\n",
    "# {pad}\n{pad}\n",
    "// {pad}\n{pad}\n",
    "/* {pad} */ {pad} // x\n",
    "/* {pad} */ /* {pad} */\n",
    "# {pad}\n/* {pad}\n multiline\n*/\n{pad}\n",
]

# Rule hits that must fire, for C and for Python. Each is a COMPLETE call expression, because
# several rules anchor on the opening parenthesis -- a bare `AESGCM` is genuinely not a finding.
_C_RULE_HITS = ["RSA_generate_key_ex", "EVP_aes_128", "EVP_sha256", "EVP_PKEY_EC",
                "EVP_chacha20", "EVP_md5", "EVP_sha1", "EVP_PKEY_DSA", "EVP_PKEY_DH",
                "ECDH_compute_key", "ECDSA_sign", "Ed25519PrivateKey", "AESGCM(k)",
                'Cipher.getInstance("AES/GCM/NoPadding")',
                'MessageDigest.getInstance("SHA-256")']
_PY_RULE_HITS = ["rsa.newkeys(2048)", "rsa.generate_private_key(65537, 2048)",
                 "hashes.SHA256(b'x')", "hashes.SHA1(b'x')", "AESGCM(k)",
                 "ec.generate_private_key(ec.SECP256R1())", "ec.ECDSA(h)",
                 "X25519", "rsa.PSS(mgf=MGF1(SHA256()), salt_length=32)",
                 "padding.PSS", "PKCS1_v1_5"]

# Padding deliberately contains no quote characters. Three quotes in a row would change the
# STRUCTURE of the file (opening or closing a docstring) rather than the offsets under test,
# and a test that fails because it built a different language is not measuring anything.
_PAD_ALPHABET = "abcXYZ \n\t/*#"


@given(prefix_index=st.integers(min_value=0, max_value=len(_COMMENT_PREFIXES) - 1),
       second_index=st.integers(min_value=0, max_value=len(_COMMENT_PREFIXES) - 1),
       pad=st.text(alphabet=_PAD_ALPHABET, max_size=400),
       hit_index=st.integers(min_value=0, max_value=len(_C_RULE_HITS) - 1),
       filler=st.integers(min_value=0, max_value=40))
def test_comment_blanking_preserves_line_offsets_for_c_files(prefix_index, second_index, pad,
                                                            hit_index, filler):
    """A finding after any combination of comments must report its TRUE physical line.

    The direct test of the "blank, don't delete" design: if any stripping path ever removes a
    newline, every location after it silently shifts and the CBOM points at the wrong line
    with total confidence.
    """
    head = _COMMENT_PREFIXES[prefix_index].format(pad=pad)
    middle = _COMMENT_PREFIXES[second_index].format(pad=pad)
    filler_lines = "".join(f"int v{k} = {k}; /* filler */\n" for k in range(filler))
    hit = _C_RULE_HITS[hit_index]
    text = f"{head}{middle}{filler_lines}{hit};\n"
    expected_line = text[: text.index(hit)].count("\n") + 1

    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "sample.c", text)
        result = _scanner().scan_directory(path)

    assert result, f"rule hit {hit!r} was not detected at all -- the offsets test cannot run"
    for finding in result:
        if finding.get("line") is not None:
            assert finding["line"] == expected_line, (
                f"line {finding['line']} != true line {expected_line}; comment blanking "
                f"shifted offsets\n--- source ---\n{text}\n--- finding ---\n{finding}")


@given(prefix_index=st.integers(min_value=0, max_value=len(_COMMENT_PREFIXES) - 1),
       pad=st.text(alphabet=_PAD_ALPHABET, max_size=400),
       hit_index=st.integers(min_value=0, max_value=len(_PY_RULE_HITS) - 1),
       filler=st.integers(min_value=0, max_value=40))
def test_comment_blanking_preserves_line_offsets_for_python_files(prefix_index, pad, hit_index,
                                                                   filler):
    """Same invariant for Python, where `#` comments and docstrings are additionally stripped."""
    head = _COMMENT_PREFIXES[prefix_index].format(pad=pad)
    filler_lines = "".join(f"v{k} = {k}  # filler\n" for k in range(filler))
    hit = _PY_RULE_HITS[hit_index]
    text = f"{head}{filler_lines}{hit}\n"
    expected_line = text[: text.index(hit)].count("\n") + 1

    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, "sample.py", text)
        result = _scanner().scan_directory(path)

    assert result, f"rule hit {hit!r} was not detected at all -- the offsets test cannot run"
    for finding in result:
        if finding.get("line") is not None:
            assert finding["line"] == expected_line, (
                f"line {finding['line']} != true line {expected_line}\n{text}\n{finding}")


# ==============================================================================================


# ==============================================================================================
# 5. RECOMMENDER -- totality over the full cross-product
# ==============================================================================================

@given(repeats=st.integers(min_value=1, max_value=12),
       noise_lines=st.integers(min_value=0, max_value=6))
def test_duplicate_findings_are_collapsed(repeats, noise_lines):
    """Same file + name + rule + line must appear once, however many times it was matched.

    Scanned as a DIRECTORY, which is the code path that runs the de-duplication pass.
    (Scanning a single FILE is a different code path -- see tests/test_differential.py, where
    the two are compared against each other.)
    """
    body = "".join(f"rsa.newkeys(2048)  # repeat {k}\n" for k in range(repeats))
    noise = "".join(f"v{k} = {k}\n" for k in range(noise_lines))
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "dup.py", body + noise)
        result = _scanner().scan_directory(tmp)

    keys = [(f["file"], f["name"], f["rule_id"], f["line"]) for f in result]
    assert len(keys) == len(set(keys)), f"duplicate findings survived: {keys}"
    rsa = [f for f in result if f["rule_id"] == "ECD-SRC-RSA-001"]
    assert len(rsa) == repeats, f"expected one finding per matching line, got {len(rsa)}"


@given(repeats=st.integers(min_value=1, max_value=8))
def test_repeated_scans_of_the_same_tree_yield_identical_findings(repeats):
    """A whole-directory scan is reproducible, and re-scanning does not accumulate state."""
    with tempfile.TemporaryDirectory() as tmp:
        _write(tmp, "a.py", "rsa.newkeys(2048)\nAESGCM(b'k')\n")
        _write(tmp, "b.c", "RSA_generate_key_ex(r, 2048);\nEVP_sha256();\n")
        _write(tmp, "c.conf", "ssl_protocols TLSv1.2;\n")
        first = _scanner().scan_directory(tmp)
        for _ in range(repeats):
            assert _scanner().scan_directory(tmp) == first


def _recommendation_defect(record):
    if not isinstance(record, dict):
        return f"not a dict: {type(record).__name__}"
    for key in ("algorithm", "action", "justification", "tradeoff_size",
                "tradeoff_latency", "rule_trace", "confidence", "cost_band"):
        if key not in record:
            return f"missing key {key!r}"
    for key in ("algorithm", "action", "justification", "rule_trace"):
        if not isinstance(record[key], str) or not record[key].strip():
            return f"{key} must be a non-empty string, got {record[key]!r}"
    for key in ("notes", "standard_basis"):
        if not isinstance(record[key], list):
            return f"{key} must be a list, got {type(record[key]).__name__}"
    if record["confidence"] not in ("standard-derived", "manual-review"):
        return f"unexpected confidence {record['confidence']!r}"
    return None


def test_recommender_is_total_over_the_full_name_primitive_uses_evidence_cross_product():
    """Exhaustive: EVERY combination returns a complete, explainable record and never raises.

    The recommender decides whether an operator is told to migrate. A crash here loses the
    whole report; a malformed record loses the audit trail. The domain includes None, empty
    strings, unknown primitives and non-string garbage types, because those are exactly what a
    finding dict sourced from JSON, YAML or a package registry can contain.
    """
    combos = 0
    failures = []
    malformed = []
    for name, primitive, uses, evidence in itertools.product(
            REC_NAMES, REC_PRIMITIVES, REC_USES, REC_EVIDENCE):
        combos += 1
        finding = {"name": name, "primitive": primitive, "uses": uses,
                   "evidence_class": evidence}
        try:
            record = get_pqc_recommendation(finding)
        except Exception as exc:                                  # noqa: BLE001
            failures.append((finding, f"{type(exc).__name__}: {exc}"))
            continue
        problem = _recommendation_defect(record)
        if problem:
            malformed.append((finding, problem))

    assert not failures, (
        f"{len(failures)}/{combos} combinations RAISED. First 5:\n"
        + "\n".join(f"  {f} -> {e}" for f, e in failures[:5]))
    assert not malformed, (
        f"{len(malformed)}/{combos} combinations returned a malformed record. First 5:\n"
        + "\n".join(f"  {f} -> {p}" for f, p in malformed[:5]))


def test_recommender_is_total_when_the_finding_carries_arbitrary_extra_keys():
    """Keys the recommender does not read must not be able to break it either.

    `key_length` / `key_size` are read and coerced with int(); a non-numeric value there is
    the kind of thing that arrives from a config file or a spreadsheet import.
    """
    garbage = [None, "", 0, -1, 3.5, True, [], {}, "not-a-number", "2048 bits", "0x800",
               "  2048  ", [2048], {"bits": 2048}, "١٢٣"]
    failures = []
    for value in garbage:
        for key in ("key_length", "key_size", "mode", "curve", "data_class",
                    "artefact_class", "dl_confidence", "ast_depth", "uses", "type",
                    "evidence_class", "risk", "recommendation", "file", "line", "match"):
            finding = {"name": "RSA", "primitive": "pke", key: value}
            try:
                record = get_pqc_recommendation(finding)
            except Exception as exc:                              # noqa: BLE001
                failures.append((key, value, f"{type(exc).__name__}: {exc}"))
                continue
            defect = _recommendation_defect(record)
            if defect:
                failures.append((key, value, defect))
    assert not failures, "recommender broke on: " + "\n".join(
        f"  {k}={v!r} -> {e}" for k, v, e in failures[:8])


def test_recommender_tolerates_any_mapping_like_finding():
    """A finding is duck-typed on `.get()`. Anything with `.get()` must work, and anything else
    must be a clean, attributable error rather than a half-populated record."""
    class Mappingish:
        def get(self, key, default=None):
            return {"name": "RSA", "primitive": "signature"}.get(key, default)

    record = get_pqc_recommendation(Mappingish())
    assert "ML-DSA" in record["algorithm"]
    assert _recommendation_defect(record) is None

    with pytest.raises((AttributeError, TypeError)):
        get_pqc_recommendation(object())


# ==============================================================================================
# 6. RECOMMENDER -- purity (no mutation of the caller's dict, no shared module state)
# ==============================================================================================

@given(
    name=st.one_of(st.sampled_from(REC_NAMES), st.text(max_size=40)),
    primitive=st.one_of(st.sampled_from(REC_PRIMITIVES), st.text(max_size=40)),
    uses=st.one_of(st.sampled_from(REC_USES), st.text(max_size=20)),
    evidence=st.one_of(st.sampled_from(REC_EVIDENCE), st.text(max_size=20)),
    key_length=st.one_of(st.none(), st.integers(), st.text(max_size=10), st.booleans()),
    extra=st.dictionaries(st.text(max_size=8), st.one_of(
        st.none(), st.integers(), st.text(max_size=8), st.booleans(),
        st.lists(st.integers(max_value=5), max_size=3)), max_size=4),
)
def test_recommendation_does_not_mutate_the_finding_it_is_given(name, primitive, uses, evidence,
                                                               key_length, extra):
    """Deep-compare the caller's dict before and after.

    The caller in cli.py, app.py and validate_real_world.py all keep using their finding dicts
    after enrichment, so an in-place edit here corrupts the CBOM they are about to generate.
    Shallow comparison misses nested edits, so the snapshot is serialised.
    """
    finding = {"name": name, "primitive": primitive, "uses": uses,
               "evidence_class": evidence, "key_length": key_length}
    finding.update(extra)
    before = json.dumps(finding, sort_keys=True, default=repr)
    before_items = repr(sorted(finding.items(), key=lambda kv: str(kv[0])))
    get_pqc_recommendation(finding)
    after = json.dumps(finding, sort_keys=True, default=repr)
    after_items = repr(sorted(finding.items(), key=lambda kv: str(kv[0])))
    assert before == after, f"finding mutated: {before} -> {after}"
    assert before_items == after_items


def test_recommendation_records_are_not_shared_module_state():
    """Two callers must not receive the SAME dict object.

    `NO_ACTION` is a module-level constant, and returning it directly hands every caller a
    reference to one shared dict. A single caller that annotates its result -- a GUI adding a
    row id, a reporter adding a ticket number -- then silently rewrites the recommendation for
    every later caller in the process, and the corruption is invisible in the output.
    """
    first = get_pqc_recommendation({"name": "AES", "primitive": "ae", "key_length": 256})
    second = get_pqc_recommendation({"name": "AES", "primitive": "ae", "key_length": 256})
    assert first is not second, "get_pqc_recommendation returned a shared object"

    original_algorithm = first["algorithm"]
    original_notes = list(first["notes"])
    first["algorithm"] = "POISONED BY CALLER"
    first["notes"].append("POISONED BY CALLER")
    first["standard_basis"].append("POISONED BY CALLER")

    third = get_pqc_recommendation({"name": "AES", "primitive": "ae", "key_length": 256})
    fourth = get_pqc_recommendation({"name": "SHA256", "primitive": "hash"})
    assert third["algorithm"] == original_algorithm, \
        f"a caller's mutation leaked into a later recommendation: {third['algorithm']!r}"
    assert third["notes"] == original_notes, \
        f"a caller's mutation leaked into a later recommendation: {third['notes']!r}"
    assert "POISONED BY CALLER" not in fourth["notes"]
    assert "POISONED BY CALLER" not in fourth["standard_basis"]


# ==============================================================================================
# 7. CBOM -- schema conformance
# ==============================================================================================

CBOM_FINDING = st.fixed_dictionaries({
    "name": st.sampled_from(CBOM_NAMES),
    "primitive": st.sampled_from(CBOM_PRIMITIVES),
    "type": st.sampled_from(["algorithm", "algorithm", "algorithm", "library", "protocol"]),
    # A non-empty path: an EMPTY `file` is not provenance, it is the absence of provenance,
    # and generate_cbom treats it as such (`if not f.get("file")`).
    "file": st.sampled_from(["src/app.py", "a.conf", "openssl.cnf", "img.tar!app.py"]),
    "line": st.one_of(st.none(), st.integers(min_value=1, max_value=5000)),
    "key_length": st.sampled_from(CBOM_KEY_SIZES),
    "uses": st.sampled_from(["tls", "signing", "at-rest"]),
    "evidence_class": st.sampled_from(["discovered", "configured", "declared", "observed"]),
    "artefact_class": st.sampled_from(["source", "config", "library", "firmware"]),
})

# Schema validation dominates the runtime, so the CBOM properties use a tighter example budget
# than the rest of the file. 25 documents drawn from a 16 x 14 x 9 x 6 x 6 strategy space is
# ample coverage of the branches that matter; the exhaustive checks are elsewhere.
CBOM_SETTINGS = settings(max_examples=25, parent=settings.get_profile("ecdat"))


@CBOM_SETTINGS
@given(findings=st.lists(CBOM_FINDING, max_size=6))
def test_cbom_matches_the_published_schema_for_findings_with_provenance(findings):
    """Findings that carry real file/line provenance must produce a schema-valid CycloneDX 1.7
    document. This is the path the CLI and the GUI both take, so it is the one that matters
    most -- and it is the path the existing example-based schema test already covers, which is
    why the no-provenance path below needed finding.
    """
    document = json.loads(generate_cbom(findings, enriched=True, subject_name="prop-target"))
    assert not _schema_errors(document), (
        "CBOM failed CycloneDX 1.7 validation:\n" + _schema_errors(document))


@CBOM_SETTINGS
@given(findings=st.lists(CBOM_FINDING, min_size=1, max_size=6))
def test_cbom_matches_the_published_schema_for_findings_without_provenance(findings):
    """A finding with no `file` is legitimate: ambient or global crypto, a policy-wide setting,
    or an inventory re-imported from another tool. `generate_cbom` has an explicit
    `dependencies` branch for exactly that case, so the branch is reachable through the public
    API -- and whatever it emits must validate.
    """
    stripped = [{k: v for k, v in f.items() if k != "file"} for f in findings]
    document = json.loads(generate_cbom(stripped, enriched=True, subject_name="prop-target"))
    assert not _schema_errors(document), (
        "CBOM failed CycloneDX 1.7 validation:\n" + _schema_errors(document))


@CBOM_SETTINGS
@given(findings=st.lists(CBOM_FINDING, max_size=4),
       mode=st.sampled_from(CBOM_MODES))
def test_cbom_matches_the_published_schema_for_every_cipher_mode(findings, mode):
    """`mode` is a CLOSED enum in CycloneDX. Real cipher modes outside it must still validate.

    The schema provides "other" and "unknown" precisely so that an unrecognised mode can be
    represented; emitting the raw string instead makes the document unusable by any consumer
    that validates, which is the entire point of publishing a CBOM.
    """
    stamped = [dict(f, mode=mode, name="AES", primitive="ae", key_length=256) for f in findings]
    document = json.loads(generate_cbom(stamped, enriched=True, subject_name="prop-target"))
    assert not _schema_errors(document), (
        f"mode={mode!r} produced a schema-invalid CBOM:\n" + _schema_errors(document))


@CBOM_SETTINGS
@given(findings=st.lists(CBOM_FINDING, max_size=4),
       key_length=st.sampled_from([None, 128, 256, 2048, "2048", "unknown", "big", ""]))
def test_cbom_is_total_for_arbitrary_key_length(findings, key_length):
    """`key_length` is coerced with int() and then published as `classicalSecurityLevel`.

    A non-numeric value must not take the whole report down, and a value that cannot be
    interpreted must be omitted rather than emitted as something the schema rejects.
    """
    stamped = [dict(f, key_length=key_length) for f in findings]
    document = json.loads(generate_cbom(stamped, enriched=True, subject_name="prop-target"))
    assert not _schema_errors(document), (
        f"key_length={key_length!r} produced an invalid CBOM:\n" + _schema_errors(document))


@settings(max_examples=40, parent=settings.get_profile("ecdat"))
@given(name=st.one_of(st.text(max_size=30), st.none(), st.integers(), st.booleans(),
                      st.lists(st.integers(max_value=5), max_size=3),
                      st.dictionaries(st.text(max_size=4), st.integers(), max_size=3)))
def test_cbom_is_total_for_any_json_representable_algorithm_name(name):
    """`name` is used as a dict key for the OID lookup, so an unhashable value must not crash
    report generation -- and whatever is emitted must still satisfy the schema, which types
    `component.name` as a string. A finding read back out of a JSON inventory can legitimately
    carry a number or a null there.

    `file` is supplied so that this test isolates the `name` handling: the no-provenance
    `dependencies` branch is a separate defect with a separate test.
    """
    document = json.loads(generate_cbom([{"name": name, "primitive": "pke",
                                         "file": "a.py", "line": 1}]))
    assert not _schema_errors(document), (
        f"name={name!r} produced an invalid CBOM:\n" + _schema_errors(document))


@given(findings=st.lists(CBOM_FINDING, min_size=1, max_size=5),
       subject_name=st.text(min_size=1, max_size=60),
       subject_version=st.one_of(st.none(), st.text(max_size=20), st.integers()))
def test_cbom_is_wellformed_for_any_subject_name(findings, subject_name, subject_version):
    """`name` and `version` are caller-supplied strings; they must stay schema-valid and must
    survive the round trip unchanged."""
    document = json.loads(generate_cbom(findings, enriched=True, subject_name=subject_name,
                                       subject_version=subject_version))
    assert not _schema_errors(document), (
        f"subject={subject_name!r} produced an invalid CBOM:\n" + _schema_errors(document))
    assert document["metadata"]["component"]["name"] == subject_name


COVERAGE_MANIFEST = st.fixed_dictionaries({
    "files_scanned": st.integers(min_value=0, max_value=10 ** 6),
    "files_skipped": st.integers(min_value=0, max_value=10 ** 6),
    "ml_reason": st.text(max_size=30),
    "never_in_scope": st.lists(st.text(max_size=30), max_size=5),
    "assurance_histogram": st.dictionaries(st.text(max_size=12),
                                           st.integers(max_value=1000), max_size=6),
    "proven_use": st.integers(min_value=0, max_value=10 ** 6),
    "findings_total": st.integers(min_value=0, max_value=10 ** 6),
    "unresolved_purpose": st.integers(min_value=0, max_value=10 ** 6),
})


@CBOM_SETTINGS
@given(findings=st.lists(CBOM_FINDING, max_size=5), coverage=COVERAGE_MANIFEST)
def test_cbom_matches_the_schema_with_any_coverage_manifest(findings, coverage):
    """The coverage manifest is a separate public input to generate_cbom and is rendered into
    metadata.properties, so it is subject to the same schema contract."""
    document = json.loads(generate_cbom(findings, enriched=True, subject_name="prop-target",
                                       coverage=coverage))
    assert not _schema_errors(document), (
        "CBOM with a coverage manifest failed validation:\n" + _schema_errors(document))


def test_cbom_is_deterministic_apart_from_its_identity_fields():
    """The same findings must produce the same document every time, except serialNumber and
    timestamp. A CBOM that reshuffles between runs cannot be diffed between releases."""
    findings = [dict(name="RSA", primitive="pke", key_length=2048, file="a.py", line=1),
                dict(name="AES", primitive="ae", key_length=256, file="b.py", line=7),
                dict(name="TLS", primitive="protocol", file="c.conf", line=2)]

    def stable(document):
        document = json.loads(json.dumps(document))
        document.pop("serialNumber", None)
        document.get("metadata", {}).pop("timestamp", None)
        return document

    a = stable(json.loads(generate_cbom(findings, enriched=True, subject_name="s")))
    b = stable(json.loads(generate_cbom(findings, enriched=True, subject_name="s")))
    assert a == b
    document = json.loads(generate_cbom(findings, subject_name="s"))
    assert document["serialNumber"].startswith("urn:uuid:"), "the document must be identifiable"
    assert document["metadata"]["timestamp"].endswith("Z"), \
        "the document must say when it was produced"


# ==============================================================================================
# 8. MOSCA -- monotonicity and the X + Y > Z boundary
# ==============================================================================================

TIER_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

MOSCA_FINDINGS = [
    {"name": "RSA", "primitive": "pke"},
    {"name": "ECDSA", "primitive": "signature"},
    {"name": "ECDH", "primitive": "key-agreement"},
    {"name": "Ed25519", "primitive": "signature"},
    {"name": "DSA", "primitive": "signature"},
    {"name": "DH", "primitive": "key-agreement"},
    {"name": "AES", "primitive": "ae", "key_length": 128},
    {"name": "AES", "primitive": "ae", "key_length": 256},
    {"name": "AES", "primitive": "ae"},
    {"name": "SHA256", "primitive": "hash"},
    {"name": "SHA1", "primitive": "hash"},
    {"name": "ChaCha20", "primitive": "ae"},
    {"name": "MysteryCipher", "primitive": "unknown"},
    {"name": "RSA", "primitive": "pke", "data_class": "statutory-archive"},
    {"name": "RSA", "primitive": "pke", "data_class": "session", "artefact_class": "config"},
    {"name": "RSA", "primitive": "pke", "artefact_class": "hsm-tpm", "ast_depth": 50},
    {"name": "RSA", "primitive": "pke", "data_class": "health-record",
     "artefact_class": "ca-root"},
]

_YEARS = st.floats(min_value=0.0, max_value=60.0, allow_nan=False, allow_infinity=False)
_Z = st.sampled_from([0.0, 1.0, 2.5, 5.0, 7.5, 10.0, 12.0, 15.0, 20.0, 30.0, 50.0, 100.0])


@given(finding=st.sampled_from(MOSCA_FINDINGS), x=_YEARS, delta=_YEARS, z=_Z)
def test_risk_tier_never_lowers_when_x_increases(finding, x, delta, z):
    """X is 'how long this must stay secret'. More of that can never reduce the risk."""
    assume(delta > 0)
    low = calculate_risk(finding, x, 3.0, z, current_year=2026)
    high = calculate_risk(finding, x + delta, 3.0, z, current_year=2026)
    assert TIER_ORDER.index(high["tier"]) >= TIER_ORDER.index(low["tier"]), (
        f"X {x} -> {x + delta} lowered the tier {low['tier']} -> {high['tier']} for {finding}")
    assert high["margin"] >= low["margin"]
    assert high["x_y"] >= low["x_y"]


@given(finding=st.sampled_from(MOSCA_FINDINGS), y=_YEARS, delta=_YEARS, z=_Z)
def test_risk_tier_never_lowers_when_y_increases(finding, y, delta, z):
    """Y is 'how long migration takes'. More of that can never reduce the risk."""
    assume(delta > 0)
    low = calculate_risk(finding, 5.0, y, z, current_year=2026)
    high = calculate_risk(finding, 5.0, y + delta, z, current_year=2026)
    assert TIER_ORDER.index(high["tier"]) >= TIER_ORDER.index(low["tier"]), (
        f"Y {y} -> {y + delta} lowered the tier {low['tier']} -> {high['tier']} for {finding}")
    assert high["margin"] >= low["margin"]


@given(finding=st.sampled_from(MOSCA_FINDINGS), x=_YEARS, y=_YEARS, z1=_Z, z2=_Z)
def test_risk_tier_never_rises_when_z_increases(finding, x, y, z1, z2):
    """Z is 'years until a CRQC'. More time can never increase the risk."""
    assume(z2 > z1)
    near = calculate_risk(finding, x, y, z1, current_year=2026)
    far = calculate_risk(finding, x, y, z2, current_year=2026)
    assert TIER_ORDER.index(far["tier"]) <= TIER_ORDER.index(near["tier"]), (
        f"Z {z1} -> {z2} raised the tier {near['tier']} -> {far['tier']} for {finding}")
    assert far["margin"] <= near["margin"]


@given(finding=st.sampled_from(MOSCA_FINDINGS), x=_YEARS, y=_YEARS, z=_Z)
def test_is_vulnerable_is_exactly_x_plus_y_greater_than_z(finding, x, y, z):
    """The verdict must BE the inequality, not a proxy for it -- reported values included.

    This is the audit-trail property: the numbers printed in the report must imply the same
    verdict the report states, or the report is not evidence of anything.
    """
    risk = calculate_risk(finding, x, y, z, current_year=2026)
    expected = bool(risk["subject_to_inequality"]
                    and Decimal(str(x)) + Decimal(str(y)) > Decimal(str(z)))
    assert risk["is_vulnerable"] is expected, (
        f"X={x} Y={y} Z={z}: reported x_y={risk['x_y']} z={risk['z']} "
        f"is_vulnerable={risk['is_vulnerable']}, the inequality says {expected}")


# --- the exact boundary -----------------------------------------------------------------------

# Dyadic rationals with at most 2 decimal places: sums of these are EXACT in binary floating
# point AND survive the engine's `round(..., 2)` reporting unchanged, so X + Y == Z is
# representable end to end and the comparison is not a test of floating-point rounding.
_DYADIC = [k / 4.0 for k in range(0, 241)]


@given(finding=st.sampled_from(MOSCA_FINDINGS),
       x=st.sampled_from(_DYADIC), y=st.sampled_from(_DYADIC))
def test_exact_boundary_x_plus_y_equal_to_z_is_not_vulnerable(finding, x, y):
    """X + Y == Z is NOT vulnerable: the inequality is strict.

    This is the most consequential boundary in the tool -- it is the difference between
    MEDIUM ("not yet, plan") and HIGH ("start now") for every Shor-vulnerable artefact.
    """
    assume(x + y <= 60.0)
    z = x + y
    risk = calculate_risk(finding, x, y, z, current_year=2026)
    assert risk["x_y"] == z
    assert risk["margin"] == 0.0
    assert risk["is_vulnerable"] is False, (
        f"X={x} Y={y} Z={z}: X+Y == Z must NOT be vulnerable, got tier {risk['tier']}")


@given(finding=st.sampled_from(MOSCA_FINDINGS),
       x=st.sampled_from(_DYADIC), y=st.sampled_from(_DYADIC))
def test_epsilon_past_the_boundary_is_vulnerable(finding, x, y):
    """One representable step PAST the boundary must flip to vulnerable.

    The strictness of the inequality must hold in both directions, not merely be biased
    towards "not yet" -- a check that is always False passes the test above for the wrong
    reason and would silently disable migration for the entire estate.
    """
    assume(x + y <= 59.0)
    z = x + y
    risk = calculate_risk(finding, x, y + 0.25, z, current_year=2026)
    if risk["subject_to_inequality"]:
        assert risk["is_vulnerable"] is True, (
            f"X={x} Y={y + 0.25} Z={z}: X+Y > Z must be vulnerable, got tier {risk['tier']}")


# The decimal years an operator actually types into the UI. These are NOT dyadic: 0.1 + 0.2 is
# 0.30000000000000004 in IEEE-754, so X + Y == Z holds mathematically while `total > z_years`
# evaluates true in floating point.
_DECIMAL_TENTHS = [Decimal(k) / Decimal(10) for k in range(0, 301)]


@given(finding=st.sampled_from(MOSCA_FINDINGS),
       x=st.sampled_from(_DECIMAL_TENTHS), y=st.sampled_from(_DECIMAL_TENTHS))
def test_exact_decimal_boundary_x_plus_y_equal_to_z_is_not_vulnerable(finding, x, y):
    """The same boundary, expressed in the tenths an operator types: X=1.1, Y=2.2, Z=3.3.

    `X + Y == Z` is a mathematical statement about the numbers the user entered, not about
    their IEEE-754 representations. `1.1 + 2.2` is 3.3000000000000003, which compares strictly
    greater than 3.3, so the tool reports HIGH for an artefact sitting exactly on the boundary
    -- and then prints `X+Y=3.3 vs Z=3.3` in the very line that makes the claim, which is a
    self-contradicting audit trail.
    """
    assume(x + y <= Decimal(60))
    z = x + y
    risk = calculate_risk(finding, float(x), float(y), float(z), current_year=2026)
    assert risk["is_vulnerable"] is False, (
        f"X={x} Y={y} Z={z}: X+Y == Z must NOT be vulnerable. The report states "
        f"x_y={risk['x_y']} against z={risk['z']} and tier={risk['tier']} -- it claims "
        f"vulnerable while showing equal numbers on both sides of the inequality."
    )


@given(finding=st.sampled_from(MOSCA_FINDINGS), x=st.sampled_from(_DECIMAL_TENTHS),
       y=st.sampled_from(_DECIMAL_TENTHS))
def test_risk_totals_are_reported_at_the_precision_they_were_computed(finding, x, y):
    """The audit trail must be internally consistent: the reported X, Y, X+Y, margin and the
    reported verdict must all agree, at the precision they are printed to.

    If the verdict is decided on full-precision floats but the report shows 2-dp values, then
    whenever the two disagree the document contradicts itself and cannot settle an argument
    about whether a breach happened.
    """
    risk = calculate_risk(finding, float(x), float(y), 10.0, current_year=2026)
    shown_sum = round(risk["x"] + risk["y"], 2)
    assert risk["x_y"] == shown_sum, (
        f"X={risk['x']} Y={risk['y']}: reported x_y={risk['x_y']} but the printed inputs "
        f"sum to {shown_sum}")
    assert risk["margin"] == round(risk["x_y"] - risk["z"], 2)
    if risk["subject_to_inequality"]:
        implied = Decimal(str(risk["x_y"])) > Decimal(str(risk["z"]))
        assert implied == risk["is_vulnerable"], (
            f"the reported numbers (x_y={risk['x_y']} vs z={risk['z']}) imply "
            f"is_vulnerable={implied}, but the report says {risk['is_vulnerable']}")


@given(finding=st.sampled_from(MOSCA_FINDINGS), x=st.sampled_from(_DECIMAL_TENTHS),
       y=st.sampled_from(_DECIMAL_TENTHS), z=_Z)
def test_mosca_inputs_are_reported_exactly_as_supplied(finding, x, y, z):
    """An explicit override must be echoed back unchanged, or the operator cannot tell which
    number the verdict was actually based on."""
    risk = calculate_risk(finding, float(x), float(y), float(z), current_year=2026)
    assert risk["x"] == round(float(x), 2)
    assert risk["y"] == round(float(y) + risk["y_complexity_adjustment"], 2)
    assert risk["z"] == float(z)
    assert risk["y_complexity_adjustment"] == 0.0, "an explicit Y override leaves no room for " \
                                                   "a derived complexity adjustment"
    assert "explicit override" in risk["x_reason"]
    assert "explicit override" in risk["y_reason"]


# ==============================================================================================
# 9. FSPOLICY -- containment
# ==============================================================================================

@given(components=st.lists(st.sampled_from(PATH_COMPONENTS), min_size=1, max_size=6),
       tail=st.sampled_from(PATH_COMPONENTS))
def test_resolve_within_never_returns_a_path_outside_the_root(components, tail):
    """Whatever the input looks like, a non-None answer must be inside the root.

    This is the arbitrary-file-read guard. It is asserted over generated traversal sequences,
    absolute drive-letter paths, UNC paths, NUL bytes and lookalike separators -- and it is
    paired with `test_resolve_within_accepts_genuinely_inside_paths` below, because a
    containment check implemented as "always return None" would pass this test while being
    useless.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        os.makedirs(os.path.join(root, "sub"), exist_ok=True)
        candidate = os.path.join(root, *components, tail) if components else tail
        result = resolve_within(root, candidate)
        if result is not None:
            real = os.path.realpath(result)
            assert real == root or real.startswith(root.rstrip(os.sep) + os.sep), (
                f"resolve_within({root!r}, {candidate!r}) returned {result!r}, which resolves "
                f"to {real!r} -- OUTSIDE the root")
            # A non-None answer must be the real path of the input, not a normalised fiction.
            assert real == os.path.realpath(candidate)


@given(components=st.lists(
    st.sampled_from(["sub", "a", "b", "deep", "x.py", "conf"]), min_size=1, max_size=5))
def test_resolve_within_accepts_genuinely_inside_paths(components):
    """Positive control: containment must not be implemented by refusing everything."""
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        inside = os.path.join(root, *components)
        result = resolve_within(root, inside)
        assert result is not None, f"resolve_within wrongly refused {inside!r} inside {root!r}"
        assert os.path.realpath(result).startswith(root)


@given(depth=st.integers(min_value=1, max_value=8))
def test_resolve_within_refuses_every_depth_of_parent_traversal(depth):
    """`../../../../..` must be refused at every depth, starting from a real subdirectory.

    The walk starts `depth` directories below the root and climbs `depth + 1` levels, so the
    final path is genuinely outside the root. Climbing exactly `depth` levels would land back
    inside it, and asserting on that would be testing nothing.
    """
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        deep = root
        for _ in range(depth):
            deep = os.path.join(deep, "sub")
        os.makedirs(deep, exist_ok=True)
        escapes = os.path.join(deep, *([".."] * (depth + 1)), "outside.py")
        assert os.path.dirname(os.path.abspath(escapes)) != root, "the test path is not an escape"
        assert resolve_within(root, escapes) is None
        sibling = os.path.join(root, "..", "root-evil", "x.py")
        assert resolve_within(root, sibling) is None, "prefix-lookalike path was accepted"


@given(component=st.sampled_from(PATH_COMPONENTS))
def test_resolve_within_refuses_absolute_and_remote_paths(component):
    """Absolute paths, drive letters and UNC shares are never inside a scan root."""
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        for absolute in [component, os.path.join(component, "x.py"),
                         "C:\\Windows\\System32\\config\\SAM",
                         "\\\\server\\share\\secret.txt", "/etc/shadow", "~/.ssh/id_rsa"]:
            result = resolve_within(root, absolute)
            if result is not None:
                real = os.path.realpath(result)
                assert real == root or real.startswith(root.rstrip(os.sep) + os.sep), (
                    f"resolve_within({root!r}, {absolute!r}) escaped to {real!r}")


def test_resolve_within_does_not_raise_on_hostile_path_objects():
    """The scanner walks untrusted trees. A path object that explodes on os.fspath, or a path
    with an embedded NUL, must produce a refusal or a clean answer -- never an exception that
    unwinds the whole scan."""
    class Hostile:
        def __fspath__(self):
            raise RuntimeError("boom")

    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.realpath(tmp)
        for candidate in [Hostile(), "a\x00b.py", "\x00", "\\??\\C:\\Windows", "..." * 100]:
            try:
                result = resolve_within(root, candidate)
            except (RuntimeError, ValueError) as exc:
                # A refusal-by-exception is acceptable only if it is one of the two documented
                # ways to say "no"; anything else propagates into the scanner's caller.
                assert isinstance(exc, (RuntimeError, ValueError)), exc
                continue
            if result is not None:
                real = os.path.realpath(result)
                assert real == root or real.startswith(root.rstrip(os.sep) + os.sep)

