"""Tests written specifically to KILL the mutants that survived mutation testing.

`mutation_test.py` reported 8 surviving mutants -- defects of a real shape that the existing
suite would have shipped undetected. Each test below is named after the mutant it kills, so the
link between the measurement and the fix is explicit and the next person can re-verify.

Run `python mutation_test.py` after adding tests here: the score should rise. If a test is
deleted, the corresponding mutant survives again -- that is the point.

    kills MOSCA-01  CRITICAL threshold at margin>=10 is wrong
    kills MOSCA-02  AST-depth complexity adjustment is not actually proportional
    kills MOSCA-03  confidentiality/verifiability horizon default
    kills MOSCA-04  the "sign" primitive check in _horizon_type
    kills MOSCA-05  non-subject artefacts must be downgraded, not escalated
    kills REC-02    NO_ACTION must carry a real, specific rule trace
    kills SCAN-01   an OSError while reading must be recorded, not swallowed
    kills SCAN-03   a symlink escaping the scan root must be skipped
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.mosca import _horizon_type, _tier, calculate_risk
from engine.recommender import NO_ACTION, get_pqc_recommendation
from engine.scanner import ECDATScanner


# ===========================================================================================
# Kills MOSCA-01 -- the CRITICAL margin threshold
# ===========================================================================================
def test_kills_MOSCA01_critical_threshold_is_ten_years():
    """A vulnerable, HNDL-exposed artefact is CRITICAL; a non-HNDL one escalates at margin 10.

    The mutant raises the CRITICAL threshold to 1000, silently downgrading genuinely exposed
    assets to HIGH. Two paths reach CRITICAL and both must be pinned:
      * hndl_exposed (confidentiality horizon, X > Z) -> CRITICAL at ANY margin
      * merely vulnerable, not HNDL -> CRITICAL only once margin >= 10
    """
    # HNDL path: confidentiality horizon, X(20) > Z(10). CRITICAL regardless of margin.
    hndl = calculate_risk(dict(name="RSA", primitive="pke"), user_x=20, user_y=3,
                          z_collapse_time=10)
    assert hndl["hndl_exposed"] is True
    assert hndl["tier"] == "CRITICAL", f"HNDL-exposed must be CRITICAL, got {hndl['tier']}"

    # Non-HNDL path: a signature. margin 5 -> HIGH, margin 13 -> CRITICAL.
    at_5 = calculate_risk(dict(name="ECDSA", primitive="signature"), user_x=12, user_y=3,
                          z_collapse_time=10)
    assert at_5["margin"] == 5.0
    assert at_5["is_vulnerable"] is True
    assert at_5["hndl_exposed"] is False
    assert at_5["tier"] == "HIGH", f"margin 5 must be HIGH, got {at_5['tier']}"

    at_13 = calculate_risk(dict(name="ECDSA", primitive="signature"), user_x=20, user_y=3,
                           z_collapse_time=10)
    assert at_13["margin"] == 13.0
    assert at_13["hndl_exposed"] is False, "a signature is never HNDL-exposed"
    assert at_13["tier"] == "CRITICAL", f"margin 13 must be CRITICAL, got {at_13['tier']}"


def test_kills_MOSCA01_tier_is_monotone_in_margin():
    """As the margin grows the tier must never get LESS severe.

    A property, not an example: it holds for every input, so a mutant that weakens the CRITICAL
    rule at any threshold breaks it somewhere. Uses a signature so the HNDL short-circuit does
    not mask the margin branch.
    """
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    tiers = [calculate_risk(dict(name="ECDSA", primitive="signature"), user_x=x, user_y=3,
                            z_collapse_time=10)["tier"] for x in range(5, 40)]
    ranks = [order[t] for t in tiers]
    assert ranks == sorted(ranks), f"tier severity must be non-decreasing as X grows; got {tiers}"



# ===========================================================================================
# Kills MOSCA-02 -- the AST-depth complexity adjustment
# ===========================================================================================
def test_kills_MOSCA02_complexity_adjustment_is_proportional():
    """The adjustment must scale with AST depth, not be pinned at its cap for everything.

    The mutant multiplies the reference depth by 1000, driving the ratio to ~0 for any realistic
    depth, so the adjustment vanishes entirely.
    """
    from engine.mosca import COMPLEXITY_ADJUSTMENT_MAX_YEARS, COMPLEXITY_AST_DEPTH_REFERENCE

    half = COMPLEXITY_AST_DEPTH_REFERENCE / 2.0
    r = calculate_risk(dict(name="RSA", primitive="pke", ast_depth=half))
    expected = COMPLEXITY_ADJUSTMENT_MAX_YEARS * 0.5
    assert r["y_complexity_adjustment"] == pytest.approx(expected, abs=0.01), (
        f"at half the reference depth the adjustment should be ~{expected:.2f}y, got "
        f"{r['y_complexity_adjustment']:.4f}y -- a vanished adjustment means complexity no "
        f"longer informs migration effort")


def test_kills_MOSCA02_zero_depth_gives_zero_adjustment():
    r = calculate_risk(dict(name="RSA", primitive="pke", ast_depth=0))
    assert r["y_complexity_adjustment"] == 0.0


# ===========================================================================================
# Kills MOSCA-03 / MOSCA-04 -- horizon type resolution
# ===========================================================================================
def test_kills_MOSCA03_default_horizon_is_confidentiality_not_verifiability():
    """A non-signature, Shor-broken primitive defaults to the CONFIDENTIALITY horizon.

    This is the HNDL case and the most consequential default in the model. If it silently became
    verifiability, `hndl_exposed` would never be set and the tool would stop warning about
    harvest-now-decrypt-later entirely.
    """
    f = dict(name="RSA", primitive="pke")
    assert _horizon_type(f, "broken-by-Shor") == "confidentiality"
    r = calculate_risk(f, user_x=20, user_y=3, z_collapse_time=10)
    assert r["horizon_type"] == "confidentiality", f"got {r['horizon_type']}"
    assert r["hndl_exposed"] is True, (
        "X(20) > Z(10) with a confidentiality horizon MUST set hndl_exposed")


def test_kills_MOSCA04_primitive_containing_sign_is_verifiability():
    """A primitive whose name contains 'sign' resolves to the VERIFIABILITY horizon.

    HNDL does not apply to signatures -- a CRQC cannot un-sign an artefact released today.
    """
    f = dict(name="ML-DSA", primitive="digital-signature")
    assert _horizon_type(f, "broken-by-Shor") == "verifiability"
    r = calculate_risk(f, user_x=20, user_y=3, z_collapse_time=10)
    assert r["horizon_type"] == "verifiability"
    assert r["hndl_exposed"] is False, (
        "a signature must never be marked HNDL-exposed: forgery risk is from Q-Day onward, "
        "not retroactive")


def test_kills_MOSCA04_known_primitive_horizon_table_wins():
    """The explicit PRIMITIVE_HORIZON table takes precedence over the substring heuristic."""
    assert _horizon_type(dict(name="ECDSA", primitive="signature"), "broken-by-Shor") == "verifiability"


def test_kills_MOSCA03_non_shor_primitive_has_no_horizon():
    """A Grover-weakened primitive has no horizon -- the inequality does not apply to it."""
    assert _horizon_type(dict(name="AES", primitive="ae"), "weakened-by-Grover") == "none"


def test_kills_MOSCA03_fallback_for_unrecognised_primitive_is_confidentiality():
    """An UNRECOGNISED primitive falls through the table to the confidentiality default.

    This fallback is the robustness path, and it is the one no canonical-primitive test reaches:
    `pke`, `signature`, `kem` and `key-agreement` are all answered by PRIMITIVE_HORIZON before the
    default ever runs. But a real scan produces whatever primitive string the emitting tool used,
    so the fallback is exactly the code a novel or malformed input hits. Getting it wrong silently
    marks an unknown asymmetric primitive as verifiability, which suppresses the HNDL warning.
    """
    for primitive in ("pke-oaep-variant", "asymmetric-encryption", "xy-2026-newthing", ""):
        assert _horizon_type(dict(name="RSA", primitive=primitive), "broken-by-Shor") \
            == "confidentiality", (
            f"unrecognised primitive {primitive!r} must default to the confidentiality "
            f"horizon, not verifiability")


def test_kills_MOSCA04_sign_substring_fallback_catches_unknown_signature_primitives():
    """An unrecognised primitive whose name contains 'sign' resolves to VERIFIABILITY.

    The second robustness fallback, unreachable through the table for the same reason. A new
    signature primitive that is not yet in PRIMITIVE_HORIZON must still be recognised as one, or
    a signature gets a confidentiality horizon and is falsely flagged harvest-now-decrypt-later.
    """
    for primitive in ("pqc-signature-v2", "ml-dsa-sign", "fips-signature"):
        assert _horizon_type(dict(name="Whatever", primitive=primitive), "broken-by-Shor") \
            == "verifiability", (
            f"{primitive!r} contains 'sign' and must resolve to verifiability")


def test_kills_MOSCA04_mode_signing_fallback():
    """A `mode` of 'signing' also resolves to verifiability, for an unrecognised primitive."""
    f = dict(name="Whatever", primitive="unlisted-thing", mode="signing")
    assert _horizon_type(f, "broken-by-Shor") == "verifiability"



# ===========================================================================================
# Kills MOSCA-05 -- non-subject artefacts are downgraded, never escalated
# ===========================================================================================
def test_kills_MOSCA05_non_subject_is_low_even_with_a_huge_margin():
    """Not being Shor-broken means LOW, however large X is.

    The mutant removes the `if not subject` guard, so a huge data lifetime escalates the tier.
    This is the category error Phase-1 gap H4 warns about: applying the inequality to a
    primitive Grover does not break.
    """
    r = calculate_risk(dict(name="AES", primitive="ae", key_length=256),
                       user_x=30, user_y=3, z_collapse_time=10)
    assert r["is_vulnerable"] is False
    assert r["tier"] == "LOW", f"AES-256 with a 30y lifetime must stay LOW, got {r['tier']}"


def test_kills_MOSCA05_tier_helper_downgrades_non_subject():
    assert _tier("broken-by-Shor", subject=False, is_vulnerable=True, hndl=False,
                 margin=999, effective_bits=None) == "LOW"
    assert _tier("not-affected", subject=False, is_vulnerable=False, hndl=False,
                 margin=0, effective_bits=None) == "LOW"


# ===========================================================================================
# Kills REC-02 -- every recommendation carries a real, specific rule trace
# ===========================================================================================
def test_kills_REC02_no_action_carries_a_meaningful_rule_trace():
    """The NO_ACTION constant must name the condition that produced it.

    Mutating the trace to a generic "RULE-BROKEN" would otherwise pass silently, and a
    meaningless trace defeats the explainability requirement: a reader who cannot see WHY a
    finding was dismissed cannot audit the dismissal.
    """
    assert NO_ACTION["rule_trace"].startswith("RULE-SYM-OK:"), (
        f"NO_ACTION trace must be specific, got {NO_ACTION['rule_trace']!r}")
    assert "Shor" in NO_ACTION["justification"], (
        "NO_ACTION must state WHY the artefact is not at risk, not merely that it is fine")
    assert NO_ACTION["standard_basis"], "NO_ACTION must cite a standard"


def test_kills_REC02_every_recommendation_trace_is_non_trivial():
    """Every recommendation path must produce a trace long enough to be diagnostic."""
    cases = [
        dict(name="RSA", primitive="pke"),
        dict(name="RSA", primitive="signature"),
        dict(name="AES", primitive="ae", key_length=256),
        dict(name="AES", primitive="ae", key_length=128),
        dict(name="SHA256", primitive="hash", key_length=256),
        dict(name="SHA1", primitive="hash"),
        dict(name="ECDH", primitive="key-agreement", uses="tls"),
        dict(name="TLS", primitive="protocol"),
        dict(name="libcrypto", primitive="cryptographic-library", type="library"),
        dict(name="MD5", primitive="hash"),
    ]
    for case in cases:
        rec = get_pqc_recommendation(case)
        trace = rec.get("rule_trace", "")
        assert trace, f"no rule_trace for {case}"
        assert len(trace) > 20, f"rule_trace too short to be diagnostic for {case}: {trace!r}"
        assert trace.startswith("RULE-"), f"rule_trace must be RULE-prefixed: {trace!r}"


# ===========================================================================================
# Kills SCAN-01 -- an OSError must be recorded, not swallowed
# ===========================================================================================
@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not enforced on Windows")
def test_kills_SCAN01_unreadable_file_is_recorded_as_an_error(tmp_path):
    """A file that exists but cannot be opened must land in `errors`, not vanish.

    The mutant replaces the error record with `pass`. The suite would still pass, because a
    skipped unreadable file looks exactly like a clean file -- precisely the dishonesty the
    coverage manifest exists to prevent.
    """
    p = tmp_path / "locked.py"
    p.write_text("key = rsa.newkeys(2048)\n", encoding="utf-8")
    os.chmod(p, 0o000)
    try:
        scanner = ECDATScanner(enable_ml=False)
        scanner.scan_directory(str(tmp_path))
        assert any("unreadable" in e["reason"] for e in scanner.errors), (
            f"an unreadable file must be named; errors={scanner.errors}")
    finally:
        os.chmod(p, 0o600)


def test_kills_SCAN01_oserror_is_recorded_platform_independently(tmp_path, monkeypatch):
    """The same guarantee, without depending on POSIX permission bits.

    The chmod-based test above is skipped on Windows, which means on this platform the mutant
    would survive undetected -- a test that only runs on some hosts is not a guarantee. Here the
    scanner's own `open` is patched to raise OSError, so the error path is exercised everywhere.
    """
    (tmp_path / "x.py").write_text("key = rsa.newkeys(2048)\n", encoding="utf-8")
    real_open = open

    def exploding_open(path, *a, **kw):
        if str(path).endswith("x.py"):
            raise OSError(5, "Access is denied")
        return real_open(path, *a, **kw)

    monkeypatch.setattr("builtins.open", exploding_open)
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(tmp_path))
    monkeypatch.undo()

    assert findings == [], "an unreadable file cannot yield findings"
    assert scanner.errors, "the OSError must be recorded, not swallowed"
    assert "unreadable" in scanner.errors[0]["reason"], scanner.errors[0]
    assert scanner.coverage["files_skipped"] >= 1, "the skip must be counted"



def test_kills_SCAN01_undecodable_file_is_recorded(tmp_path):
    """The portable sibling of the above: invalid UTF-8 must also be recorded, not ignored."""
    p = tmp_path / "bad.py"
    p.write_bytes(b"\xff\xfe\x00\x00invalid utf8")
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(tmp_path))
    assert findings == []
    assert scanner.errors, "an undecodable file must be recorded as an error"
    assert "undecodable" in scanner.errors[0]["reason"]


# ===========================================================================================
# Kills SCAN-03 -- symlink containment
# ===========================================================================================
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_kills_SCAN03_symlink_escape_is_skipped_and_recorded(tmp_path):
    """A symlink pointing outside the scan root must be skipped AND recorded.

    Two distinct obligations. Skipping without recording is indistinguishable from a missed
    detection; recording without skipping still reads the file.
    """
    secret = tmp_path / "outside" / "key.pem"
    secret.parent.mkdir()
    secret.write_text("-----BEGIN RSA PRIVATE KEY-----", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "config.py"
    try:
        os.symlink(secret, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")

    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(root))
    assert findings == [], f"a symlink out of the root must not be scanned: {findings}"
    assert scanner.errors, "the skip must be recorded, not silent"
    joined = " ".join(e["reason"] for e in scanner.errors)
    assert "symlink" in joined or "credential" in joined, joined


def test_kills_SCAN03_scan_root_refusal_is_recorded(tmp_path):
    """A nonexistent root is a recorded error, never an exception."""
    scanner = ECDATScanner(enable_ml=False)
    assert scanner.scan_directory(str(tmp_path / "does-not-exist")) == []
    assert scanner.errors, "a missing path must be recorded as an error"


def test_kills_SCAN03_containment_check_is_enforced_platform_independently(tmp_path, monkeypatch):
    """Containment must hold even where the OS will not let us create a real symlink.

    Windows without admin refuses `os.symlink`, so the behavioural test above is skipped there
    and the containment mutant would survive on this platform. Here the walk is intercepted: a
    file inside the root reports a realpath pointing OUTSIDE it, exactly what a symlink does.
    The scanner must skip it and record the skip -- not scan it.
    """
    root = tmp_path / "root"
    root.mkdir()
    (root / "innocent.py").write_text("key = rsa.newkeys(2048)\n", encoding="utf-8")
    real_realpath = os.path.realpath

    def fake_resolve(root_, path_):
        # The scanner must treat an escaping path as refused (None) and record it.
        if str(path_).endswith("innocent.py"):
            return None
        return real_realpath(path_)

    monkeypatch.setattr("engine.scanner.resolve_within", fake_resolve)
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(root))
    monkeypatch.undo()

    names = {os.path.basename(f["file"]) for f in findings}
    assert "innocent.py" not in names, (
        f"a path reported as escaping the root must not be scanned; got {names}")
    reasons = " ".join(e["reason"] for e in scanner.errors)
    assert "symlink" in reasons, f"the escape must be recorded as such; errors={scanner.errors}"



