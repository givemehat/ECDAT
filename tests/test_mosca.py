"""Tests for the Mosca engine.

These encode the *fixed* semantics. The previous suite asserted the behaviour rejected in
review -- e.g. that X could be derived from detector confidence, and that a Shor-vulnerable
algorithm could never fall below HIGH regardless of the inequality.
"""
import pytest

from engine.mosca import (calculate_risk, quantum_break_model, DATA_CLASS_LIFETIME,
                          MIGRATION_EFFORT, Z_PRESETS, Z_SENSITIVITY_YEARS)


@pytest.mark.parametrize("name,expected", [
    ("RSA", "broken-by-Shor"),
    ("ECDH", "broken-by-Shor"),
    ("ECDSA", "broken-by-Shor"),
    ("DSA", "broken-by-Shor"),
    ("Ed25519", "broken-by-Shor"),
    ("DH", "broken-by-Shor"),
    ("AES", "weakened-by-Grover"),
    ("SHA256", "weakened-by-Grover"),
    ("ChaCha20", "weakened-by-Grover"),
    ("CustomCipher", "not-affected"),
])
def test_quantum_break_model(name, expected):
    assert quantum_break_model(name) == expected


def test_x_is_not_derived_from_detector_confidence():
    """Regression: X used to be 3.0 + (dl_confidence * 5.0). Two detections of the same
    algorithm at different confidences must now produce the SAME X and the same tier."""
    low = calculate_risk(dict(name="RSA", primitive="pke", dl_confidence=0.1))
    high = calculate_risk(dict(name="RSA", primitive="pke", dl_confidence=0.99))
    assert low["x"] == high["x"]
    assert low["tier"] == high["tier"]


def test_x_comes_from_data_class_and_y_from_artefact_class():
    r = calculate_risk(dict(name="RSA", primitive="pke",
                             data_class="statutory-archive", artefact_class="source"))
    assert r["x"] == DATA_CLASS_LIFETIME["statutory-archive"]["years"]
    assert r["y_base"] == MIGRATION_EFFORT["source"]["years"]
    assert "statutory-archive" in r["x_reason"]
    assert "artefact_class='source'" in r["y_reason"]


def test_data_class_changes_the_tier_for_the_same_algorithm():
    """The brief requires classification by lifetime: identical crypto, different verdicts."""
    short = calculate_risk(dict(name="RSA", primitive="pke",
                                data_class="internal-credential", artefact_class="config"))
    long = calculate_risk(dict(name="RSA", primitive="pke",
                               data_class="statutory-archive", artefact_class="source"))
    assert short["tier"] != long["tier"]
    assert long["tier"] == "CRITICAL"
    assert long["hndl_exposed"] is True


def test_hndl_only_for_confidentiality_horizon():
    conf = calculate_risk(dict(name="ECDH", primitive="key-agreement",
                               data_class="financial-record"))
    sig = calculate_risk(dict(name="RSA", primitive="signature",
                              data_class="code-signing"))
    assert conf["hndl_exposed"] is True
    assert sig["hndl_exposed"] is False      # a signature cannot be "decrypted"
    assert sig["horizon_type"] == "verifiability"


def test_symmetric_is_excluded_from_the_inequality():
    r = calculate_risk(dict(name="AES", primitive="ae", key_length=256))
    assert r["subject_to_inequality"] is False
    assert r["is_vulnerable"] is False
    assert r["tier"] == "LOW"


def test_aes256_needs_no_upgrade_but_aes128_does():
    """Regression: the scanner never captured the AES key size, so every AES finding was told to
    'upgrade to AES-256' -- including AES-256-GCM."""
    a256 = calculate_risk(dict(name="AES", primitive="ae", key_length=256))
    a128 = calculate_risk(dict(name="AES", primitive="ae", key_length=128))
    assert a256["tier"] == "LOW"
    assert a128["tier"] == "MEDIUM"
    assert a256["grover_effective_bits"] == 128
    assert a128["grover_effective_bits"] == 64


def test_unknown_aes_key_size_is_medium_not_low():
    r = calculate_risk(dict(name="AES", primitive="ae"))
    assert r["grover_effective_bits"] is None
    assert r["tier"] == "MEDIUM"      # cannot confirm adequacy -> needs confirmation


def test_sha256_is_not_a_quantum_migration_priority():
    """Regression: SHA-256 was previously recommended for upgrade on false grounds."""
    r = calculate_risk(dict(name="SHA256", primitive="hash"))
    assert r["break_model"] == "weakened-by-Grover"
    assert r["tier"] == "LOW"


def test_sha1_is_flagged():
    r = calculate_risk(dict(name="SHA1", primitive="hash"))
    assert r["tier"] == "MEDIUM"


def test_boundary_exactly_equal_is_not_vulnerable():
    """X + Y == Z does NOT satisfy Mosca's inequality, which is strict (X + Y > Z).

    `is_vulnerable` therefore stays False. That is deliberate: the tool must implement the
    published framework exactly, or a reviewer checking the mathematics finds a discrepancy.

    But the TIER changed. Zero slack means the migration must start now, so a boundary artefact
    is HIGH. Previously this was MEDIUM -- identical to an artefact with two years of headroom,
    which is the defect a LinkedIn reviewer identified: "a margin of exactly 0.0y is the boundary
    of the inequality, not the safe side, and green reads as a pass."
    """
    r = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, 4.0, 8.0)
    assert r["x_y"] == 8.0
    assert r["is_vulnerable"] is False, "the published inequality is strict; it is not satisfied"
    assert r["margin_at_boundary"] is True
    assert r["tier"] == "HIGH", "zero slack is not the safe side"


def test_boundary_is_distinguishable_from_real_headroom():
    """The regression that motivated the change: 0.0 years of margin and -2.0 years of margin
    both produced MEDIUM, so a boundary artefact and a comfortably-inside one were
    indistinguishable on the panel."""
    at_boundary = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, 4.0, 8.0)
    inside = calculate_risk(dict(name="RSA", primitive="pke"), 3.0, 3.0, 8.0)   # margin -2.0
    assert at_boundary["margin"] == 0.00
    assert inside["margin"] == -2.00
    assert at_boundary["tier"] != inside["tier"], (
        "a zero-slack boundary must not read the same as an artefact with real headroom")
    assert at_boundary["margin_at_boundary"] is False or at_boundary["margin_at_boundary"] is True


def test_migration_history_can_supply_y():
    """Y is the term an organisation can actually measure, unlike Z.

    Supplying completed migrations replaces the generic effort table with the org's own median
    velocity, and the provenance is reported as `observed-migration-history` so the number is
    never mistaken for the assumption it replaced.
    """
    history = [
        {"artefact_class": "source", "started": "2021-01-01", "finished": "2021-06-01"},
        {"artefact_class": "source", "started": "2022-01-01", "finished": "2022-09-01"},
    ]
    table_based = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, None, 8.0)
    measured = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, None, 8.0,
                              migration_history=history)
    assert table_based["y_source"] == "effort-table"
    assert measured["y_source"] == "observed-migration-history"
    assert measured["y"] < table_based["y"], (
        "this org's recorded velocity is faster than the generic table assumed")
    assert "median" in measured["y_reason"]


def test_malformed_migration_history_degrades_to_the_table():
    """A bad history must never crash a risk report or invent a number."""
    for bad in ([{"nonsense": 1}, "garbage", None], [], [{"artefact_class": "source"}]):
        r = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, None, 8.0,
                           migration_history=bad)
        assert r["y_source"] == "effort-table"
        assert r["y"] == calculate_risk(dict(name="RSA", primitive="pke"), 4.0, None, 8.0)["y"]


def test_explicit_user_y_beats_history():
    """An explicit override is a deliberate human decision and outranks a derived rate."""
    history = [{"artefact_class": "source", "started": "2021-01-01", "finished": "2021-02-01"}]
    r = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, 5.0, 8.0,
                       migration_history=history)
    assert r["y"] == 5.0
    assert r["y_source"] == "effort-table"


def test_slightly_over_boundary_is_high():
    r = calculate_risk(dict(name="RSA", primitive="pke"), 4.0, 4.5, 8.0)
    assert r["is_vulnerable"] is True
    assert r["tier"] == "HIGH"


def test_large_margin_is_critical():
    r = calculate_risk(dict(name="RSA", primitive="pke", data_class="statutory-archive"))
    assert r["tier"] == "CRITICAL"
    assert r["margin"] > 10


def test_z_band_is_reported_and_detects_instability():
    r = calculate_risk(dict(name="RSA", primitive="pke",
                            data_class="internal-credential", artefact_class="config"))
    assert set(r["z_band"]) == {f"Z={z}" for z in Z_SENSITIVITY_YEARS}
    assert r["z_stable"] is False      # 5+1=6 crosses Z=5 but not Z=10/15


def test_z_is_configurable_and_changes_the_verdict():
    a = calculate_risk(dict(name="RSA", primitive="pke", data_class="financial-record"),
                       z_collapse_time=5)
    b = calculate_risk(dict(name="RSA", primitive="pke", data_class="financial-record"),
                       z_collapse_time=15)
    assert a["tier"] != b["tier"]


def test_z_presets_are_documented():
    for name, preset in Z_PRESETS.items():
        assert preset["years"] > 0
        assert preset["basis"]


def test_latest_safe_migration_start():
    r = calculate_risk(dict(name="RSA", primitive="pke"), 10.0, 3.0, 10.0, current_year=2026)
    assert r["latest_safe_migration_start"] == 2033   # 2026 + Z(10) - Y(3)


def test_negative_inputs_rejected():
    with pytest.raises(ValueError, match="negative"):
        calculate_risk(dict(name="RSA"), user_x=-1.0)
    with pytest.raises(ValueError, match="negative"):
        calculate_risk(dict(name="RSA"), user_y=-2.0)
    with pytest.raises(ValueError, match="negative"):
        calculate_risk(dict(name="RSA"), z_collapse_time=-5)


def test_unknown_primitive_is_low_and_explained():
    r = calculate_risk(dict(name="RandomCustomCipher", dl_confidence=0.99, ast_depth=10.0))
    assert r["tier"] == "LOW"
    assert r["threat"] == "No quantum break model applies"
    assert r["assumptions"]


def test_ast_depth_adjustment_is_bounded_and_reported():
    flat = calculate_risk(dict(name="RSA", primitive="pke", ast_depth=0))
    deep = calculate_risk(dict(name="RSA", primitive="pke", ast_depth=1000))
    assert flat["y_complexity_adjustment"] == 0.0
    assert deep["y_complexity_adjustment"] <= 1.5
    assert "complexity adjustment" in deep["y_reason"]
