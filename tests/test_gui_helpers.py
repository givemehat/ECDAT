"""Tests for the console's presentation helpers (`engine/gui_helpers.py`).

These exist because the claims the console makes are checkable claims. The colour contrast, the
HTML escaping, the "clean versus not looked at" verdict and the CBOM validation result are all
things a reviewer should be able to assert without starting a web server, so they are asserted
here instead. Nothing in this module imports Streamlit, and no test touches the network.
"""
import json
import os

import pytest

from engine.cbom import generate_cbom
from engine.gui_helpers import (ASSURANCE_COLOURS, TIER_COLOURS, assurance_counts,
                                auditor_rows, bar_chart_svg, certificate_rows,
                                certificate_summary, contrast_ratio, coverage_verdict,
                                dependency_rows, dependency_summary, enrich_findings, escape,
                                evidence_needed, ink_on, proven_use, queue_rows,
                                sensor_status_rows, short_path, tier_counts, unresolved_split,
                                validate_cbom_document, verification_rows, verification_summary)
from engine.theme import (proof_bar, reveal, risk_ring_panel, risk_score, scanning_indicator,
                                score_ring_svg)

SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "schemas", "bom-1.7.schema.json")

AMBIGUOUS_RSA = dict(name="RSA", primitive="pke", type="algorithm", uses="tls",
                     match='KeyPairGenerator.getInstance("RSA")', file="a/RSAKeyGen.java", line=1,
                     rule_id="ECD-SRC-RSA-003", evidence_class="discovered")
SIGNING_RSA = dict(name="ECDSA", primitive="signature", type="algorithm", uses="signing",
                   match="ec.ECDSA(", file="a/keys.py", line=9, rule_id="ECD-SRC-ECDSA-001",
                   evidence_class="discovered")
AES = dict(name="AES", primitive="ae", type="algorithm", key_length=256, uses="at-rest",
           match="AESGCM", file="a/aes.py", line=2, rule_id="ECD-SRC-AES-001",
           evidence_class="discovered")
DECLARED = dict(name="TLS", primitive="protocol", type="protocol", uses="tls",
                match="TLSv1.2", file="a/openssl.cnf", line=1, rule_id="ECD-CFG-TLS-001",
                evidence_class="configured")


def _rate(findings, **kwargs):
    params = dict(z_years=10, policy="india_dst_nqm", data_class="operational-record")
    params.update(kwargs)
    return enrich_findings(findings, **params)


# ---------------------------------------------------------------------------------------------
# Colour: the fills are dark, so the ink on top of them has to be legible. Asserted, not assumed.
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("colour", sorted(set(TIER_COLOURS.values())
                                          | set(ASSURANCE_COLOURS.values())))
def test_ink_on_every_fill_is_legible(colour):
    assert contrast_ratio(ink_on(colour), colour) >= 4.5


def test_ink_picks_the_better_of_the_two_candidates():
    for colour in TIER_COLOURS.values():
        chosen = contrast_ratio(ink_on(colour), colour)
        other = contrast_ratio("#0B0F14" if ink_on(colour) == "#FFFFFF" else "#FFFFFF", colour)
        assert chosen >= other


# ---------------------------------------------------------------------------------------------
# Escaping: findings carry file paths and matched source text, both attacker-influenced.
# ---------------------------------------------------------------------------------------------

def test_escape_neutralises_markup_in_finding_text():
    assert escape("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"
    assert escape("a & b") == "a &amp; b"
    assert escape(None) == ""


def test_chart_states_its_values_as_text_not_only_as_colour():
    svg = bar_chart_svg([("used", 3, "#1F5C3A"), ("capability", 1, "#3D4756")],
                        aria_label="Assurance")
    assert 'role="img"' in svg and 'aria-label="Assurance"' in svg
    assert ">3<" in svg and ">1<" in svg          # the numbers are readable as text
    assert "#1F5C3A" in svg and "#3D4756" in svg  # and the fills carry the same information


def test_all_zero_chart_says_so_instead_of_drawing_nothing():
    svg = bar_chart_svg([("used", 0, "#1F5C3A")], aria_label="Assurance",
                        empty_label="0 findings")
    assert "0 findings" in svg and "stroke-dasharray" in svg


# ---------------------------------------------------------------------------------------------
# The honesty arithmetic
# ---------------------------------------------------------------------------------------------

def test_proven_use_is_never_confused_with_the_total():
    records = _rate([AMBIGUOUS_RSA, SIGNING_RSA, AES, DECLARED])
    assert len(records) == 4
    assert proven_use(records) == 3                     # the configured one is only 'declared'
    assert proven_use(records) < len(records)
    assert assurance_counts(records)["declared"] == 1
    assert sum(tier_counts(records).values()) == 4      # every record lands in exactly one tier


def test_unresolved_purpose_splits_into_declined_and_named():
    records = _rate([AMBIGUOUS_RSA, SIGNING_RSA])
    declined, named = unresolved_split(records)
    assert [r["name"] for r in declined] == ["RSA"]    # pke + purpose signals -> no target named
    assert [r["name"] for r in named] == ["ECDSA"]     # primitive already typed -> target named


def test_a_finding_the_risk_calculator_cannot_rate_is_kept_and_flagged():
    records = _rate([AMBIGUOUS_RSA], z_years=-5)        # negative Z is rejected by the engine
    assert len(records) == 1
    assert records[0]["rating_error"]
    assert records[0]["tier"] == "UNRATED"
    assert records[0]["recommendation"]["algorithm"]    # the recommendation still ran


def test_queue_puts_the_human_review_items_first():
    rows = queue_rows(_rate([AES, SIGNING_RSA, AMBIGUOUS_RSA]), deadline_year=2029)
    assert rows[0]["Status"].startswith("TARGET DECLINED")
    assert rows[0]["#"] == 1


def test_auditor_rows_carry_the_inputs_not_just_the_verdict():
    row = auditor_rows(_rate([SIGNING_RSA]))[0]
    # "Tier at Z=5/10/15" became "Tier at Z" plus a "Z values" column. The hardcoded label
    # asserted a fixed 5/10/15 range, but the engine now centres the sensitivity band on the
    # CALLER's Z, so at Z=40 the band is 35/40/45. A column whose name promises Z values the
    # table does not contain is a false claim about the analysis, not a label.
    for column in ("X (y)", "Y (y)", "Z (y)", "Margin", "Tier at Z", "Z values",
                   "Stable across Z", "Rule", "Location"):
        assert column in row, "auditor table must carry %r" % column
    assert row["Location"].endswith("keys.py:9")


def test_auditor_z_columns_agree_with_the_band_the_engine_produced():
    """The regression test for the hardcoded (5, 10, 15).

    At a non-default Z the engine emits keys like Z=35/40/45. The table used to probe
    (5, 10, 15) against those keys, found nothing, and rendered three dashes -- while
    "Stable across Z" still said "yes". A sensitivity column that displays nothing while
    claiming stability is worse than no column at all.
    """
    # `_rate` is the module's own enrich helper, so purpose and assurance are populated exactly
    # as they are in the real pipeline. The z it is given becomes the Z the band is centred on.
    row = auditor_rows(_rate([SIGNING_RSA], z_years=40))[0]
    assert "-" * 3 not in row["Tier at Z"], (
        "a populated band must not render as dashes: %r" % row["Tier at Z"])
    probed = {float(v.split("=")[-1]) for v in row["Z values"].split(",") if v.strip()}
    assert 40.0 in probed, (
        "the table must show the Z values the engine actually evaluated, got %s" % probed)


def test_evidence_needed_is_specific_to_the_primitive_not_generic():
    steps = " ".join(evidence_needed(_rate([AMBIGUOUS_RSA])[0]))
    assert "KeyUsage" in steps and "handshake" in steps.lower()
    assert "signs and does not encrypt" in " ".join(evidence_needed(_rate([SIGNING_RSA])[0]))


# ---------------------------------------------------------------------------------------------
# Coverage: 'clean' and 'not looked at' must never render the same way
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("manifest,expected", [
    ({"files_seen": 0, "files_scanned": 0, "files_skipped": 0, "errors": []},
     "nothing-examined"),
    ({"files_seen": 9, "files_scanned": 0, "files_skipped": 9,
      "errors": [{"file": "x", "reason": "unreadable"}]}, "nothing-examined"),
    ({"files_seen": 9, "files_scanned": 7, "files_skipped": 2,
      "errors": [{"file": "x", "reason": "credential store"}]}, "incomplete"),
    ({"files_seen": 9, "files_scanned": 9, "files_skipped": 0, "errors": []}, "covered"),
])
def test_coverage_verdict_names_the_state(manifest, expected):
    verdict = coverage_verdict(manifest)
    assert verdict["state"] == expected
    assert verdict["message"]


def test_a_clean_result_over_an_unreadable_tree_is_never_reported_as_clean():
    verdict = coverage_verdict({"files_seen": 4, "files_scanned": 0, "files_skipped": 4,
                                "errors": [{"file": "a", "reason": "binary"}]})
    assert verdict["state"] == "nothing-examined"
    assert "clean" in verdict["message"]


def test_short_path_keeps_the_tail_only():
    assert short_path("/a/b/c/d.py") == "c/d.py"
    assert short_path("d.py") == "d.py"
    assert short_path(None) == "n/a"


# ---------------------------------------------------------------------------------------------
# CBOM validation: shown on screen, and the download is withheld when it cannot be proven
# ---------------------------------------------------------------------------------------------

@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="CycloneDX 1.7 schema not cached")
def test_a_generated_cbom_validates_and_is_offered():
    pytest.importorskip("jsonschema")
    records = _rate([AMBIGUOUS_RSA, SIGNING_RSA, AES])
    document = json.loads(generate_cbom(records, enriched=True, subject_name="t"))
    result = validate_cbom_document(document, SCHEMA)
    assert result["ok"] and result["state"] == "valid"
    assert result["component_count"] == len(records)
    assert result["errors"] == []


@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="CycloneDX 1.7 schema not cached")
def test_a_broken_cbom_is_reported_invalid_rather_than_raising():
    pytest.importorskip("jsonschema")
    result = validate_cbom_document(
        {"bomFormat": "CycloneDX", "specVersion": "1.7",
         "components": [{"type": "nonsense"}]}, SCHEMA)
    assert not result["ok"] and result["state"] == "invalid"
    assert result["errors"]


def test_a_missing_schema_is_explained_and_never_raises():
    result = validate_cbom_document({"specVersion": "1.7"}, os.path.join("no", "such.json"))
    assert not result["ok"]
    assert result["state"] in ("schema-missing", "library-missing")
    assert "conformant" in result["message"] or "no CBOM download" in result["message"]


# ===========================================================================================
# Advanced-sensor presentation helpers.
#
# These four engines were built and tested but were unreachable from the console, so the tests
# here guard the thing that actually caused the gap: a sensor that silently contributes nothing.
# Every one of these asserts the QUALIFIER survives, not just the total.
# ===========================================================================================

def test_sensor_status_distinguishes_ran_from_available_from_missing():
    rows = sensor_status_rows(
        available=["certificates", "dependencies", "network"],
        ran=["certificates"],
        headline={"certificates": "3 certificate(s) parsed"})
    by_key = {r["key"]: r for r in rows}
    assert by_key["certificates"]["state"] == "ran"
    assert "3 certificate" in by_key["certificates"]["note"]
    assert by_key["dependencies"]["state"] == "not run"
    assert by_key["verification"]["state"] == "unavailable"
    # Every sensor is listed even when absent -- that is the whole point of the table.
    assert len(rows) == 4


def test_certificate_rows_expose_key_usage_and_never_guess_purpose():
    rows = certificate_rows([
        {"file": "a/b/cert.pem", "name": "RSA-2048", "sig_algorithm": "sha256WithRSAEncryption",
         "key_usage": ["digitalSignature"], "purpose": "signature", "not_after": "2030-01-01"},
        {"file": "d/e/f.pem", "name": "EC-P256", "sig_algorithm": "sha1WithRSAEncryption",
         "key_usage": ["digitalSignature", "keyEncipherment"]},
    ])
    assert rows[0]["purpose"] == "signature"
    assert rows[0]["key_usage"] == "digitalSignature"
    # A dual-use cert has ambiguous KeyUsage, so it must NOT be assigned a purpose.
    assert rows[1]["purpose"] == "unresolved"
    assert "digitalsignature" in rows[1]["key_usage"].lower()


def test_certificate_summary_breaks_down_rather_than_reporting_a_bare_total():
    recs = [
        {"expired": True, "sig_algorithm": "sha1WithRSAEncryption",
         "key_usage": ["digitalSignature"], "purpose": "signature"},
        {"sig_algorithm": "sha256WithRSAEncryption",
         "key_usage": ["digitalSignature", "keyEncipherment"]},
    ]
    s = certificate_summary(recs)
    assert s["total"] == 2
    assert s["expired"] == 1
    assert s["weak_signature"] == 1        # SHA-1 is classically broken, not a Grover issue
    assert s["dual_use_unresolved"] == 1
    assert s["by_purpose"]


def test_certificate_rows_tolerate_missing_fields():
    rows = certificate_rows([{}])
    assert rows[0]["key_usage"] == "absent"
    assert rows[0]["purpose"] == "unresolved"


def test_dependency_rows_preserve_the_capability_assurance_and_none_verdict():
    rows = dependency_rows([
        {"name": "pyca/cryptography", "ecosystem": "pypi", "version": "42.0.0",
         "provides": ["AES-GCM", "ECDH", "RSA"], "provides_pqc": True},
        {"name": "jose", "ecosystem": "npm", "provides": ["RSA", "HS256"], "provides_pqc": None},
    ])
    assert rows[0]["provides_pqc"] is True
    assert rows[0]["version"] == "42.0.0"
    # Undetermined must stay None, NOT collapse to False: "maybe after an upgrade" != "no".
    assert rows[1]["provides_pqc"] is None
    assert rows[1]["version"] == "unpinned"
    s = dependency_summary([
        {"provides_pqc": True}, {"provides_pqc": None}, {"provides_pqc": False}, {},
    ])
    assert s["total"] == 4
    assert s["provide_pqc"] == 1
    assert s["pqc_undetermined"] == 2   # `{}` has no PQC claim: undetermined, NOT classical-only
    assert s["provide_classical_only"] == 1
    assert s["unpinned"] == 4
    assert "capability" in s["assurance"]


def test_verification_keeps_deprecated_kyber_separate_from_ml_kem():
    report = {"verdict": "MIGRATED", "verified": True, "files_examined": 12,
              "algorithms": {"ML-KEM-768": {"status": "verified", "matches": 3,
                                            "reasons": ["kyber768 in tlslite"]},
                             "ECDH": {"status": "no-usage", "matches": 0, "reasons": []}},
              "deprecated_variants": [{"marker": "kyber512r1"}],
              "hybrids": [{"name": "ECDHE-ML-KEM"}], "verdict_reason": "ML-KEM in use."}
    rows = verification_rows(report)
    by_algo = {r["algorithm"]: r for r in rows}
    assert by_algo["ML-KEM-768"]["status"] == "verified"
    assert by_algo["ECDH"]["status"] == "no-usage"
    # The deprecated draft marker must travel with the row, so it cannot read as "migrated".
    assert by_algo["ML-KEM-768"]["deprecated"] == "kyber512r1"
    s = verification_summary(report)
    assert s["verdict"] == "MIGRATED"
    assert s["hybrids"] == ["ECDHE-ML-KEM"]
    assert s["deprecated"] == ["kyber512r1"]


def test_verification_summary_of_nothing_is_not_a_pass():
    s = verification_summary(None)
    assert s["verdict"] == "not run"
    assert s["verified"] is False


# ===========================================================================================
# Theme system.
#
# The CSS was written by appending to a file, and appending silently truncated two rules mid-block
# on the first attempt. A browser drops a malformed rule without a word, so `test_the_stylesheet_is_structurally_balanced` is not pedantry: it is the only thing standing between a broken edit and a console that looks fine and styles nothing.
# ===========================================================================================

def test_the_stylesheet_is_structurally_balanced():
    from engine.theme import CSS
    assert CSS.count("<style>") == CSS.count("</style>") == 1
    assert CSS.count("{") == CSS.count("}"), "an unbalanced brace makes a browser drop the rule"
    assert CSS.count("(") == CSS.count(")"), "an unbalanced paren does the same"


def test_the_stylesheet_honours_reduced_motion():
    from engine.theme import CSS
    assert "prefers-reduced-motion" in CSS
    # Motion is permitted, but only conditionally. A console that cannot be read by someone who
    # has asked their OS for less motion is not finished.
    assert "@keyframes" in CSS


def test_the_stylesheet_defines_every_token_it_uses():
    import re
    from engine.theme import CSS
    declared = set(re.findall(r"(--[a-z0-9-]+)\s*:", CSS))
    used = set(re.findall(r"var\((--[a-z0-9-]+)\)", CSS))
    # A var() with no declaration resolves to nothing and inherits silently -- no error, just a
    # colour that quietly falls back to the browser default.
    assert used <= declared, f"undeclared custom properties: {sorted(used - declared)}"


def test_proof_bar_encodes_the_proven_share_and_its_remainder():
    html = proof_bar(3, 12)
    assert "width:25.00%" in html
    assert "3 proven use" in html
    assert "9 other findings" in html            # singular/plural on the remainder
    assert 'role="img"' in html                  # the bar carries meaning for a screen reader
    assert "3 of 12" in html


def test_proof_bar_never_renders_a_zero_total_as_zero_percent():
    """Zero findings is ambiguous by construction: an unreadable tree and a clean tree both
    produce it. A 0% bar would render that ambiguity as a clean result."""
    html = proof_bar(0, 0)
    assert "width:" not in html
    assert "no findings" in html
    assert "coverage manifest" in html


def test_proof_bar_singular_remainder_and_clamped_width():
    assert "1 other finding<" in proof_bar(8, 9)   # singular, and not "1 other findings"
    # A corrupt input (proven > total) must not overflow the bar past 100%.
    assert "width:100.00%" in proof_bar(50, 10)


def test_proof_bar_escapes_a_hostile_caption():
    hostile = proof_bar(1, 2, caption="<script>alert(1)</script>")
    assert "<script>" not in hostile
    assert "&lt;script&gt;" in hostile


def test_reveal_is_capped_so_the_tail_never_arrives_late():
    assert reveal(0) == "ec-reveal"
    assert reveal(2) == "ec-reveal ec-reveal-2"
    # Past step 4 the delay would read as a broken page rather than a stagger.
    assert reveal(4) == "ec-reveal ec-reveal-4"
    assert reveal(99) == "ec-reveal ec-reveal-4"


def test_scanning_indicator_is_the_only_unattended_animation():
    assert "ec-scanning" in scanning_indicator("scanning")
    assert scanning_indicator("probing").count("probing") == 1


# ===========================================================================================
# The risk ring.
#
# The ring is the first thing a non-technical judge looks at, so its failure modes are
# reputational rather than technical. Three of them are asserted below, in order of how badly
# they would read on a projector.
# ===========================================================================================

def _finding(shor=False, level="capability"):
    return {"risk": {"break_model": "shor" if shor else "grover"},
            "assurance": {"value": level}}


def test_the_ring_score_is_never_shown_without_its_working():
    """A gauge is a verdict with no argument attached.

    The panel must state how the number was reached. A reader who cannot recompute it cannot
    challenge it, and a security tool that emits an unexplainable score is doing the exact thing
    it exists to prevent.
    """
    payload = risk_score([_finding(shor=True, level="used")] * 6
                         + [_finding(shor=False)] * 2)
    panel = risk_ring_panel(payload)
    assert "Method:" in panel
    assert "not a measurement" in panel
    assert "6" in panel and "8" in panel          # the actual inputs, not just a score


def test_zero_findings_is_never_rendered_as_a_perfect_score():
    """The single most dangerous possible misreading.

    A ring reading 0 with a green arc says "you are safe". But zero findings is what an
    UNREADABLE tree produces too. The empty case must refuse to draw a ring at all.
    """
    payload = risk_score([])
    assert payload["score"] == 0 and payload["total"] == 0
    panel = risk_ring_panel(payload)
    assert "<svg" not in panel, "an empty scan must not draw a score ring at all"
    assert "not a clean bill of health" in panel


def test_the_ring_is_animatable_and_correct_without_the_animation():
    """The dash offsets are written as the SETTLED state; the animation only approaches them.

    If motion is reduced, blocked, or never runs, the ring must still show the right value. An
    animation that is load-bearing for a displayed number is one more way to show a wrong answer.
    """
    payload = {"score": 42.0, "tier": "moderate", "total": 10, "proven": 3, "shor_broken": 4}
    svg = score_ring_svg(payload)
    assert "stroke-dasharray" in svg
    assert "prefers-reduced-motion" in svg, "the ring must honour a reduced-motion preference"
    assert "animation:none" in svg
    # The final dasharray encodes the value, not zero -- that is the settled state.
    assert "stroke-dasharray:0.00" not in svg


def test_the_ring_carries_a_readable_label_not_just_colour():
    """Colour is never the only channel, in this project, and that includes the ring."""
    svg = score_ring_svg({"score": 70.0, "tier": "high", "total": 9, "proven": 2,
                          "shor_broken": 6})
    assert 'role="img"' in svg
    assert "aria-label=" in svg
    assert "70" in svg and "2 of 9" in svg
    assert "high" in svg


def test_proven_evidence_raises_the_score_but_only_slightly():
    """The weighting is a stated opinion and the test states it too.

    If evidence dominated the score, a tool that found more unevidenced capability would look
    "safer" for being less thorough -- which is backwards. The bonus is capped at 10 points.
    """
    without = risk_score([_finding(shor=True)] * 10 + [_finding(shor=False)] * 10)
    with_ev = risk_score([_finding(shor=True, level="used")] * 10 + [_finding(shor=False)] * 10)
    # 50% Shor-broken gives a base of 50 either way; the 10 proven findings add 5 points.
    assert 0 < (with_ev["score"] - without["score"]) <= 10.0
    assert round(without["score"], 1) == 50.0


def test_the_ring_survives_a_record_with_no_risk_block():
    """Scan output crosses a JSON boundary; a record may arrive with no risk at all.

    It must render as a lower score, never as a crash on the headline screen.
    """
    payload = risk_score([{"name": "x"}, {"name": "y", "risk": {"break_model": "shor"}}])
    assert payload["total"] == 2 and payload["shor_broken"] == 1
    assert score_ring_svg(payload).startswith("<svg")
