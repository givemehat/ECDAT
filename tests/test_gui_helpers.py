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
                                auditor_rows, bar_chart_svg, contrast_ratio, coverage_verdict,
                                enrich_findings, escape, evidence_needed, ink_on, proven_use,
                                queue_rows, short_path, tier_counts, unresolved_split,
                                validate_cbom_document)

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
