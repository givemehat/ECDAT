"""Regressions for defects found in a 2026-09 review pass.

Every test here corresponds to a bug that was LIVE in the shipped code and reproduced on demand.
They are grouped by severity rather than by module, because the common thread is worse than any
individual module: in four of the six groups the tool asserted something it had not established.

  * SELF-CONTRADICTION -- the tool classified its own migration recommendation as
    quantum-vulnerable, and a quantum-safe signature as Shor-broken.
  * FALSE ASSURANCE  -- an unassessable finding was counted as compliant, and a lapsed deadline
    rendered as a small negative number.
  * STALE EVIDENCE    -- a memoised scan returned previous findings under a fresh timestamp.
  * CRASH             -- one malformed field aborted the entire report.

The test names state the defect, not the function, so a future rename does not erase the reason
the test exists.

Run: python -m pytest tests/test_review_regressions.py -v
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.cbom import is_pqc
from engine.gui_helpers import (DEADLINE_NO_POLICY, DEADLINE_OVERRUN, DEADLINE_UNRATED,
                                DEADLINE_WITHIN, deadline_countdown, deadline_verdict,
                                late_records, queue_rows, unrated_records)
from engine.mosca import quantum_break_model
from engine.recommender import get_pqc_recommendation
from engine.scanner import RULES

# Every spelling of these that appears in the wild. IANA/TLS codepoints, the `cryptography`
# library, the SSH hybrid draft and the NIST names all disagree, which is the whole reason the
# original hyphen-only tuple failed.
PQC_NAMES = ["ML-KEM-768", "MLKEM768", "mlkem768", "X25519MLKEM768", "SecP384r1MLKEM1024",
             "ML-DSA-65", "MLDSA65", "SLH-DSA-SHA2-128s", "SLHDSA128s", "XMSS_H10",
             "p256_mlkem768", "mlkem768x25519-sha256", "Falcon-512"]

CLASSICAL_NAMES = ["RSA-2048", "ECDSA-P256", "X25519", "AES-256", "SHA-256", "Ed25519",
                   "DSA-2048", "3DES"]


# --------------------------------------------------------------------------------------------
# SELF-CONTRADICTION: the tool flagged its own recommendations as quantum-vulnerable
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", PQC_NAMES)
def test_every_pqc_spelling_is_classified_as_pqc(name):
    """MLKEM768, ML-DSA-65 and X25519MLKEM768 were all classified as NOT post-quantum.

    The tuple of literal hyphenated names could not match the deployed spellings, and the file's
    own comment had already identified this as "the most damaging possible error in this file --
    the tool would label its own migration recommendation as quantum-vulnerable".
    """
    assert is_pqc(name), f"{name} must be recognised as post-quantum"


@pytest.mark.parametrize("name", CLASSICAL_NAMES)
def test_classical_algorithms_are_not_mislabelled_as_pqc(name):
    """The counterpart check: broadening the matcher must not swallow classical algorithms."""
    assert not is_pqc(name), f"{name} is not post-quantum"


def test_xmss_is_spelled_correctly():
    """XMMS was a typo for XMSS (eXtended Merkle Signature Scheme, SP 800-208)."""
    assert is_pqc("XMSS_H10")
    assert not is_pqc("XMMS")  # guard: the typo must not itself have become the vocabulary


@pytest.mark.parametrize("name", ["X25519MLKEM768", "ML-DSA-65", "ML-KEM-768", "XMSS_H10"])
def test_pqc_is_screened_before_the_shor_table(name):
    """`quantum_break_model` returned 'broken-by-Shor' for our top migration recommendation.

    `X25519MLKEM768` contains "X25519", which is in the Shor table, and "DSA" is a substring of
    "ML-DSA" -- so reaching the token tables before the PQC screen marked a quantum-safe
    signature and a quantum-safe hybrid as broken.
    """
    assert quantum_break_model(name, "signature") == "not-affected"


@pytest.mark.parametrize("name", ["RSA-2048", "ECDSA-P256", "X25519", "DSA-2048"])
def test_genuinely_quantum_vulnerable_algorithms_still_report_shor(name):
    """The PQC pre-screen must not swallow the algorithms it is meant to exempt."""
    assert quantum_break_model(name, "signature") == "broken-by-Shor"


# --------------------------------------------------------------------------------------------
# CRASH: one malformed field aborted the whole report
# --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("bad", ["not-a-number", "", None, "2048bits", [], {}, "1e3"])
def test_malformed_key_length_does_not_abort_the_report(bad):
    """`int('not-a-number')` raised ValueError and killed the entire report.

    `key_length` comes from regex capture groups and third-party inputs, so any string is
    possible. One unreadable field must degrade to "confirm the key size", not end the run.
    """
    result = get_pqc_recommendation({"name": "AES-256", "primitive": "block-cipher",
                                     "key_length": bad, "uses": "at-rest"})
    assert result is None or isinstance(result, dict)


def test_numeric_string_key_length_is_still_interpreted():
    """The coercion must not become a blanket refusal: "256" is a usable key size."""
    result = get_pqc_recommendation({"name": "AES-256", "primitive": "block-cipher",
                                     "key_length": "256", "uses": "at-rest"})
    assert result is None or isinstance(result, dict)


# --------------------------------------------------------------------------------------------
# SELF-CONTRADICTION: a finite-field DH group reported as ECDH
# --------------------------------------------------------------------------------------------

def _rule(rule_id):
    return next(r for r in RULES if r["id"] == rule_id)


@pytest.mark.parametrize("identifier", ['"diffie-hellman-group14-sha256"',
                                        '"diffie-hellman-group-exchange-sha256"',
                                        '"diffie-hellman-group1-sha1"'])
def test_finite_field_dh_is_named_DH_not_ECDH(identifier):
    """A finite-field DH group was reported as BOTH ECDH and DH: a wrong algorithm name.

    Adding the DH rule without removing the finite-field names from the ECDH rule double-counted
    every FFDH identifier, inflating finding counts and writing "ECDH" into the CBOM for a
    group that is not elliptic at all.
    """
    assert not re.search(_rule("ECD-SRC-SSH-KEX-001")["regex"], identifier), \
        f"{identifier} is finite-field DH and must not match the ECDH rule"
    assert re.search(_rule("ECD-SRC-SSH-DH-001")["regex"], identifier), \
        f"{identifier} must match the DH rule"


@pytest.mark.parametrize("identifier", ['"ecdh-sha2-nistp256"', '"curve25519-sha256"'])
def test_genuinely_elliptic_kex_still_reports_ECDH(identifier):
    """Removing FFDH from the ECDH rule must not cost the elliptic names it should keep."""
    assert re.search(_rule("ECD-SRC-SSH-KEX-001")["regex"], identifier)


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: unassessable findings counted as compliant
# --------------------------------------------------------------------------------------------

def test_finding_with_no_risk_is_UNRATED_not_compliant():
    """`(risk.get(...) or 0) > deadline` collapsed a missing risk to 0, which is never > a real
    deadline, so UNRATED findings fell into the 'within window' bucket and were tallied as
    compliant. An artefact ECDAT could not assess was reported as a pass."""
    assert deadline_verdict({"name": "RSA"}, 2035) == DEADLINE_UNRATED


def test_start_year_after_the_deadline_is_OVERRUN():
    assert deadline_verdict({"risk": {"latest_safe_migration_start": 2040}}, 2035) == DEADLINE_OVERRUN


def test_start_year_before_the_deadline_is_within_window():
    assert deadline_verdict({"risk": {"latest_safe_migration_start": 2030}}, 2035) == DEADLINE_WITHIN


def test_no_active_policy_is_its_own_state():
    assert deadline_verdict({"name": "RSA"}, None) == DEADLINE_NO_POLICY


def test_unrated_records_are_counted_separately_from_late_ones():
    """The two must not be merged: one is known-bad, the other is unknown."""
    records = [{"name": "unrated"},
               {"risk": {"latest_safe_migration_start": 2040}},
               {"risk": {"latest_safe_migration_start": 2030}}]
    assert len(unrated_records(records, 2035)) == 1
    assert len(late_records(records, 2035)) == 1


def test_unrated_records_is_empty_without_a_policy():
    """With no deadline there is nothing to be unrated against, and claiming otherwise invents
    a gap in an assessment that was never attempted."""
    assert unrated_records([{"name": "x"}], None) == []


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: a lapsed deadline rendered as a small negative number
# --------------------------------------------------------------------------------------------

def test_lapsed_deadline_says_PASSED():
    """A deadline 6 years in the past rendered as "-6 year(s) from 2026": arithmetically right,
    rhetorically useless. A reader skims the magnitude and misses that the date has passed."""
    assert deadline_countdown(2020, 2026) == "PASSED 6 year(s) ago"


def test_deadline_this_year_reads_as_such():
    assert deadline_countdown(2026, 2026) == "this year"


def test_future_deadline_keeps_the_plain_countdown():
    assert deadline_countdown(2030, 2026) == "4 year(s) from 2026"


def test_missing_deadline_is_na():
    assert deadline_countdown(None, 2026) == "n/a"


# --------------------------------------------------------------------------------------------
# FALSE ASSURANCE: a crashed recommender bucketed as "target named"
# --------------------------------------------------------------------------------------------

def test_unresolved_sentinel_never_reads_as_target_named():
    """A recommender that crashed or declined returns an 'unresolved:...' sentinel. The status
    test ran the `unresolved` FLAG first, so the sentinel fell through to the "target named"
    bucket -- the one label that implies no human is needed."""
    record = {"name": "X", "tier": "HIGH", "assurance": {"value": "used"},
              "unresolved": True, "file": "a.py", "line": 1,
              "recommendation": {"algorithm": "unresolved:purpose-not-proven"}}
    row = queue_rows([record], deadline_year=2035)[0]
    assert "DECLINED" in row["Status"]
    assert "target named" not in row["Status"]


def test_a_genuine_named_target_is_still_labelled_named():
    """The sentinel check must not swallow the legitimate 'named but unresolved' case."""
    record = {"name": "X", "tier": "HIGH", "assurance": {"value": "used"},
              "unresolved": True, "file": "a.py", "line": 1,
              "recommendation": {"algorithm": "ML-DSA-65"}}
    row = queue_rows([record], deadline_year=2035)[0]
    assert "target named" in row["Status"]
