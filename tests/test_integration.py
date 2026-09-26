"""End-to-end pipeline test: scan -> Mosca -> recommendation -> CycloneDX CBOM.

Exercises the full path the brief describes, without requiring PyTorch (regex-only mode) so it
runs anywhere the test suite runs.
"""
import json

from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk, DATA_CLASS_LIFETIME
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom, SPEC_VERSION

RSA_SNIPPET = "from cryptography.hazmat.primitives.asymmetric import rsa\nkey = rsa.generate_private_key(65537, 2048)\n"
ECDH_SNIPPET = "from cryptography.hazmat.primitives.asymmetric import ec\npriv = ec.generate_private_key(ec.SECP256R1())\n"


def _pipeline(target, z=10, policy="india_dst_nqm"):
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(target)
    enriched = []
    for f in findings:
        f["risk"] = calculate_risk(f, z_collapse_time=z, policy=policy)
        f["recommendation"] = get_pqc_recommendation(f)
        enriched.append(f)
    cbom = generate_cbom(enriched, enriched=True, subject_name="integration-target",
                         coverage=scanner.coverage_manifest())
    return scanner, enriched, json.loads(cbom)


def test_full_pipeline_integration(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    (d / "kex.py").write_text(ECDH_SNIPPET, encoding="utf-8")

    scanner, findings, cbom = _pipeline(str(d))

    assert findings, "scanner found nothing"
    assert any(f["name"] == "RSA" for f in findings)
    assert any(f["name"] == "ECDH" for f in findings), "ECC detection is the brief's demo target"

    for f in findings:
        assert f["risk"]["tier"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert f["recommendation"]["algorithm"]
        assert f["recommendation"]["rule_trace"]

    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == SPEC_VERSION
    assert cbom["components"]
    assert scanner.coverage_manifest()["files_scanned"] >= 2


def test_data_lifetime_drives_the_verdict(tmp_path):
    """The brief requires classification by type, lifetime and criticality. Two identical RSA
    artefacts under different retention obligations must not receive the same verdict."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")

    scanner = ECDATScanner(enable_ml=False)
    base = scanner.scan_directory(str(d))
    rsa = [f for f in base if f["name"] == "RSA"][0]

    short = calculate_risk({**rsa, "data_class": "session", "artefact_class": "config"})
    long = calculate_risk({**rsa, "data_class": "statutory-archive", "artefact_class": "source"})

    assert short["tier"] != long["tier"]
    assert long["tier"] == "CRITICAL"
    assert long["hndl_exposed"] is True
    assert short["hndl_exposed"] is False


def test_z_is_tunable_end_to_end(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")

    _scanner, _findings, cbom = _pipeline(str(d), z=15, policy="nist_ir_8547")
    mosca_props = {p["name"]: p["value"] for c in cbom["components"] for p in c["properties"]}
    assert "ecd:mosca.z" in mosca_props
    assert mosca_props["ecd:mosca.z"] == "15.0"
    assert mosca_props["ecd:mosca.policy"] == "nist_ir_8547"
    assert mosca_props["ecd:mosca.policy_deadline"] == "2035"


def test_critical_risk_is_driven_by_real_inputs_not_detector_confidence(tmp_path):
    """Regression guard: a highly confident detection of short-lived crypto must not outrank a
    less confident detection of long-lived crypto."""
    d = tmp_path / "app"
    d.mkdir()
    (d / "vuln.py").write_text(RSA_SNIPPET, encoding="utf-8")
    scanner = ECDATScanner(enable_ml=False)
    rsa = [f for f in scanner.scan_directory(str(d)) if f["name"] == "RSA"][0]

    short = calculate_risk({**rsa, "dl_confidence": 0.99,
                            "data_class": "session", "artefact_class": "config"})
    long = calculate_risk({**rsa, "dl_confidence": 0.10,
                           "data_class": "health-record", "artefact_class": "source"})
    assert long["tier"] == "CRITICAL"
    assert short["tier"] != "CRITICAL"
    assert long["x"] > short["x"]
