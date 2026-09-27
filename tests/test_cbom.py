"""Tests for CycloneDX CBOM generation.

Regressions encoded here (all fixed 2026-09-25):
  * specVersion was pinned to 1.6 -> now 1.7
  * primitives were non-standard strings ("public-key-encryption") -> now the CycloneDX enum
  * nistQuantumSecurityLevel was never emitted -> now 0 for Shor-broken primitives
  * key size/curve/mode went into ad-hoc properties -> now algorithmProperties fields
  * property names collided with other tools -> now `ecd:`-namespaced
  * libraries were emitted as cryptographic-assets with a fake primitive -> now `type: library`
"""
import json

import pytest

from engine.cbom import generate_cbom, SPEC_VERSION, _canonical_primitive

VALID_PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
                    "xof", "kem", "ae", "combiner", "other", "unknown", "key-agree",
                    "kdf", "key-wrap"}


def test_empty_findings():
    cbom = json.loads(generate_cbom([]))
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == SPEC_VERSION
    assert cbom["components"] == []


def test_envelope_has_required_metadata():
    cbom = json.loads(generate_cbom([]))
    assert cbom["serialNumber"].startswith("urn:uuid:")
    assert cbom["metadata"]["timestamp"].endswith("Z")
    assert cbom["metadata"]["tools"]["components"][0]["name"] == "ecdat"
    assert cbom["version"] == 1


def test_spec_version_is_1_7():
    assert SPEC_VERSION == "1.7"


@pytest.mark.parametrize("raw,expected", [
    ("public-key-encryption", "pke"),
    ("digital-signature", "signature"),
    ("symmetric-encryption", "ae"),
    ("key-exchange", "key-agree"),
    ("hash", "hash"),
    ("cryptographic-library", "unknown"),
    ("neural-detected", "unknown"),
    ("nonsense", "unknown"),
])
def test_primitive_normalisation(raw, expected):
    assert _canonical_primitive(raw) == expected


def test_all_emitted_primitives_are_in_the_cyclonedx_vocabulary():
    findings = [
        dict(name="RSA", primitive="pke", key_length=2048, file="a.py", line=1),
        dict(name="ECDH", primitive="key-agreement", file="a.py", line=2),
        dict(name="ECDSA", primitive="signature", file="a.py", line=3),
        dict(name="AES", primitive="ae", key_length=256, mode="GCM", file="a.py", line=4),
        dict(name="SHA256", primitive="hash", file="a.py", line=5),
        dict(name="TLS", primitive="protocol", file="a.conf", line=6),
    ]
    cbom = json.loads(generate_cbom(findings))
    for comp in cbom["components"]:
        crypto = comp.get("cryptoProperties", {})
        if crypto.get("assetType") == "protocol":
            # protocols are modelled with protocolProperties, not algorithmProperties
            assert crypto["protocolProperties"]["type"] in {
                "tls", "ssh", "ipsec", "ike", "sstp", "wpa", "dtls", "quic", "other", "unknown"}
            continue
        prim = crypto["algorithmProperties"]["primitive"]
        assert prim in VALID_PRIMITIVES, f"non-standard primitive emitted: {prim}"


def test_nist_quantum_security_level_is_zero_for_shor_broken():
    """0 means "a CRQC breaks this", and is emitted ONLY where that is true.

    This test previously asserted 0 for every component in the CBOM without checking what the
    components were, which is how `nistQuantumSecurityLevel: 0` came to mean both "RSA is
    quantum-broken" and "we have no idea what category this symmetric cipher is". The value is
    load-bearing, so the test now names the algorithms it is asserting about.
    """
    findings = [
        dict(name="RSA", primitive="pke", key_length=2048, file="a.py", line=1),
        dict(name="ECDH", primitive="key-agreement", file="a.py", line=2),
    ]
    cbom = json.loads(generate_cbom(findings))
    for comp in cbom["components"]:
        ap = comp["cryptoProperties"]["algorithmProperties"]
        assert ap["nistQuantumSecurityLevel"] == 0, (
            "a Shor-broken asymmetric primitive must be 0")


def test_nist_quantum_security_level_is_not_zero_for_symmetric():
    """The counterpart: a symmetric primitive a CRQC does NOT break must not be published as 0.

    AES-256, SHA-3 and every MAC and KDF were all emitted as `nistQuantumSecurityLevel: 0` --
    the same value as RSA -- which told a consumer the tool believed a CRQC breaks them. It
    does not: Grover halves the exponent, and the result is not retroactive.
    """
    findings = [
        dict(name="AES", primitive="ae", key_length=256, mode="GCM", file="a.py", line=1),
        dict(name="SHA-256", primitive="hash", file="a.py", line=2),
    ]
    cbom = json.loads(generate_cbom(findings))
    for comp in cbom["components"]:
        ap = comp["cryptoProperties"]["algorithmProperties"]
        assert ap.get("nistQuantumSecurityLevel") != 0, (
            "%s is not broken by a CRQC and must not carry the Shor-broken value"
            % comp.get("name"))


def test_an_unknown_nist_category_is_omitted_not_asserted_as_zero():
    """Where the category is genuinely unknown the property is absent, and the gap is stated.

    The schema has no "unknown" member and sets `additionalProperties: false`, so the honest
    answer is to omit the field and say why in an `ecd:`-namespaced property -- not to publish
    a 0 that means the opposite of what the reader will take it to mean.
    """
    findings = [dict(name="ChaCha20", primitive="stream-cipher", file="a.py", line=1)]
    cbom = json.loads(generate_cbom(findings))
    comp = cbom["components"][0]
    ap = comp["cryptoProperties"]["algorithmProperties"]
    assert "nistQuantumSecurityLevel" not in ap
    gaps = [p for p in comp.get("properties", [])
            if p.get("name") == "ecd:nist_level_gap"]
    assert gaps, "an absent field must be explained, or it reads as 'no category exists'"


def test_key_size_and_mode_use_standard_algorithm_properties():
    finding = dict(name="AES", primitive="ae", key_length=256, mode="GCM", file="a.py", line=7)
    cbom = json.loads(generate_cbom([finding]))
    ap = cbom["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert ap["parameterSetIdentifier"] == "256"
    assert ap["mode"] == "gcm"
    assert ap["nistQuantumSecurityLevel"] == 5        # AES-256 survives Grover
    assert ap["cryptoFunctions"]


def test_all_custom_properties_are_namespaced():
    findings = [dict(name="RSA", primitive="pke", key_length=2048, file="a.py", line=1,
                     evidence_class="discovered", artefact_class="source", uses="at-rest",
                     scanner="source-scanner", rule_id="ECD-SRC-RSA-001",
                     risk={"tier": "CRITICAL", "x": 30, "y": 3, "z": 10, "margin": 23,
                           "hndl_exposed": True},
                     recommendation={"algorithm": "ML-KEM-768", "action": "Migrate",
                                     "rule_trace": "RULE-KEM-002", "standard_basis": ["FIPS 203"]})]
    cbom = json.loads(generate_cbom(findings, enriched=True))
    props = cbom["components"][0]["properties"]
    assert props, "expected ECDAT properties"
    for p in props:
        assert p["name"].startswith("ecd:"), f"collision risk: {p['name']}"
    names = {p["name"] for p in props}
    assert "ecd:mosca.tier" in names
    assert "ecd:mosca.hndl_exposed" in names
    assert "ecd:rec.rule_trace" in names


def test_legacy_property_names_are_gone():
    """Regression: moscaRiskTier / pqcRecommendation / keyLength were un-namespaced."""
    cbom = json.loads(generate_cbom([dict(name="RSA", primitive="pke", key_length=2048)]))
    blob = json.dumps(cbom)
    for legacy in ("moscaRiskTier", "pqcRecommendation", "quantumThreat", '"keyLength"'):
        assert legacy not in blob, f"legacy un-namespaced property still present: {legacy}"


def test_libraries_are_components_not_crypto_assets():
    """Regression: a library was emitted as cryptographic-asset with primitive
    'cryptographic-library', which is not a valid CycloneDX primitive."""
    finding = dict(name="OpenSSL/libcrypto", primitive="cryptographic-library",
                   type="library", file="libcrypto.so")
    cbom = json.loads(generate_cbom([finding]))
    comp = cbom["components"][0]
    assert comp["type"] == "library"
    assert "cryptoProperties" not in comp


def test_provenance_is_recorded():
    finding = dict(name="RSA", primitive="pke", key_length=2048, file="src/app.py", line=42)
    cbom = json.loads(generate_cbom([finding]))
    occ = cbom["components"][0]["evidence"]["occurrences"][0]
    assert occ["location"] == "src/app.py"
    assert occ["line"] == 42


def test_coverage_manifest_is_attached_when_supplied():
    coverage = {"files_scanned": 10, "files_skipped": 1, "ml_reason": "regex-only",
                "never_in_scope": ["network-negotiated crypto"]}
    cbom = json.loads(generate_cbom([], coverage=coverage))
    names = {p["name"] for p in cbom["metadata"]["properties"]}
    assert "ecd:coverage.files_skipped" in names
    assert "ecd:coverage.never_in_scope" in names


def test_documents_are_unique_but_structurally_stable():
    f = [dict(name="RSA", primitive="pke", key_length=2048)]
    a = json.loads(generate_cbom(f))
    b = json.loads(generate_cbom(f))
    assert a["components"][0]["cryptoProperties"] == b["components"][0]["cryptoProperties"]
    assert a["serialNumber"] != b["serialNumber"]
