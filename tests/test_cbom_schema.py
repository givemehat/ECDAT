"""Schema conformance test.

This is the test that the original suite lacked. validate_real_world.py printed "Skipping schema
validation due to 404 on schema URL", so the CBOM was never checked against the standard. These
tests validate against the real, published CycloneDX 1.7 JSON Schema (cached in schemas/), and
skip loudly -- never silently -- if the schema is absent.
"""
import json
import os

import pytest

from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom

SCHEMA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "schemas", "bom-1.7.schema.json")

jsonschema = pytest.importorskip("jsonschema")

SNIPPETS = {
    "app.py": ("from cryptography.hazmat.primitives.asymmetric import rsa\n"
               "from cryptography.hazmat.primitives.asymmetric import ec\n"
               "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
               "k = rsa.generate_private_key(65537, 2048)\n"
               "p = ec.generate_private_key(ec.SECP256R1())\n"
               "a = AESGCM(AESGCM.generate_key(bit_length=256))\n"),
    "legacy.conf": "ssl_protocols TLSv1.2;\nssl_ciphers RC4-SHA:DES-CBC3-SHA;\n",
    "sig.java": ('Signature.getInstance("SHA256withECDSA");\n'
                 'KeyPairGenerator.getInstance("RSA");\n'),
}


def _build(tmp_path):
    for name, text in SNIPPETS.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    (tmp_path / "libcrypto.so").write_bytes(
        b"\x7fELF" + b"\x00" * 8 + b"OpenSSL 3.0.13 libcrypto\x00")
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(tmp_path))
    for f in findings:
        f["risk"] = calculate_risk(f)
        f["recommendation"] = get_pqc_recommendation(f)
    return scanner, findings


@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="CycloneDX 1.7 schema not vendored")
def test_emitted_cbom_validates_against_published_schema(tmp_path):
    scanner, findings = _build(tmp_path)
    document = json.loads(generate_cbom(findings, enriched=True, subject_name="schema-target",
                                        coverage=scanner.coverage_manifest()))
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    errors = sorted(jsonschema.Draft7Validator(schema).iter_errors(document),
                    key=lambda e: list(e.absolute_path))
    assert not errors, "\n".join(
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}" for e in errors[:10])


@pytest.mark.skipif(not os.path.exists(SCHEMA), reason="CycloneDX 1.7 schema not vendored")
def test_empty_cbom_also_validates(tmp_path):
    document = json.loads(generate_cbom([], enriched=True))
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    jsonschema.Draft7Validator(schema).validate(document)


def test_primitive_enum_comes_from_the_schema_not_guesswork():
    """`key-agree` is the schema's spelling, not `key-agreement`. This test fails if the schema is
    present and our mapping disagrees with it."""
    if not os.path.exists(SCHEMA):
        pytest.skip("schema not vendored")
    from engine.cbom import PRIMITIVE_ENUM
    with open(SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    allowed = set(schema["definitions"]["cryptoProperties"]["properties"]
                  ["algorithmProperties"]["properties"]["primitive"]["enum"])
    emitted = {v for v in PRIMITIVE_ENUM.values() if v != "unknown"}
    assert emitted <= allowed, f"primitives not in the schema enum: {emitted - allowed}"


def test_protocol_findings_use_assetType_protocol():
    """`protocol` is not a valid primitive; protocols are assetType=protocol."""
    doc = json.loads(generate_cbom([dict(name="TLS", primitive="protocol", file="a.conf", line=1)]))
    comp = doc["components"][0]
    assert comp["cryptoProperties"]["assetType"] == "protocol"
    assert "protocolProperties" in comp["cryptoProperties"]
    assert comp["cryptoProperties"]["protocolProperties"]["type"] in (
        "tls", "ssh", "ipsec", "other", "unknown")
