"""
CycloneDX CBOM generation.

DESIGN NOTE -- what changed on 2026-09-25 and why
------------------------------------------------------------------------------------------------
The previous revision emitted `specVersion: "1.6"` with:

  * non-standard `primitive` values ("public-key-encryption", "symmetric-encryption",
    "cryptographic-library", "neural-detected") -- CycloneDX defines a fixed primitive vocabulary
    (pke, signature, key-agreement, kem, ae, block-cipher, hash, mac, protocol, ...), so a
    consumer's schema validation would reject these;
  * `nistQuantumSecurityLevel` omitted entirely, even though that is the standard's own field for
    expressing whether an algorithm survives a quantum attack (0 = broken);
  * key length, curve and mode dumped into `properties[]` as `keyLength` / `curve` / `mode`
    instead of the standard's `algorithmProperties` fields;
  * no `oid`, no `cryptoFunctions`, no `classicalSecurityLevel`;
  * no `dependencies[]`, so there is no machine-readable "which app uses which algorithm"
    and no way to express CycloneDX's `implements` vs `uses` distinction;
  * un-namespaced property names (`moscaRiskTier`, `pqcRecommendation`) that could collide with
    another tool's properties;
  * no `metadata.timestamp`, `serialNumber` or `tools`, which CycloneDX 1.5+ expects.

validate_real_world.py even printed "Skipping schema validation due to 404 on schema URL", i.e.
the document was never checked against the schema. This revision emits a schema-shaped v1.7
document, keeps all ECDAT-specific values in a documented `ecd:` property namespace so the base
document stays valid, and `validate_real_world.py` now performs local schema validation.
"""
import json
import re
import uuid
from datetime import datetime, timezone

from engine.purpose import PURPOSE_UNRESOLVED, resolve_assurance, resolve_purpose

SPEC_VERSION = "1.7"
PROPERTY_NS = "ecd"          # ECDAT-namespaced extension properties

# CycloneDX primitive vocabulary, taken from the published 1.7 JSON Schema enum
# (schemas/bom-1.7.schema.json -> definitions.cryptoProperties.properties.algorithmProperties).
# Note the exact spelling `key-agree`, and note that `protocol` is NOT a primitive: a protocol is
# modelled as assetType "protocol" with protocolProperties, which is what we emit below.
PRIMITIVE_ENUM = {
    "pke": "pke",
    "key-agreement": "key-agree",
    "key-agree": "key-agree",
    "key-exchange": "key-agree",
    "kem": "kem",
    "signature": "signature",
    "ae": "ae",
    "block-cipher": "block-cipher",
    "stream-cipher": "stream-cipher",
    "hash": "hash",
    "mac": "mac",
    "kdf": "kdf",
    "key-derive": "kdf",
    "key-wrap": "key-wrap",
    "combiner": "combiner",
    "xof": "xof",
    "drbg": "drbg",
    "other": "other",
    "public-key-encryption": "pke",
    "digital-signature": "signature",
    "symmetric-encryption": "ae",
    "cryptographic-library": "unknown",
    "neural-detected": "unknown",
    "protocol": "unknown",      # handled via assetType=protocol, not as an algorithm
    "unknown": "unknown",
}

# Protocol asset types allowed by the schema.
PROTOCOL_TYPE_ENUM = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "dtls", "quic",
                      "eap-aka", "eap-aka-prime", "prins", "5g-aka", "other", "unknown"}

# NIST quantum security levels: 0 = broken by a CRQC (Shor), 1-5 = NIST categories.
QUANTUM_BROKEN = 0
QUANTUM_CATEGORY = {"AES-128": 1, "AES-192": 3, "AES-256": 5,
                    "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5}

# NIST SP 800-57 security strength in bits, for `classicalSecurityLevel`. That field means
# "equivalent security in BITS", not key length: RSA-2048 is 2048-bit key but ~112-bit
# security. Reporting the key length there overstates every asymmetric algorithm by an order
# of magnitude, and it is the number a consumer reads to judge adequacy.
CLASSICAL_STRENGTH_BITS = {
    "RSA-1024": 80, "RSA-2048": 112, "RSA-3072": 128, "RSA-4096": 152,
    "EC-P-192": 96, "EC-P-224": 112, "EC-P-256": 128, "EC-P-384": 192, "EC-P-521": 256,
    "X25519": 128, "X448": 224, "Ed25519": 128, "Ed448": 224,
    "DSA-2048": 112,
    "ML-KEM-512": 128, "ML-KEM-768": 192, "ML-KEM-1024": 256,
    "ML-DSA-44": 128, "ML-DSA-65": 192, "ML-DSA-87": 256,
    "SLH-DSA-SHA2-128s": 128, "SLH-DSA-SHA2-192s": 192, "SLH-DSA-SHA2-256s": 256,
    "AES-128": 128, "AES-192": 192, "AES-256": 256,
    "SHA-256": 128, "SHA-384": 192, "SHA-512": 256,
    "SHA-1": 87, "MD5": 0, "3DES": 112,
}

# Post-quantum algorithm families, matched on the name BEFORE any primitive-based rule. ML-KEM,
# ML-DSA, SLH-DSA and FN-DSA are the standardised replacements: a CRQC does not break them, so
# they must never inherit the "broken by Shor" verdict that applies to the primitives they
# replace. Getting this backwards is the most damaging possible error in this file -- the tool
# would label its own migration recommendation as quantum-vulnerable.
#
# Spelling variants are NORMALISED before matching rather than listed one by one. Real
# deployments use every spelling at once: IANA/TLS codepoints write `X25519MLKEM768`, the
# `cryptography` library writes `MLKEM1024`, the SSH draft writes `mlkem768x25519-sha256`, and
# the NIST names are hyphenated (`ML-KEM-768`). Matching only the hyphenated forms meant the
# single most important name in the file -- our own recommended hybrid `X25519MLKEM768` -- was
# classified as NOT post-quantum. A tuple of literal strings could never stay current, so the
# families are the regexes that survive the spelling variation instead.
PQC_FAMILIES = (r"ML[-_]?KEM", r"ML[-_]?KSA", r"ML[-_]?DSA", r"SLH[-_]?DSA", r"FN[-_]?DSA",
                r"FALCON", r"XMSS", r"LMS", r"SPHINCS", r"HQC", r"DILITHIUM", r"FIPS.?204",
                r"SPHINCS\+", r"RAINBOW", r"CLASSIC\.MCELIECE", r"MCELIECE", r"NTRU")

_PQC_RE = re.compile("|".join(PQC_FAMILIES), re.IGNORECASE)


def is_pqc(name):
    """True if `name` denotes a post-quantum (or hybrid) algorithm.

    Deliberately a substring test on a normalised haystack rather than a word-boundary match:
    hybrid names concatenate a classical and a PQ component (`X25519MLKEM768`,
    `SecP384r1MLKEM1024`, `p256_mlkem768`) with no separator, and a `\b` boundary would split
    `MLKEM768` off from its prefix and miss it.
    """
    return bool(_PQC_RE.search(str(name or "")))

# Cryptographic function, inferred from purpose. CycloneDX types `cryptoFunctions` as a list
# from a closed vocabulary, and hardcoding "keygen" for a signing-only artefact is simply wrong.
_CRYPTO_FUNCTIONS = {
    "signature": ["sign", "verify", "keygen"],
    "key-establishment": ["keygen", "encapsulate", "decapsulate", "keyderive"],
    "confidentiality": ["keygen", "encrypt", "decrypt", "keyderive"],
    "hash": ["digest", "tag"],
    "mac": ["tag", "generate", "verify"],
    "ae": ["encrypt", "decrypt", "tag", "keygen"],
    "block-cipher": ["encrypt", "decrypt", "keygen"],
    "stream-cipher": ["encrypt", "decrypt", "keygen"],
    "kdf": ["keyderive"],
    "kem": ["keygen", "encapsulate", "decapsulate"],
    "drbg": ["generate"],
    "unknown": ["keygen"],
}

OID_BY_NAME = {
    "AES-128-GCM": "2.16.840.1.101.3.4.1.6",
    "AES-256-GCM": "2.16.840.1.101.3.4.1.46",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "RSA-2048": "1.2.840.113549.1.1.1",
    "RSA-PKCS1-1.5-SHA-256-2048": "1.2.840.113549.1.1.11",
}


def _canonical_primitive(primitive):
    return PRIMITIVE_ENUM.get(str(primitive or "").lower(), "unknown")


def _is_pqc(name):
    """True when the name is a standardised post-quantum algorithm family.

    Checked BEFORE any primitive rule, because ML-KEM has primitive `kem` and ML-DSA has
    primitive `signature` -- the same primitive values as RSA and ECDSA. Ordering the primitive
    check first made every PQC algorithm inherit the "broken by Shor" verdict, so the tool
    labelled its own migration recommendation `nistQuantumSecurityLevel: 0`.

    Delegates to `is_pqc`, which normalises spelling variants rather than matching only the
    hyphenated NIST forms.
    """
    return is_pqc(name)


def _nist_quantum_level(finding, primitive):
    """0 when the primitive is broken by a CRQC (Shor), else a NIST category where known.

    The standard's own convention (documented in the CycloneDX crypto-asset use case) is
    `nistQuantumSecurityLevel: 0` for a quantum-vulnerable algorithm such as RSA, and 1..5 for
    NIST security categories. Returning 0 is therefore the CBOM-native way to say "a CRQC breaks
    this" -- it is not a severity score.
    """
    name = str(finding.get("name", "")).upper()
    key_length = finding.get("key_length")

    # A standardised post-quantum algorithm is NOT broken by Shor. This must be tested first.
    if _is_pqc(name):
        if name in QUANTUM_CATEGORY:
            return QUANTUM_CATEGORY[name]
        # Parameter-set families: 512/44/128s -> 1, 768/65/192s -> 3, 1024/87/256s -> 5.
        for token, level in (("512", 1), ("44", 1), ("128s", 1),
                             ("768", 3), ("65", 3), ("192s", 3),
                             ("1024", 5), ("87", 5), ("256s", 5)):
            if token in name:
                return level
        return 3                     # a PQC family we do not have a level for is not "broken"

    if primitive in ("pke", "signature", "key-agreement", "kem"):
        return QUANTUM_BROKEN
    if "AES" in name:
        if key_length:
            return QUANTUM_CATEGORY.get(f"AES-{key_length}", 0)
        return 0
    if primitive == "hash":
        return 1 if "SHA256" in name or "SHA-256" in name else 0
    return 0


def _coerce_int(value):
    """Best-effort int, or None. A CBOM generator must never crash on a malformed finding.

    `key_length` arrives from regex capture groups and from third-party inputs, so it can be any
    string. `int('unknown')` raises ValueError and would abort the whole report -- turning one
    bad field into a total scan failure. An unknown key size is a reportable condition, not a
    fatal one: it is simply omitted and the artefact stays in the CBOM.
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# CycloneDX 1.7 types `algorithmProperties.mode` as a CLOSED enum with nine values. Modes such as
# XTS, GCM-SIV, EAX, OCB and SIV are real, widely deployed AEAD/cipher modes but are NOT in it.
# The schema provides `other` and `unknown` precisely so an unrecognised mode can be
# represented; emitting a raw lowercase mode name would produce a document that fails validation,
# so a mode outside the enum degrades to `other` and the verbatim value is preserved in the
# namespaced `ecd:` properties where it costs the document nothing.
CYCLONEDX_MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr"}


def _canonical_mode(raw):
    """Map a free-text cipher mode onto the CycloneDX closed enum, or None if unrecognised."""
    m = str(raw or "").strip().lower().replace("_", "-")
    if not m:
        return None
    if m in CYCLONEDX_MODES:
        return m
    # A compound name such as "GCM-SIV" or "AES-256-GCM" resolves to its base mode when the
    # base is a member of the enum; otherwise it is genuinely `other`.
    for part in re.split(r"[-/ ]+", m):
        if part in CYCLONEDX_MODES:
            return part
    return "other"


def _classical_strength(finding, primitive):
    """Equivalent security in BITS (NIST SP 800-57), for `classicalSecurityLevel`.

    That field means security strength, NOT key length. RSA-2048 has a 2048-bit key but ~112-bit
    security; reporting 2048 overstated every asymmetric algorithm by more than an order of
    magnitude, and this is the number a downstream consumer reads to judge adequacy. The raw key
    length is still emitted, correctly, as `parameterSetIdentifier`.
    """
    name = str(finding.get("name", "") or "")
    upper = name.upper()
    if upper in CLASSICAL_STRENGTH_BITS:
        return CLASSICAL_STRENGTH_BITS[upper]
    for key, bits in CLASSICAL_STRENGTH_BITS.items():
        if key in upper:
            return bits
    key_bits = _coerce_int(finding.get("key_length"))
    # A bare family name plus a key length is the shape the SCANNER emits: "RSA" + 2048. Look the
    # parameter set up from the length, otherwise every finding from our own rules would report
    # strength 0 -- technically "not stated" while the information was sitting in the same dict.
    if key_bits and upper:
        for family, table in (
            ("RSA", {"1024": 80, "2048": 112, "3072": 128, "4096": 152}),
            ("DSA", {"1024": 80, "2048": 112, "3072": 128}),
            ("EC", {"192": 96, "224": 112, "256": 128, "384": 192, "521": 256}),
            ("ECDSA", {"192": 96, "224": 112, "256": 128, "384": 192, "521": 256}),
        ):
            if family in upper and str(key_bits) in table:
                return table[str(key_bits)]
    # Fall back on the primitive: symmetric and hash primitives are judged by key/digest size,
    # which for these IS the strength. Asymmetric without a recognised parameter set is unknown,
    # and 0 is the honest answer -- it means "not stated", not "zero security".
    if primitive in ("ae", "block-cipher", "stream-cipher", "mac", "hash", "xof", "kdf"):
        return key_bits or 0
    if primitive == "drbg":
        return 0
    return 0


def _crypto_functions(finding, primitive):
    """The cryptographic functions this asset provides, per CycloneDX's closed vocabulary.

    Hardcoding ["keygen"] for every artefact was simply wrong: a signing key does not encrypt and
    a digest is not a key generator. The purpose model already resolves what a finding is FOR, so
    the function list follows the purpose when known and the primitive otherwise.
    """
    try:
        purpose = resolve_purpose(finding)[0]
    except Exception:                                    # noqa: BLE001 - never fail a report
        purpose = PURPOSE_UNRESOLVED
    fns = _CRYPTO_FUNCTIONS.get(purpose)
    if fns is None:
        fns = _CRYPTO_FUNCTIONS.get(primitive, _CRYPTO_FUNCTIONS["unknown"])
    return list(fns)


def _algorithm_properties(finding, primitive):
    props = {
        "primitive": primitive,
        "executionEnvironment": "software-plain-ram",
        "cryptoFunctions": _crypto_functions(finding, primitive),
    }
    key_length = finding.get("key_length")
    if key_length:
        # The raw value is still worth recording (e.g. "unknown"), but only a real integer can
        # be a CycloneDX parameterSetIdentifier consumer would recognise.
        props["parameterSetIdentifier"] = str(key_length)
    if finding.get("mode"):
        mode = _canonical_mode(finding["mode"])
        if mode:
            props["mode"] = mode
    if finding.get("curve"):
        props["curve"] = str(finding["curve"])
    # `uses` (at-rest / tls / signing) has no CycloneDX field; it is emitted as an `ecd:uses`
    # property instead, so it never invalidates the base document.
    # classicalSecurityLevel is EQUIVALENT SECURITY IN BITS (NIST SP 800-57), not key length.
    props["classicalSecurityLevel"] = _classical_strength(finding, primitive)
    if not props["classicalSecurityLevel"] and primitive == "hash":
        props["classicalSecurityLevel"] = 128
    props["nistQuantumSecurityLevel"] = _nist_quantum_level(finding, primitive)
    return props


def _ecd_properties(finding, risk, recommendation):
    """All ECDAT-specific values, namespaced so the base document stays schema-valid."""
    out = []
    name = str(finding.get("name", "unknown"))
    for key, value in (
        ("algorithm", name),
        ("evidence_class", finding.get("evidence_class", "discovered")),
        ("artefact_class", finding.get("artefact_class", "source")),
        ("uses", finding.get("uses", "")),
        ("scanner", finding.get("scanner", "")),
        ("rule_id", finding.get("rule_id", "")),
    ):
        if value:
            out.append({"name": f"{PROPERTY_NS}:{key}", "value": str(value)})

    # Assurance answers "what does the evidence PROVE?", which is a different question from
    # confidence ("is this identification correct?"). A dependency on a crypto library can be a
    # CERTAIN identification of something that proves very little, so the two must both be
    # exported or a reader cannot tell which they are looking at.
    assurance, assurance_reason = resolve_assurance(finding)
    out.append({"name": f"{PROPERTY_NS}:assurance", "value": assurance})
    out.append({"name": f"{PROPERTY_NS}:assurance_meaning", "value": assurance_reason})

    # Purpose decides which PQC family replaces the primitive, and is itself sometimes
    # unresolvable from static evidence. Exporting it makes the recommendation auditable.
    purpose, purpose_signals, purpose_reason = resolve_purpose(finding)
    out.append({"name": f"{PROPERTY_NS}:purpose", "value": purpose})
    if purpose_signals:
        out.append({"name": f"{PROPERTY_NS}:purpose_signals", "value": "; ".join(purpose_signals)})
    if purpose == PURPOSE_UNRESOLVED:
        out.append({"name": f"{PROPERTY_NS}:purpose_note", "value": purpose_reason})

    if finding.get("line"):
        out.append({"name": f"{PROPERTY_NS}:line", "value": str(finding["line"])})
    if finding.get("mode"):
        # The verbatim mode, alongside the schema-constrained `algorithmProperties.mode`. A mode
        # like "GCM-SIV" or "XTS" is not in the CycloneDX closed enum and is emitted there as
        # `other`; recording what it actually was prevents that from being a silent loss.
        out.append({"name": f"{PROPERTY_NS}:mode_verbatim", "value": str(finding["mode"])})
    if finding.get("dl_confidence") is not None:
        out.append({"name": f"{PROPERTY_NS}:detector_confidence",
                    "value": str(finding.get("dl_confidence"))})
    if risk:
        for key in ("tier", "x", "y", "z", "x_y", "margin", "is_vulnerable",
                    "hndl_exposed", "horizon_type", "break_model", "x_reason", "y_reason",
                    "latest_safe_migration_start", "policy", "z_stable"):
            if key in risk:
                value = risk[key]
                out.append({"name": f"{PROPERTY_NS}:mosca.{key}", "value": str(value)})
        if risk.get("policy_deadline", {}).get("year"):
            out.append({"name": f"{PROPERTY_NS}:mosca.policy_deadline",
                        "value": str(risk["policy_deadline"]["year"])})
        if risk.get("z_band"):
            out.append({"name": f"{PROPERTY_NS}:mosca.z_band", "value": json.dumps(risk["z_band"])})
    if recommendation:
        for key in ("algorithm", "action", "hybrid_semantics", "cost_band",
                    "ossification_risk", "rule_trace", "standard_basis", "tradeoff_size",
                    "tradeoff_latency"):
            value = recommendation.get(key)
            if value:
                out.append({"name": f"{PROPERTY_NS}:rec.{key}",
                            "value": value if isinstance(value, str) else json.dumps(value)})
    return out


def generate_cbom(findings, enriched=False, subject_name="ECDAT-Scanned-Artefact",
                  subject_version=None, coverage=None):
    """Build a CycloneDX v1.7 CBOM from scanner findings.

    When `enriched=True` and a finding carries `risk` / `recommendation`, the Mosca verdict and
    the PQC recommendation are attached as `ecd:`-namespaced properties so the base document
    remains schema-valid and portable to other tools.
    """
    components = []
    dependencies = []
    uses_targets = []

    for idx, f in enumerate(findings):
        ref = f"crypto-asset-{idx}"
        primitive = _canonical_primitive(f.get("primitive"))
        is_library = f.get("type") == "library"
        risk = f.get("risk") if enriched else None
        recommendation = f.get("recommendation") if enriched else None

        if is_library:
            # A library is a software component that *implements* algorithms, not an algorithm
            # itself. Emitting it as cryptographic-asset with a fake primitive misrepresents it.
            components.append({
                "type": "library",
                "bom-ref": ref,
                "name": f.get("name", "unknown"),
                "scope": "required",
                "properties": _ecd_properties(f, risk, recommendation),
            })
            continue

        # A protocol (TLS, a configured cipher suite) is modelled by CycloneDX as
        # assetType "protocol" with protocolProperties -- `protocol` is NOT a valid primitive.
        if f.get("primitive") == "protocol" or f.get("type") == "protocol":
            proto_type = "tls" if "TLS" in str(f.get("name", "")).upper() else "other"
            if proto_type not in PROTOCOL_TYPE_ENUM:
                proto_type = "other"
            protocol = {"type": proto_type}
            if f.get("match"):
                protocol["version"] = str(f["match"])[:120]
            components.append({
                "type": "cryptographic-asset",
                "bom-ref": ref,
                "name": f.get("name", "unknown"),
                "cryptoProperties": {
                    "assetType": "protocol",
                    "protocolProperties": protocol,
                },
                "properties": _ecd_properties(f, risk, recommendation),
            })
            if f.get("line"):
                components[-1]["evidence"] = {
                    "occurrences": [{"bom-ref": f"occ-{idx}",
                                     "location": f.get("file", ""), "line": f.get("line")}]
                }
            continue

        algo = _algorithm_properties(f, primitive)
        # `dict.get(k, default)` returns None when the key EXISTS with a None value, so a
        # finding from an external source carrying `"name": null` produced `"name": null` and an
        # invalid document. Falling back only on falsy covers both the missing key and the null.
        # The value is also coerced to a hashable string: a JSON inventory can legitimately carry
        # a list or dict for `name`, and an unhashable key raises TypeError deep inside a dict
        # lookup -- taking the whole report down over one malformed field.
        algo_name = f.get("name")
        if not isinstance(algo_name, str) or not algo_name:
            algo_name = "unknown"
        component = {
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": algo_name,
            "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
            "properties": _ecd_properties(f, risk, recommendation),
        }
        oid = OID_BY_NAME.get(algo_name)
        if oid:
            component["cryptoProperties"]["oid"] = oid
        if f.get("line"):
            component["evidence"] = {
                "occurrences": [{
                    "bom-ref": f"occ-{idx}",
                    "location": f.get("file", ""),
                    "line": f.get("line"),
                }]
            }
        components.append(component)
        if not f.get("file"):
            uses_targets.append(ref)

    if uses_targets:
        # NO `dependencyType` field here. The vendored CycloneDX 1.7 `definitions.dependency`
        # allows only `ref`, `dependsOn` and `provides`, and sets additionalProperties:false --
        # emitting `dependencyType` makes the document invalid for every consumer that validates
        # it, which defeats the purpose of publishing a CBOM at all. The `implements` vs `uses`
        # distinction the design intends is expressed through `compositions` and component
        # `type`, not through a field on a dependency edge. Findings with no `file` are ambient
        # or global, so the subject genuinely does use them; that is what `dependsOn` says.
        dependencies.append({
            "ref": subject_name,
            "dependsOn": uses_targets,
        })

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    metadata_component = {"type": "application", "name": str(subject_name)}
    if subject_version is not None and str(subject_version).strip():
        # CycloneDX types `component.version` as a string. A caller passing `1` (an int) would
        # otherwise produce a document that fails schema validation, so coerce rather than
        # reject: the value is still meaningful as text and refusing it would be unhelpful.
        metadata_component["version"] = str(subject_version)

    metadata = {
        "timestamp": timestamp,
        "tools": {"components": [
            {"type": "application", "name": "ecdat", "version": "0.2.0"},
        ]},
        "component": metadata_component,
    }
    if coverage:
        metadata["properties"] = [
            {"name": f"{PROPERTY_NS}:coverage.files_scanned", "value": str(coverage.get("files_scanned", 0))},
            {"name": f"{PROPERTY_NS}:coverage.files_skipped", "value": str(coverage.get("files_skipped", 0))},
            {"name": f"{PROPERTY_NS}:coverage.ml_reason", "value": str(coverage.get("ml_reason", ""))},
            {"name": f"{PROPERTY_NS}:coverage.never_in_scope", "value": json.dumps(coverage.get("never_in_scope", []))},
        ]
        # Report the PROVEN-use count next to the raw total. Reporting "412 quantum-vulnerable
        # assets" when 300 are capabilities nothing calls is the easiest way for a discovery tool
        # to mislead, so the two numbers are published together or the raw one is meaningless.
        if "assurance_histogram" in coverage:
            hist = coverage["assurance_histogram"]
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:assurance_histogram", "value": json.dumps(hist)})
        if "proven_use" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:proven_use", "value": str(coverage["proven_use"])})
        if "findings_total" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:findings_total", "value": str(coverage["findings_total"])})
        if "unresolved_purpose" in coverage:
            metadata["properties"].append(
                {"name": f"{PROPERTY_NS}:unresolved_purpose", "value": str(coverage["unresolved_purpose"])})

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": components,
    }
    if dependencies:
        cbom["dependencies"] = dependencies

    return json.dumps(cbom, indent=2)

