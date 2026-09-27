"""
Mosca's inequality:  X + Y > Z  =>  migration should already have started.

    X = years the data (or the signed artefact) must remain protected
    Y = years required to migrate this artefact
    Z = years until a Cryptographically Relevant Quantum Computer (CRQC) exists

Source: M. Mosca, "Cybersecurity in an Era with Quantum Computers: Will We Be Ready?",
IACR ePrint 2015/1075; IEEE Security & Privacy 16(5), 2018.

------------------------------------------------------------------------------------------------
DESIGN NOTE -- why X and Y are NOT derived from model confidence (fixed 2026-09-25)
------------------------------------------------------------------------------------------------
An earlier revision of this module computed:

    X = 3.0 + (dl_confidence * 5.0)      # <- NOT DEFENSIBLE
    Y = 1.0 + (ast_depth / 10.0) * 0.5

X is a *business/compliance* property of the DATA (how long must this remain secret, or how long
must this signature remain trustworthy?). It is not a property of how confident the detector is
that it found an algorithm. Deriving X from `dl_confidence` had three consequences:

  1. No evidential basis. No published correlation exists between detector confidence and
     data-retention obligations, so the tool could not answer "where does X come from?".
  2. The risk tier depended on the neural network's confidence, so every model retrain silently
     re-rated the estate. Risk verdicts must be reproducible.
  3. It bypassed the brief's requirement to classify artefacts by "type, lifetime and business
     criticality" -- the lifetime input was replaced by a proxy.

X and Y now come from explicit, documented, overridable tables below. The ML complexity signal is
retained, but only as a BOUNDED, clearly-labelled adjustment to Y -- never as X.
------------------------------------------------------------------------------------------------
"""

# ---------------------------------------------------------------------------------------------
# Horizon semantics: which clock does X measure for a given primitive?
# ---------------------------------------------------------------------------------------------
HORIZON_CONFIDENTIALITY = "confidentiality"   # data must stay secret -> HNDL applies
HORIZON_VERIFIABILITY = "verifiability"       # signature must stay trustworthy -> no HNDL
HORIZON_NONE = "none"                          # symmetric/hash -> inequality does not apply

PRIMITIVE_HORIZON = {
    "public-key-encryption": HORIZON_CONFIDENTIALITY,
    "pke": HORIZON_CONFIDENTIALITY,
    "key-agreement": HORIZON_CONFIDENTIALITY,
    "kem": HORIZON_CONFIDENTIALITY,
    "key-transport": HORIZON_CONFIDENTIALITY,
    "digital-signature": HORIZON_VERIFIABILITY,
    "signature": HORIZON_VERIFIABILITY,
    "symmetric-encryption": HORIZON_NONE,
    "ae": HORIZON_NONE,
    "block-cipher": HORIZON_NONE,
    "hash": HORIZON_NONE,
    "mac": HORIZON_NONE,
    "cryptographic-library": HORIZON_NONE,
}

# ---------------------------------------------------------------------------------------------
# Z -- the CRQC planning horizon, in YEARS from "now".
# Deliberately NOT a compliance deadline (India DST CII 2029, NIST IR 8547 deprecate-2030 /
# disallow-2035, CNSA 2.0 2030/2033). Those are procurement dates reported separately.
# Basis: GRI/evolutionQ "Quantum Threat Timeline" (7th ed., Mar 2026) -- expert consensus
# window 10-20 years, with 28-49% probability of a CRQC within 10 years.
# ---------------------------------------------------------------------------------------------
Z_PRESETS = {
    "aggressive":   {"years": 5,  "label": "Z=5y  (plan-as-if-early; ~2031)",
                     "basis": "Lower bound of the expert-consensus window."},
    "gri_midpoint": {"years": 10, "label": "Z=10y (GRI 2026 midpoint; ~2036)",
                     "basis": "Midpoint of the GRI/evolutionQ 10-20 year consensus window."},
    "conservative": {"years": 15, "label": "Z=15y (upper bound; ~2041)",
                     "basis": "Upper bound of the expert-consensus window."},
}
DEFAULT_Z = Z_PRESETS["gri_midpoint"]["years"]
Z_SENSITIVITY_YEARS = (5, 10, 15)   # band reported alongside every verdict

POLICY_DEADLINES = {
    "india_dst_nqm": {"label": "India DST / National Quantum Mission (CII migration)", "year": 2029},
    "nist_ir_8547":  {"label": "NIST IR 8547 -- quantum-vulnerable PKC disallowed",    "year": 2035},
    "cnsa_2_0":      {"label": "CNSA 2.0 -- exclusive use across NSS",                  "year": 2033},
}
DEFAULT_POLICY = "india_dst_nqm"

# ---------------------------------------------------------------------------------------------
# X -- required protection lifetime, in years, by data class. Overridable per artefact or scan.
# Brackets derive from the regulatory retention regimes behind the published Mosca worked
# examples (HIPAA, statutory financial retention, classification schedules, device support life).
# ---------------------------------------------------------------------------------------------
DATA_CLASS_LIFETIME = {
    "session":             {"years": 2,  "note": "ephemeral session / traffic keys"},
    "internal-credential": {"years": 5,  "note": "short-lived internal service credential"},
    "operational-record":  {"years": 7,  "note": "typical operational / audit retention"},
    "financial-record":    {"years": 12, "note": "regulatory financial retention + loan lifecycle"},
    "personal-data":       {"years": 12, "note": "regulated personal data retention"},
    "ip-source-code":      {"years": 20, "note": "intellectual property / trade-secret horizon"},
    "code-signing":        {"years": 25, "note": "verifiability across a device support life"},
    "defence-classified":  {"years": 25, "note": "classification schedules"},
    "statutory-archive":   {"years": 30, "note": "long statutory record retention"},
    "health-record":       {"years": 50, "note": "patient lifetime + heirs"},
}
DEFAULT_DATA_CLASS = "operational-record"

# ---------------------------------------------------------------------------------------------
# Y -- migration duration, in years, by artefact class. Documented, editable assumptions.
# ---------------------------------------------------------------------------------------------
MIGRATION_EFFORT = {
    "config":   {"years": 1, "note": "configuration change + regression test"},
    "protocol": {"years": 2, "note": "protocol/stack upgrade, peer coordination"},
    "source":   {"years": 3, "note": "application code change + release cycle"},
    "library":  {"years": 4, "note": "third-party / vendored dependency upgrade"},
    "hsm-tpm":  {"years": 6, "note": "HSM firmware + validation + key ceremony"},
    "firmware": {"years": 7, "note": "firmware / hardware refresh cycle"},
    "ca-root":  {"years": 8, "note": "root/CA rollover: trust distribution lag"},
}
DEFAULT_ARTEFACT_CLASS = "source"

# Bounded complexity adjustment derived from the ML/AST signal. Kept because structural
# complexity genuinely does correlate with migration effort -- but capped, and always reported
# in the output so the number is auditable.
COMPLEXITY_ADJUSTMENT_MAX_YEARS = 1.5
COMPLEXITY_AST_DEPTH_REFERENCE = 30.0

SHOR_VULNERABLE = ("RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH", "DIFFIE", "ELGAMAL",
                   "X25519", "ED25519", "CURVE25519")
GROVER_WEAKENED = ("AES", "SHA", "MD5", "3DES", "DES", "BLOWFISH", "CHACHA", "RC4")

# Reused rather than re-declared: the family vocabulary is the thing most likely to drift, and
# two copies is how `X25519MLKEM768` ends up Shor-broken in one module and PQC in another.
from .cbom import is_pqc  # noqa: E402  (circular-import guard; cbom imports nothing from mosca)


def quantum_break_model(name, primitive=""):
    """Return 'broken-by-Shor' | 'weakened-by-Grover' | 'not-affected'.

    Shor  => the primitive is dead, and data captured TODAY is retroactively readable (HNDL).
    Grover => quadratic speedup only, and NOT retroactive: ciphertext recorded today cannot be
              recovered faster later merely because Grover exists. This is exactly why the
              Mosca inequality must not be applied to symmetric primitives -- doing so is a
              category error that would flag every AES-256 user as exposed.
    """
    # A post-quantum algorithm is checked FIRST, and that ordering is load-bearing. `X25519MLKEM768`
    # is a hybrid: it contains "X25519", which is in the Shor table, so a token scan that reaches
    # the table before the PQC screen calls our own top migration recommendation Shor-broken.
    # The same inversion mislabelled `ML-DSA-65`, because "DSA" is a substring of "ML-DSA".
    if is_pqc(name):
        return "not-affected"
    haystack = f"{name} {primitive}".upper()
    for token in SHOR_VULNERABLE:
        if token in haystack:
            return "broken-by-Shor"
    for token in GROVER_WEAKENED:
        if token in haystack:
            return "weakened-by-Grover"
    return "not-affected"


def _horizon_type(finding, break_model):
    """Which X applies: confidentiality, verifiability, or none."""
    if break_model != "broken-by-Shor":
        return HORIZON_NONE
    primitive = str(finding.get("primitive", "")).lower()
    if primitive in PRIMITIVE_HORIZON:
        return PRIMITIVE_HORIZON[primitive]
    if "sign" in primitive:
        return HORIZON_VERIFIABILITY
    if str(finding.get("mode", "")).lower() == "signing":
        return HORIZON_VERIFIABILITY
    return HORIZON_CONFIDENTIALITY


def _resolve_x(finding, horizon, user_x):
    """X in years, plus the reason. Never derived from detection confidence."""
    if user_x is not None:
        if user_x < 0:
            raise ValueError("Data Shelf Life (X) cannot be negative.")
        return float(user_x), "explicit override"
    if horizon == HORIZON_NONE:
        return 0.0, "not applicable (symmetric/hash primitive)"
    data_class = finding.get("data_class", DEFAULT_DATA_CLASS)
    entry = DATA_CLASS_LIFETIME.get(data_class, DATA_CLASS_LIFETIME[DEFAULT_DATA_CLASS])
    return float(entry["years"]), f"data_class='{data_class}': {entry['note']}"


def _resolve_y(finding, user_y):
    """Y in years from an artefact-class table plus a bounded, reported complexity adjustment."""
    if user_y is not None:
        if user_y < 0:
            raise ValueError("Migration Time (Y) cannot be negative.")
        return float(user_y), 0.0, "explicit override"

    artefact_class = finding.get("artefact_class", DEFAULT_ARTEFACT_CLASS)
    entry = MIGRATION_EFFORT.get(artefact_class, MIGRATION_EFFORT[DEFAULT_ARTEFACT_CLASS])
    base = float(entry["years"])

    ast_depth = max(0.0, float(finding.get("ast_depth", 0.0) or 0.0))
    if ast_depth <= 0:
        adjustment = 0.0
    else:
        ratio = min(1.0, ast_depth / COMPLEXITY_AST_DEPTH_REFERENCE)
        adjustment = round(ratio * COMPLEXITY_ADJUSTMENT_MAX_YEARS, 2)

    reason = f"artefact_class='{artefact_class}': {entry['note']}"
    if adjustment:
        reason += f"; +{adjustment}y complexity adjustment (AST depth {ast_depth:.0f})"
    return base, adjustment, reason


def _grover_effective_bits(name, key_length):
    """Post-Grover effective strength in bits, or None when it cannot be determined."""
    upper = str(name).upper()
    if "AES" in upper:
        return int(key_length) // 2 if key_length else None
    if "3DES" in upper:
        return 56   # 112-bit classical -> ~56 after Grover
    if "DES" in upper:
        return 28
    if "MD5" in upper:
        return 32
    if "SHA1" in upper or "SHA-1" in upper:
        return 40
    if "SHA" in upper:
        return int(key_length) // 2 if key_length else 128   # SHA-256 pre-image ~128
    return None


def _tier(break_model, subject, is_vulnerable, hndl, margin, effective_bits):
    """Tier from the inequality outcome and exposure type -- not from the algorithm family."""
    if break_model == "broken-by-Shor":
        if not subject:
            return "LOW"
        if hndl or (is_vulnerable and margin >= 10):
            return "CRITICAL"
        if is_vulnerable:
            return "HIGH"
        return "MEDIUM"           # not yet exposed per the inequality
    if break_model == "weakened-by-Grover":
        if effective_bits is None:
            return "MEDIUM"       # unknown key size -> needs confirmation, not a blind upgrade
        return "LOW" if effective_bits >= 128 else "MEDIUM"
    return "LOW"


def calculate_risk(finding, user_x=None, user_y=None, z_collapse_time=None,
                   policy=None, current_year=None, include_z_band=True):
    """Apply Mosca's inequality (X + Y > Z) to one finding.

    Returns a dict with the verdict plus every input and reason used to reach it, so the GUI
    and the CBOM can explain the number instead of asserting it.
    """
    import datetime

    if current_year is None:
        current_year = datetime.date.today().year
    z_years = float(DEFAULT_Z if z_collapse_time is None else z_collapse_time)
    if z_years < 0:
        raise ValueError("Z (years to CRQC) cannot be negative.")
    policy = policy or DEFAULT_POLICY

    name = str(finding.get("name", ""))
    primitive = str(finding.get("primitive", ""))
    key_length = finding.get("key_length")

    break_model = quantum_break_model(name, primitive)
    horizon = _horizon_type(finding, break_model)
    subject = break_model == "broken-by-Shor" and horizon != HORIZON_NONE

    x_years, x_reason = _resolve_x(finding, horizon, user_x)
    y_base, y_adjust, y_reason = _resolve_y(finding, user_y)
    y_years = y_base + y_adjust

    # Round to a precision far finer than any real input BEFORE comparing, because the verdict
    # and the displayed numbers must not disagree. In binary floating point 0.1 + 21.1 is
    # 21.200000000000003, which is > 21.2, so the tool would print "x_y: 21.2" next to "z: 21.2"
    # and still claim RISK. A reader who checks the arithmetic loses trust in every other number
    # in the report -- the most damaging way this tool could fail, and precisely the
    # self-contradiction we criticise competitors for.
    #
    # 1e-9 years is ~30 microseconds. No meaningful input differs at that scale, so quantising
    # cannot change a real verdict; it only removes representation noise.
    PRECISION = 9
    total = round(x_years + y_years, PRECISION)
    z_cmp = round(float(z_years), PRECISION)
    x_cmp = round(float(x_years), PRECISION)
    margin = round(total - z_cmp, 2)
    is_vulnerable = bool(subject and total > z_cmp)
    hndl_exposed = bool(subject and horizon == HORIZON_CONFIDENTIALITY and x_cmp > z_cmp)
    effective_bits = _grover_effective_bits(name, key_length)

    tier = _tier(break_model, subject, is_vulnerable, hndl_exposed, margin, effective_bits)

    # Z-sensitivity: the verdict must be shown as a band, not a single number, because Z is
    # an estimate. If the tier flips inside the band, say so rather than asserting one answer.
    z_band = {}
    if include_z_band:
        for z in Z_SENSITIVITY_YEARS:
            m = round(total - z, 2)
            vuln = bool(subject and total > z)
            hndl = bool(subject and horizon == HORIZON_CONFIDENTIALITY and x_years > z)
            z_band[f"Z={z}"] = _tier(break_model, subject, vuln, hndl, m, effective_bits)
    stable = len(set(z_band.values())) <= 1 if z_band else True

    if break_model == "broken-by-Shor":
        threat = "Shor's algorithm (full break)"
    elif break_model == "weakened-by-Grover":
        threat = "Grover's algorithm (quadratic speed-up only; not retroactive)"
    else:
        threat = "No quantum break model applies"

    return {
        # --- Mosca inputs, each with the reason it holds that value ---
        "x": round(x_years, 2),
        "y": round(y_years, 2),
        "y_base": round(y_base, 2),
        "y_complexity_adjustment": round(y_adjust, 2),
        "z": z_years,
        "x_y": round(total, 2),
        "margin": margin,
        "latest_safe_migration_start": int(current_year + z_years - y_years),
        # --- verdict ---
        "is_vulnerable": is_vulnerable,
        "subject_to_inequality": subject,
        "hndl_exposed": hndl_exposed,
        "horizon_type": horizon,
        "break_model": break_model,
        "grover_effective_bits": effective_bits,
        "tier": tier,
        "threat": threat,
        "z_band": z_band,
        "z_stable": stable,
        # --- audit trail ---
        "policy": policy,
        "policy_deadline": POLICY_DEADLINES.get(policy, {}),
        "x_reason": x_reason,
        "y_reason": y_reason,
        "assumptions": [
            f"X={round(x_years, 2)}y from {x_reason}",
            f"Y={round(y_years, 2)}y from {y_reason}",
            f"Z={z_years}y is a CRQC estimate, not a compliance deadline "
            f"(policy deadline: {POLICY_DEADLINES.get(policy, {}).get('year', 'n/a')})",
        ],
        # --- retained ML diagnostics (reported, never used to derive X) ---
        "dl_confidence": round(max(0.0, min(1.0, float(finding.get("dl_confidence", 0.5) or 0.5))), 4),
        "ast_depth": round(max(0.0, float(finding.get("ast_depth", 0.0) or 0.0)), 2),
    }

