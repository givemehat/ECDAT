"""Presentation-neutral helpers for the ECDAT console (`app.py`).

WHY THIS FILE EXISTS
--------------------
The console has one job a plot library cannot do: state what the scan did *not* prove. The
analysis engine already computes that (`coverage_manifest`, `assurance_histogram`,
`proven_use_count`, `unresolved_purpose_count`); this module turns those values into things a
reader can check -- counts that are always shown next to each other, inline SVG that needs no
network, and a CBOM validation result that is displayed before a download is offered.

Two deliberate constraints:

*   NO STREAMLIT, NO NETWORK. Everything here is a pure function over dicts, so the module is
    importable and testable without a running server, and it cannot accidentally reach for a
    CDN. Charts are hand-built inline SVG; fill colours are paired with an automatically chosen
    text colour (`ink_on`) so the same markup stays legible in the light AND the dark theme.
*   NO BARE TOTALS. `findings_total` is never returned on its own anywhere in this module. The
    raw count mixes proven call sites with capabilities nothing calls, so every number is
    returned alongside the numbers that qualify it.
"""
import functools
import html
import json
import os

from engine.mosca import POLICY_DEADLINES
from engine.purpose import (ASSURANCE_CAPABILITY, ASSURANCE_DECLARED, ASSURANCE_OBSERVED,
                            ASSURANCE_RANK, ASSURANCE_USED, PURPOSE_UNRESOLVED,
                            needs_pqc_target, resolve_assurance, resolve_purpose)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_SCHEMA_PATH = os.path.join(REPO_ROOT, "schemas", "bom-1.7.schema.json")

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNRATED"]

# Dark, desaturated tones. Each is used as a FILL with the text colour chosen by `ink_on`, never
# as a text colour on the page background: a dark fill would vanish on a dark theme, so the
# label is always carried by text as well as by colour.
TIER_COLOURS = {
    "CRITICAL": "#8C1D18",
    "HIGH": "#9A4A06",
    "MEDIUM": "#7A5C00",
    "LOW": "#1F5C3A",
    "UNRATED": "#3D4756",
}

ASSURANCE_ORDER = [ASSURANCE_OBSERVED, ASSURANCE_USED, ASSURANCE_DECLARED, ASSURANCE_CAPABILITY]
ASSURANCE_COLOURS = {
    ASSURANCE_OBSERVED: "#14532D",
    ASSURANCE_USED: "#1F5C3A",
    ASSURANCE_DECLARED: "#7A5C00",
    ASSURANCE_CAPABILITY: "#3D4756",
}

# What each policy deadline actually requires, and where that claim is sourced inside this
# repository. Nothing here is invented at the UI layer: the wording is the engine's own
# (engine/mosca.py POLICY_DEADLINES and the standard notes in engine/recommender.py).
POLICY_NOTES = {
    "india_dst_nqm": {
        "requirement": "Cryptographic Invention Interface (CII) migration target named by the "
                       "National Quantum Mission.",
        "source": "engine/mosca.py POLICY_DEADLINES (comment: 'India DST CII 2029')",
    },
    "nist_ir_8547": {
        "requirement": "DRAFT. Quantum-vulnerable public-key algorithms at >= 128-bit strength "
                       "are disallowed after 2035. The 112-bit tier is deprecated after 2030 "
                       "and remains usable during migration, not disallowed.",
        "source": "NIST IR 8547 ipd transition tables; research/sources/04-nist-ir-8547-transition.md",
    },
    "cnsa_2_0": {
        "requirement": "Exclusive use of ML-KEM-1024 for key establishment and ML-DSA-87 for "
                       "signatures across National Security Systems; software/firmware signing "
                       "by 2030.",
        "source": "engine/recommender.py CNSA 2.0 note",
    },
}

Z_BANDS = (
    (0, 5, "below the expert-consensus window: plan-as-if-early (the window itself is 10-20y)"),
    (5, 10, "lower bound of the GRI/evolutionQ 10-20 year expert-consensus window"),
    (10, 15, "midpoint of the GRI/evolutionQ 10-20 year expert-consensus window"),
    (15, 99, "upper bound of the consensus window: a deliberately conservative stance"),
)


# ---------------------------------------------------------------------------------------------
# Colour and markup primitives
# ---------------------------------------------------------------------------------------------

def _channels(colour: str):
    """(r, g, b) as 0.0-1.0 floats from a #rrggbb string."""
    value = colour.lstrip("#")
    return tuple(int(value[i:i + 2], 16) / 255.0 for i in (0, 2, 4))


def relative_luminance(colour: str) -> float:
    """WCAG 2.1 relative luminance. Used to pick legible text rather than to guess at it."""
    linear = []
    for channel in _channels(colour):
        linear.append(channel / 12.92 if channel <= 0.03928
                      else ((channel + 0.055) / 1.055) ** 2.4)
    red, green, blue = linear
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def contrast_ratio(foreground: str, background: str) -> float:
    """WCAG 2.1 contrast ratio between two #rrggbb colours (1.0 .. 21.0)."""
    a, b = relative_luminance(foreground), relative_luminance(background)
    lighter, darker = max(a, b), min(a, b)
    return round((lighter + 0.05) / (darker + 0.05), 2)


def ink_on(colour: str) -> str:
    """Near-black or white text for a filled chip/bar -- whichever actually has more contrast."""
    dark = contrast_ratio("#0B0F14", colour)
    return "#0B0F14" if dark >= contrast_ratio("#FFFFFF", colour) else "#FFFFFF"


def escape(text) -> str:
    """HTML-escape any interpolated value. Findings carry file paths and matched source text."""
    return html.escape(str(text if text is not None else ""))


def chip(text, colour: str) -> str:
    """A labelled pill. The label is mandatory: colour is never the only channel."""
    return (f'<span class="ecdat-chip" style="background:{colour};color:{ink_on(colour)}">'
            f'{escape(text)}</span>')

def bar_chart_svg(entries, *, aria_label: str, empty_label: str = "0 findings",
                  label_width: int = 168, bar_width: int = 360) -> str:
    """Horizontal bar chart as inline SVG.

    `entries` is a sequence of (label, value, colour). Every bar carries its value as text, the
    figure carries `role="img"` and an `aria-label`, and an all-zero chart renders an explicit
    empty state rather than four empty axes -- so a reader who cannot see the fills, or who
    cannot see at all, loses nothing. Nothing is fetched: the markup is the chart.
    """
    rows = [(str(label), int(value or 0), str(colour)) for label, value, colour in entries]
    if not rows:
        return ""
    width = label_width + bar_width + 86
    row_height = 30
    height = row_height * len(rows) + 4
    maximum = max([value for _, value, _ in rows] + [1])

    parts = [
        f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" role="img" '
        f'aria-label="{escape(aria_label)}" xmlns="http://www.w3.org/2000/svg" '
        f'preserveAspectRatio="xMinYMin meet" font-family="inherit">',
        f"<title>{escape(aria_label)}</title>",
        f"<desc>{escape(aria_label)}. The value of every bar is printed beside it.</desc>",
    ]
    if all(value == 0 for _, value, _ in rows):
        parts.append(
            f'<rect x="{label_width}" y="4" width="{bar_width}" height="{row_height - 12}" '
            f'rx="4" fill="none" stroke="currentColor" stroke-opacity="0.35" '
            f'stroke-dasharray="4 3"/>')
        parts.append(
            f'<text x="{label_width + bar_width + 10}" y="{row_height / 2 + 4}" font-size="12" '
            f'fill="currentColor" opacity="0.75">{escape(empty_label)}</text>')
        parts.append("</svg>")
        return "".join(parts)

    for index, (label, value, colour) in enumerate(rows):
        top = index * row_height
        filled = 0 if value == 0 else max(3, round(bar_width * value / maximum))
        parts.append(
            f'<text x="{label_width - 12}" y="{top + row_height / 2 + 4}" font-size="12.5" '
            f'text-anchor="end" fill="currentColor" font-weight="600">{escape(label)}</text>')
        parts.append(
            f'<rect x="{label_width}" y="{top + 4}" width="{bar_width}" '
            f'height="{row_height - 13}" rx="4" fill="currentColor" fill-opacity="0.08"/>')
        parts.append(
            f'<rect x="{label_width}" y="{top + 4}" width="{filled}" height="{row_height - 13}" '
            f'rx="4" fill="{colour}"/>')
        parts.append(
            f'<text x="{label_width + bar_width + 10}" y="{top + row_height / 2 + 4}" '
            f'font-size="12.5" fill="currentColor" font-weight="700">{value}</text>')
    parts.append("</svg>")
    return "".join(parts)


def tier_chart_svg(counts) -> str:
    """Findings per risk tier, highest first, always including the UNRATED bucket."""
    counts = counts or {}
    return bar_chart_svg([(tier, counts.get(tier, 0), TIER_COLOURS[tier])
                         for tier in SEVERITY_ORDER],
                        aria_label="Findings by risk tier")


def assurance_chart_svg(histogram) -> str:
    """Findings per assurance level: what the evidence actually proves, not how sure we are."""
    histogram = histogram or {}
    return bar_chart_svg([(level, histogram.get(level, 0), ASSURANCE_COLOURS[level])
                         for level in ASSURANCE_ORDER],
                        aria_label="Findings by assurance level")


# ---------------------------------------------------------------------------------------------
# Scan records: each finding joined with its verdict, its purpose and its assurance
# ---------------------------------------------------------------------------------------------

def z_basis(z_years) -> str:
    """Where this Z sits in the published consensus window. Z is an estimate, not a deadline."""
    value = float(z_years)
    for low, high, text in Z_BANDS:
        if low <= value < high:
            return text
    return "outside the published consensus window"


def enrich_findings(findings, *, z_years, policy, data_class, x_override=None, y_override=None):
    """Attach the Mosca verdict, the recommendation, the purpose and the assurance to each
    finding.

    A finding that cannot be rated is KEPT and marked with `rating_error` rather than dropped.
    Silently discarding the one artefact the tool choked on would be exactly the dishonesty this
    console exists to avoid.
    """
    from engine.mosca import calculate_risk
    from engine.recommender import get_pqc_recommendation

    records = []
    for finding in findings:
        record = dict(finding)
        record["data_class"] = data_class
        record["rating_error"] = ""
        try:
            record["risk"] = calculate_risk(record, user_x=x_override, user_y=y_override,
                                            z_collapse_time=z_years, policy=policy)
        except Exception as exc:                                    # noqa: BLE001
            record["risk"] = None
            record["rating_error"] = f"{type(exc).__name__}: {exc}"
        try:
            record["recommendation"] = get_pqc_recommendation(record)
        except Exception as exc:                                    # noqa: BLE001
            record["recommendation"] = {
                "algorithm": "Recommendation unavailable", "action": "Review manually",
                "justification": f"The recommender raised {type(exc).__name__}: {exc}",
                "standard_basis": [], "notes": [], "rule_trace": "n/a", "cost_band": "UNKNOWN",
                "confidence": "manual-review"}
        purpose, signals, reason = resolve_purpose(record)
        assurance, assurance_reason = resolve_assurance(record)
        record["purpose"] = {"value": purpose, "signals": signals, "reason": reason}
        record["assurance"] = {"value": assurance, "reason": assurance_reason}
        record["assurance_rank"] = ASSURANCE_RANK.get(assurance, 0)
        record["needs_pqc_target"] = needs_pqc_target(record)
        record["unresolved"] = bool(record["needs_pqc_target"]
                                    and purpose == PURPOSE_UNRESOLVED)
        record["tier"] = (record.get("risk") or {}).get("tier", "UNRATED")
        record["target_declined"] = str(
            (record.get("recommendation") or {}).get("algorithm", "")).lower().startswith("unresolved")
        records.append(record)
    return records


def is_unresolved(record) -> bool:
    return bool(record.get("unresolved"))


# The three outcomes a finding can have against a policy deadline. UNRATED is a real third state,
# not a formatting detail: a finding with no risk result is one ECDAT could not assess, and
# counting it as compliant asserts a safety claim the scan never made.
DEADLINE_WITHIN = "within window"
DEADLINE_OVERRUN = "OVERRUN"
DEADLINE_UNRATED = "UNRATED"
DEADLINE_NO_POLICY = "no active policy"


def deadline_verdict(record, deadline_year) -> str:
    """Classify one finding against the active policy deadline, in three honest states.

    The bug this replaces: `(risk.get("latest_safe_migration_start") or 0) > deadline`. A finding
    whose risk result is absent collapsed to `0`, which is never greater than any real deadline, so
    the UNRATED finding fell through to "within window" and was tallied as compliant. An
    unassessed artefact silently became a pass -- the exact kind of false assurance this tool
    exists to avoid.

    `None` is returned for the start year when risk could not be computed, and that is now
    distinguishable from a start year of 0, which is itself meaningless.
    """
    if not deadline_year:
        return DEADLINE_NO_POLICY
    start = (record.get("risk") or {}).get("latest_safe_migration_start")
    if start is None:
        return DEADLINE_UNRATED
    return DEADLINE_OVERRUN if start > deadline_year else DEADLINE_WITHIN


def late_records(records, deadline_year) -> list:
    """Records that are known to OVERRUN the deadline. UNRATED ones are excluded, not assumed."""
    return [r for r in records if deadline_verdict(r, deadline_year) == DEADLINE_OVERRUN]


def unrated_records(records, deadline_year) -> list:
    """Records that could not be assessed against the deadline -- reported, never hidden."""
    if not deadline_year:
        return []
    return [r for r in records if deadline_verdict(r, deadline_year) == DEADLINE_UNRATED]


def unresolved_split(records):
    """Unresolved-purpose findings, split by what the recommender did with them.

    Two different situations hide behind one count, and conflating them would be its own kind of
    dishonesty:

    *   `declined` -- the recommender refused to name a post-quantum target. A human must look.
    *   `named`    -- purpose is unresolved, but the scanner already typed the primitive (e.g.
        `signature`), and that classification is itself evidence, so a target IS named and the
        finding is flagged for review rather than blocked.
    """
    unresolved = [r for r in records if is_unresolved(r)]
    return ([r for r in unresolved if r.get("target_declined")],
            [r for r in unresolved if not r.get("target_declined")])


def evidence_needed(record) -> list:
    """What would resolve this finding's purpose, cheapest evidence first.

    This is the answer to "so what do I actually go and look at?" for every finding where the
    engine declined to name a post-quantum target. Generic advice would be useless here, so each
    step names the artefact class it applies to and where to look.
    """
    primitive = str(record.get("primitive", "") or "").lower()
    name = str(record.get("name", "")).upper()
    where = location(record)
    steps = []

    if primitive == "pke" or not primitive:
        steps.append(
            "The call site that CONSUMES this key. RSA reached through an encrypt/decrypt or OAEP "
            "wrapper is key establishment; the same key behind a sign/verify call is a signature. "
            "Key generation on its own settles neither, which is why it is unresolved here.")
    elif primitive == "signature":
        steps.append(
            "Confirmation that this key signs and does not encrypt: a Signature.getInstance, "
            "ec.ECDSA or .sign() call, or a certificate whose KeyUsage asserts digitalSignature.")
    elif primitive == "key-agreement":
        steps.append(
            "Confirmation that this key agrees and does not sign: an ECDH_compute_key, "
            "KeyAgreement.getInstance or X25519 call, or a handshake naming the negotiated group.")
    else:
        steps.append(
            f"A call site showing what {name or 'this primitive'} is used for. The algorithm name "
            "alone does not encode the purpose.")

    steps.append(
        "The X.509 certificate for this key, if a CA issues it: the KeyUsage extension settles "
        "purpose in one read (RFC 5280). A KeyUsage asserting BOTH digitalSignature and "
        "keyEncipherment is itself unresolved, not resolved.")
    steps.append(
        f"A handshake or server log from the service that uses {where}. For anything negotiated "
        "at runtime the negotiated suite is the authoritative answer; static evidence cannot "
        "replace a capture sensor.")
    steps.append(
        f"The callers of {where}. The primitive is declared where it was found; its purpose is "
        "decided by whoever consumes it.")
    steps.append(
        "If none of that exists, record the artefact as manual review. An unresolved finding a "
        "human signed off is worth more than a confidently wrong ML-KEM / ML-DSA assignment.")
    return steps


def short_path(path) -> str:
    """Last two path segments: a full absolute path is unreadable in a dense table."""
    text = str(path or "")
    parts = text.replace("\\", "/").rstrip("/").split("/")
    return "/".join(parts[-2:]) if len(parts) > 2 else (text or "n/a")


def location(record) -> str:
    line = record.get("line")
    return f"{short_path(record.get('file'))}:{line}" if line else short_path(record.get("file"))


def tier_counts(records) -> dict:
    counts = {tier: 0 for tier in SEVERITY_ORDER}
    for record in records:
        tier = record.get("tier")
        if tier in counts:
            counts[tier] += 1
    return counts


def assurance_counts(records) -> dict:
    histogram = {level: 0 for level in ASSURANCE_ORDER}
    for record in records:
        level = record["assurance"]["value"]
        histogram[level] = histogram.get(level, 0) + 1
    return histogram


def proven_use(records) -> int:
    """Findings whose evidence proves a USE, not merely a capability. Never report without it."""
    return sum(1 for r in records
               if r["assurance"]["value"] in (ASSURANCE_USED, ASSURANCE_OBSERVED))


def hndl_records(records) -> list:
    return [r for r in records if (r.get("risk") or {}).get("hndl_exposed")]


def coverage_verdict(coverage) -> dict:
    """The distinction this whole console exists to make: 'clean' vs 'not looked at'.

    A scan that found nothing and a scan that could not read anything look identical if you only
    report the finding count. This turns the manifest into a named verdict the UI can headline
    instead of a bare '0 findings'.
    """
    coverage = coverage or {}
    seen = int(coverage.get("files_seen", 0) or 0)
    scanned = int(coverage.get("files_scanned", 0) or 0)
    skipped = int(coverage.get("files_skipped", 0) or 0)
    errors = list(coverage.get("errors") or [])
    if seen == 0 and scanned == 0:
        state = "nothing-examined"
        message = ("Nothing was examined. The scanner reads source, configuration, binary and "
                   "container-image files; a path it does not recognise is counted as NOT "
                   "EXAMINED, never as clean. No statement about this target can be made from "
                   "this scan.")
    elif scanned == 0:
        state = "nothing-examined"
        message = (f"{seen} file(s) were seen and none could be read. A zero-finding result here "
                   f"means 'unreadable', not 'clean'.")
    elif errors:
        state = "incomplete"
        message = (f"{len(errors)} file(s) could not be read. Findings from the {scanned} scanned "
                   f"file(s) stand, but the unread ones are NOT evidence of safety.")
    else:
        state = "covered"
        message = (f"All {scanned} candidate file(s) were read. For the file types this scanner "
                   f"understands a zero-finding result is a real result -- subject to the "
                   f"never-in-scope list below.")
    return {"state": state, "message": message, "files_seen": seen, "files_scanned": scanned,
            "files_skipped": skipped, "errors": errors,
            "read_fraction": (scanned / seen) if seen else 0.0}


# ---------------------------------------------------------------------------------------------
# Row builders -- one shape per role, so no view has to re-derive a number
# ---------------------------------------------------------------------------------------------

def auditor_rows(records) -> list:
    """Every finding with the Mosca inputs, the verdict and the Z-sensitivity band."""
    rows = []
    for record in records:
        risk = record.get("risk") or {}
        band = risk.get("z_band") or {}
        rows.append({
            "Artefact": record.get("name"),
            "Primitive": record.get("primitive"),
            "Tier": record.get("tier"),
            "Assurance": record["assurance"]["value"],
            "Purpose": record["purpose"]["value"],
            "X (y)": risk.get("x"),
            "Y (y)": risk.get("y"),
            "X+Y": risk.get("x_y"),
            "Z (y)": risk.get("z"),
            "Margin": risk.get("margin"),
            "HNDL now": "YES" if risk.get("hndl_exposed") else "",
            # Read the Z values FROM the band, not from a hardcoded (5, 10, 15). The engine now
            # centres the band on the caller's Z, so at Z=40 the keys are Z=35/40/45 -- and
            # probing (5, 10, 15) rendered three dashes for a band that was actually populated,
            # while `z_stable` still said "yes". A sensitivity column that displays nothing
            # while claiming stability is worse than no column.
            "Tier at Z": " / ".join(str(v) for v in band.values()) if band else "not assessed",
            "Z values": ", ".join(sorted(band, key=lambda k: float(k.split("=")[1]))) or "n/a",
            "Stable across Z": "yes" if risk.get("z_stable", True) else "FLIPS",
            # A string, not a number: mixing "" and 2048 in one column makes the table
            # unserialisable, and "not stated" is a more honest cell than an empty one.
            "Key size": f'{record["key_length"]} bits' if record.get("key_length") else "not stated",
            "Rule": record.get("rule_id", ""),
            "Location": location(record),
        })
    order = {tier: index for index, tier in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda row: (order.get(row["Tier"], 9), -(row["Margin"] or 0)))
    return rows


def queue_rows(records, deadline_year=None) -> list:
    """The actionable queue: ordered by what needs a decision first, not by discovery order."""
    rows = []
    for record in records:
        risk = record.get("risk") or {}
        rec = record.get("recommendation") or {}
        latest = risk.get("latest_safe_migration_start")
        versus = ""
        if latest and deadline_year:
            versus = ("STARTS AFTER THE DEADLINE" if latest > deadline_year
                      else "starts before the deadline")
        if record.get("target_declined"):
            status = "TARGET DECLINED - human review"
        elif str(rec.get("algorithm") or "").startswith("unresolved"):
            # Checked BEFORE the `unresolved` flag, because the flag is the weaker signal: a
            # crashed or unresolvable recommender still returns the sentinel string, and routing
            # that to the "target named" bucket asserted a target exists when none was chosen.
            status = "TARGET DECLINED - human review"
        elif record.get("unresolved"):
            status = "target named, purpose unresolved - review"
        else:
            status = "target named"
        rows.append({
            "Artefact": record.get("name"),
            "Tier": record.get("tier"),
            "Target": rec.get("algorithm"),
            "Status": status,
            "Action": rec.get("action"),
            "Assurance": record["assurance"]["value"],
            "X+Y": risk.get("x_y"),
            "Z (y)": risk.get("z"),
            "Margin": risk.get("margin"),
            "HNDL now": "YES" if risk.get("hndl_exposed") else "",
            "Latest safe start": latest,
            "vs deadline": versus,
            "Cost band": rec.get("cost_band"),
            "Size impact": rec.get("tradeoff_size"),
            "Standards": ", ".join(rec.get("standard_basis") or []) or "n/a",
            "Location": location(record),
        })
    tier_rank = {tier: index for index, tier in enumerate(SEVERITY_ORDER)}
    rows.sort(key=lambda row: (row["Status"].startswith("TARGET DECLINED") is False,
                               tier_rank.get(row["Tier"], 9),
                               -(row["Margin"] or 0)))
    for index, row in enumerate(rows, start=1):
        row["#"] = index
    ordered = ["#"] + [key for key in rows[0].keys() if key != "#"] if rows else []
    return [{key: row[key] for key in ordered} for row in rows]


def recommendations_payload(records, *, target, policy, z_years) -> list:
    """The downloadable queue: verdict, target and the evidence behind both, per artefact.

    The rating inputs travel with the answer (X, Y, Z, the policy deadline and the reasons for
    each) so a reader can recompute the verdict by hand instead of trusting the tool.
    """
    return [{
        "target": target,
        "artefact": record.get("name"),
        "primitive": record.get("primitive"),
        "location": location(record),
        "file": record.get("file"),
        "line": record.get("line"),
        "evidence_class": record.get("evidence_class"),
        "assurance": record["assurance"],
        "purpose": record["purpose"],
        "unresolved_purpose": record.get("unresolved"),
        "pqc_target_declined": record.get("target_declined"),
        "rating_inputs": {"z_years": z_years, "policy": policy},
        "risk": record.get("risk"),
        "rating_error": record.get("rating_error") or None,
        "recommendation": record.get("recommendation"),
    } for record in records]


def deadline_countdown(year, current_year) -> str:
    """A deadline's distance from today, as a word rather than a signed integer.

    A bare `year - current_year` renders a lapsed deadline as "-3 year(s) from 2026". The number is
    arithmetically right and rhetorically useless: a reader skims "from 2026", sees a small
    magnitude, and misses that the date has already passed. Saying PASSED is the whole point of
    the field.
    """
    if not year:
        return "n/a"
    remaining = year - current_year
    if remaining < 0:
        return f"PASSED {abs(remaining)} year(s) ago"
    if remaining == 0:
        return "this year"
    return f"{remaining} year(s) from {current_year}"


def policy_deadline_row(policy, current_year) -> dict:
    """One policy deadline, with what it requires and where in this repo that claim comes from."""
    entry = POLICY_DEADLINES.get(policy, {})
    year = entry.get("year")
    notes = POLICY_NOTES.get(policy, {})
    return {
        "Policy": entry.get("label", policy),
        "Deadline": year,
        "Years from now": deadline_countdown(year, current_year),
        "What it requires": notes.get("requirement", "n/a"),
        "Source in this repo": notes.get("source", "engine/mosca.py POLICY_DEADLINES"),
    }


# ---------------------------------------------------------------------------------------------
# CBOM validation -- offline, against the schema cached in schemas/
# ---------------------------------------------------------------------------------------------

@functools.lru_cache(maxsize=4)
def _validator_for(schema_path: str, mtime: float):
    """A compiled validator, cached per (path, mtime).

    `mtime` is part of the key so a refreshed schema is picked up without a restart. A
    jsonschema validator is reusable and read-only during `iter_errors`, so caching one across
    Streamlit session threads is safe.
    """
    import jsonschema

    with open(schema_path, encoding="utf-8") as handle:
        schema = json.load(handle)
    return jsonschema.Draft7Validator(schema), schema


def validate_cbom_document(document, schema_path: str = None) -> dict:
    """Validate a CBOM against the published CycloneDX 1.7 JSON Schema, entirely offline.

    The schema is the copy cached in `schemas/bom-1.7.schema.json`; nothing is fetched. Every
    failure mode is returned as a state string rather than raised, so the console can explain
    itself instead of printing a traceback -- and, more importantly, can WITHHOLD the download
    when the document has not been proven conformant. An unvalidated CBOM is not evidence.
    """
    schema_path = schema_path or DEFAULT_SCHEMA_PATH
    document = document or {}
    result = {
        "ok": False, "state": "error", "message": "", "errors": [],
        "spec_version": document.get("specVersion"),
        "schema_id": "", "component_count": len(document.get("components", []) or []),
        "schema_path": schema_path, "schema_present": os.path.exists(schema_path),
    }

    try:
        import jsonschema                                     # noqa: F401
    except ImportError:
        result.update(state="library-missing",
                      message="jsonschema is not installed, so this document cannot be proven "
                              "conformant. Install it with:  pip install jsonschema")
        return result

    if not result["schema_present"]:
        result.update(state="schema-missing",
                      message=f"No CycloneDX 1.7 schema at {schema_path}. Without it there is no "
                              f"conformance claim to make, so no CBOM download is offered.")
        return result

    try:
        validator, schema = _validator_for(schema_path, os.path.getmtime(schema_path))
    except Exception as exc:                                    # noqa: BLE001
        result.update(state="schema-unreadable",
                      message=f"The schema at {schema_path} could not be loaded: "
                              f"{type(exc).__name__}: {exc}")
        return result

    result["schema_id"] = str(schema.get("$id") or schema.get("title") or "")
    try:
        errors = sorted(validator.iter_errors(document), key=lambda e: list(e.absolute_path))
    except Exception as exc:                                    # noqa: BLE001
        result.update(state="error",
                      message=f"Validation could not be completed: {type(exc).__name__}: {exc}")
        return result

    result["errors"] = [{"path": "/".join(str(p) for p in err.absolute_path) or "<root>",
                         "message": str(err.message)[:300]} for err in errors[:25]]
    if errors:
        result.update(ok=False, state="invalid",
                      message=f"INVALID against the CycloneDX {result['spec_version']} schema: "
                              f"{len(errors)} error(s). The download is withheld until this is "
                              f"fixed -- an unvalidated CBOM is not evidence.")
        return result

    result.update(ok=True, state="valid",
                  message=f"VALID against the CycloneDX {result['spec_version']} JSON Schema: "
                          f"{result['component_count']} component(s) checked, offline, against "
                          f"the schema cached in schemas/.")
    return result
