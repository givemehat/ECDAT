"""ECDAT console -- a role-based Streamlit front end for the discovery engine.

WHY THIS FILE LOOKS THE WAY IT DOES
-----------------------------------
The previous dashboard had two views (Compliance / Engineer) and led with a single number:
"47 cryptographic artefacts discovered". That number is the easiest way for a discovery tool to
mislead a reader, because it silently mixes two different claims:

    47 artefacts were MATCHED   --  and   5 of them are proven call sites

The other 42 are capabilities: a library that *can* do RSA, with nothing showing anything calls
it. A regulator, a CISO and a judge should never have to guess which number they are looking at,
so this console:

  *   shows `findings_total` and `proven_use` side by side, everywhere, always;
  *   puts EVIDENCE & HONESTY first in the role selector, because the coverage manifest -- what
      was read, what failed, what was never in scope -- is the part competitors bury;
  *   shows UNRESOLVED-PURPOSE findings as a feature, not an embarrassment: where the evidence
      does not settle what a primitive is FOR, no post-quantum target is named, and the console
      says exactly which evidence would resolve it;
  *   validates the CycloneDX 1.7 CBOM against the schema cached in `schemas/` BEFORE offering
      the download, and withholds the download when it cannot be proven conformant.

Four views, one per audience: EVIDENCE & HONESTY, AUDITOR, MIGRATION PLANNER, STANDARDS &
COMPLIANCE. All of them read the same scan; none of them recompute a number.

OPERATIONAL CONSTRAINTS
-----------------------
No network calls, no CDN, no new dependencies: charts are inline SVG built in
`engine/gui_helpers.py`, and the CBOM schema is read from disk. The module imports cleanly
without Streamlit and without a running server (`python -c "import app"` only defines things --
the UI is behind `main()`), and every failure path renders an explanation instead of a
traceback.
"""
import datetime
import json
import os
import sys

# `streamlit run C:\\somewhere\\app.py` does not put the script's own directory on sys.path, so
# `from engine...` fails the moment the console is launched from anywhere but the repository
# root. Adding it here is what makes `streamlit run <absolute path to app.py>` work from any
# working directory, and it costs one line.
_REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:                                                        # Streamlit is optional at import time
    import streamlit as st
    STREAMLIT_AVAILABLE = True
    STREAMLIT_IMPORT_ERROR = ""
except ImportError as exc:                                   # pragma: no cover - depends on env
    st = None
    STREAMLIT_AVAILABLE = False
    STREAMLIT_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

from engine.gui_helpers import (SEVERITY_ORDER, TIER_COLOURS, assurance_chart_svg,
                                assurance_counts, auditor_rows, chip, coverage_verdict,
                                deadline_countdown, deadline_verdict, enrich_findings, escape,
                                evidence_needed, hndl_records, late_records, location,
                                policy_deadline_row, proven_use, queue_rows,
                                recommendations_payload, short_path, tier_chart_svg, tier_counts,
                                unresolved_split, unrated_records, validate_cbom_document, z_basis)
from engine.mosca import POLICY_DEADLINES
from engine.purpose import ASSURANCE_MEANING

ROLES = [
    "Evidence & Honesty",
    "Auditor",
    "Migration Planner",
    "Standards & Compliance",
]

CSS = """
<style>
  .ecdat-chip { display:inline-block; padding:1px 9px; border-radius:999px; font-size:0.76rem;
               font-weight:600; letter-spacing:0.02em; }
  .ecdat-callout { border-left:4px solid #3D4756; padding:0.55rem 0.9rem; margin:0.3rem 0 0.7rem 0;
                   border-radius:0 6px 6px 0; background:rgba(128,128,128,0.10); }
  .ecdat-callout p { margin:0.15rem 0; }
  .ecdat-title { font-size:1.5rem; font-weight:700; line-height:1.2; margin:0; }
  .ecdat-sub { font-size:0.95rem; opacity:0.85; margin:0.1rem 0 0.7rem 0; }
  .ecdat-mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
                font-size:0.85rem; }
  .ecdat-foot { font-size:0.8rem; opacity:0.75; }
  .ecdat-tiles { display:flex; flex-wrap:wrap; gap:0.4rem; margin:0.2rem 0 0.6rem 0; }
  div[data-testid="stMetric"] { border:1px solid rgba(128,128,128,0.32); border-radius:8px;
                                padding:0.55rem 0.8rem; background:rgba(128,128,128,0.04); }
  div[data-testid="stMetricLabel"] p { font-size:0.78rem; letter-spacing:0.02em; }
  ul.ecdat-list li { margin-bottom:0.3rem; }
</style>
"""


# ---------------------------------------------------------------------------------------------
# Small compatibility and formatting helpers
# ---------------------------------------------------------------------------------------------

def _streamlit_version() -> tuple:
    """(major, minor) of the installed Streamlit, or (0, 0) when it cannot be determined."""
    try:
        parts = []
        for chunk in str(st.__version__).split(".")[:2]:
            parts.append(int(chunk) if chunk.isdigit() else 0)
        return tuple(parts)
    except Exception:                                          # noqa: BLE001
        return (0, 0)


def dataframe(rows, **kwargs):
    """st.dataframe across Streamlit versions.

    `use_container_width` was deprecated in favour of `width="stretch"` in 1.49 and calling the
    modern name on an older release raises, so the console asks the version once instead of
    pinning a requirement it does not need.
    """
    if not rows:
        st.caption("Nothing to tabulate.")
        return
    if _streamlit_version() >= (1, 49):
        st.dataframe(rows, width="stretch", **kwargs)
    else:                                                     # pragma: no cover - old Streamlit
        st.dataframe(rows, use_container_width=True, **kwargs)


def metric_row(items):
    """A row of st.metric cards. `items` is a sequence of (label, value, help) tuples."""
    items = [item for item in items if item is not None]
    if not items:
        return
    for column, item in zip(st.columns(len(items)), items):
        label, value, help_text = (list(item) + [None, None])[:3]
        column.metric(label, value, help=help_text)


def callout(text, colour="#3D4756"):
    """A left-ruled note. Used instead of a bare st.info so the accent matches the charts."""
    st.markdown(f'<div class="ecdat-callout" style="border-left-color:{colour}">{text}</div>',
                unsafe_allow_html=True)


def tier_chip(tier):
    return chip(tier, TIER_COLOURS.get(tier, "#3D4756"))


def tier_tiles(records, limit=12):
    """Tier chips for the leading findings: a colour key that doubles as a short summary."""
    if not records:
        return ""
    parts = ['<div class="ecdat-tiles">']
    for record in records[:limit]:
        risk = record.get("risk") or {}
        detail = (f'{record.get("tier")} | X+Y {risk.get("x_y")} vs Z {risk.get("z")} '
                  f'| margin {risk.get("margin")}')
        parts.append(f'<span title="{escape(detail)}">{tier_chip(record.get("tier"))}</span>')
        parts.append(f'<span class="ecdat-mono">{escape(record.get("name"))} '
                     f'{escape(location(record))}</span>')
    parts.append("</div>")
    return "".join(parts)


def json_download(label: str, payload, key: str):
    """st.download_button with a stable, readable payload and a stable widget key."""
    text = payload if isinstance(payload, str) else json.dumps(payload, indent=2, default=str)
    st.download_button(label, data=text, file_name=f"{key}.json", mime="application/json",
                       key=f"dl-{key}")


# ---------------------------------------------------------------------------------------------
# Scan plumbing
#
# A fresh ECDATScanner is built per run on purpose: its coverage counters live on the instance,
# so a cached scanner would report the UNION of several runs and quietly overstate what was
# read. Results are memoised per (target, ml) instead, and the expensive part -- the PyTorch
# model -- is only loaded when the operator asks for it.
# ---------------------------------------------------------------------------------------------

def _streamlit_runtime_available() -> bool:
    """True when a Streamlit script run is actually in progress.

    `st.cache_data` warns when it is applied with no runtime, which is exactly what happens when
    this module is imported for a syntax check or a unit test. Applying the decorator only
    inside a real run keeps `python -c "import app"` silent as well as successful.
    """
    try:
        return bool(st.runtime.exists())
    except Exception:                                          # noqa: BLE001
        return False


def _memoised(max_entries: int):
    """`st.cache_data` when a Streamlit runtime is present, a no-op decorator otherwise.

    This is what lets `python -c "import app"` succeed on a machine with no Streamlit at all:
    the module still defines, it simply has nothing to render into.
    """
    def decorate(func):
        return st.cache_data(show_spinner=False, max_entries=max_entries)(func) \
            if STREAMLIT_AVAILABLE and _streamlit_runtime_available() else func
    return decorate


def _target_fingerprint(target: str) -> str:
    """A cheap, stable digest of WHAT IS ON DISK right now.

    `run_scan` is memoised, and the memo key was `(target, enable_ml)`. That makes the cache
    blind to the one thing that matters: the target's contents. Edit a file, press Rescan, and the
    user got the previous findings together with the previous `scanned_at` -- so the console
    presented stale evidence under a claim of freshness, which for an audit tool is the worst
    possible failure mode. Including a content digest in the memo key makes the cache invalidate
    itself instead.

    Path + size + mtime for each file, not content hashing: a full read of every file would cost
    as much as the scan itself, defeating the cache. Size and mtime change on any ordinary edit,
    and a deliberately unchanged mtime with changed content is not a threat model this tool has.
    """
    import hashlib

    digest = hashlib.sha256()
    try:
        for root, dirs, files in os.walk(target):
            dirs.sort()  # walk order is not stable across platforms/filesystems
            for name in sorted(files):
                path = os.path.join(root, name)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                digest.update(("%s|%d|%d\n" % (path, stat.st_size, stat.st_mtime_ns)).encode())
    except OSError:
        return "unreadable"
    return digest.hexdigest()


@_memoised(8)
def run_scan(target: str, enable_ml: bool, fingerprint: str = "") -> dict:
    """Scan a target and return findings plus the coverage manifest. Exceptions propagate to
    the caller, which renders an explanation -- never a traceback.

    `fingerprint` is NOT used for anything except cache invalidation (see `_target_fingerprint`).
    It is a parameter solely so it participates in the memo key.
    """
    from engine.scanner import ECDATScanner

    scanner = ECDATScanner(enable_ml=enable_ml)
    findings = scanner.scan_directory(target)
    coverage = scanner.coverage_manifest(findings)
    return {"target": target, "enable_ml": enable_ml, "findings": findings, "coverage": coverage,
            "scanned_at": datetime.datetime.now().replace(microsecond=0).isoformat()}


@_memoised(16)
def rate_findings(findings_json: str, z_years: float, policy: str, data_class: str,
                  x_override, y_override) -> list:
    """Attach verdicts, recommendations, purpose and assurance.

    Cached on the serialised findings plus the rating parameters, so changing Z or the policy
    re-rates instantly while switching roles costs nothing. The findings are passed as JSON
    because Streamlit hashes the arguments, and a JSON string is both hashable and a faithful
    copy -- which also stops a cached record from being mutated by a later view.
    """
    return enrich_findings(json.loads(findings_json), z_years=z_years, policy=policy,
                           data_class=data_class, x_override=x_override, y_override=y_override)


def integrity_strip(records, coverage):
    """The honesty line, shown above EVERY view.

    `findings_total` is never rendered on its own: the raw count, the proven-use count and the
    capability remainder are always adjacent, so no reader can quote one without the others.
    """
    total = len(records)
    proven = proven_use(records)
    unresolved = sum(1 for r in records if r.get("unresolved"))
    verdict = coverage_verdict(coverage)
    metric_row([
        ("Findings (raw total)", total,
         "Every artefact the rule table matched. This number on its own is misleading: it mixes "
         "proven call sites with capabilities nothing calls. Read it with the next two."),
        ("Proven use", proven,
         "Assurance is 'used' (code invokes it) or 'observed' (seen in a real artefact). These "
         "are the findings a risk decision can rest on."),
        ("Capability / declared only", total - proven,
         "Reachable or configured, with nothing showing it is called or executed. Real inventory, "
         "but not proof of exposure."),
        ("Unresolved purpose", unresolved,
         "No post-quantum target is named for these until a human resolves what the primitive is "
         "FOR. See the Migration Planner for the resolving evidence."),
        ("Files scanned", verdict["files_scanned"],
         f'Of {verdict["files_seen"]} candidate file(s) seen on disk.'),
        ("Files not read", verdict["files_skipped"],
         "Credential stores, symlinks escaping the scan root, unreadable files. Each one is "
         "listed with its reason in the Evidence view -- none of them is evidence of safety."),
    ])
    st.markdown(
        f'<div class="ecdat-foot">Read together: <b>{total}</b> artefact(s) matched, of which '
        f'<b>{proven}</b> are proven use and <b>{total - proven}</b> are capability/declared '
        f'only; <b>{unresolved}</b> need a human to settle their purpose.</div>',
        unsafe_allow_html=True)


def scan_header(scan, records):
    """One line describing WHICH scan the numbers on screen came from."""
    st.markdown(
        f'<div class="ecdat-foot">Scan of <span class="ecdat-mono">'
        f'{escape(short_path(scan["target"]))}</span> at {escape(scan["scanned_at"])} '
        f'· ML engine: {escape(scan["coverage"].get("ml_reason", "unknown"))} '
        f'· {len(records)} finding(s) after de-duplication.</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------------------------
# View 1 -- EVIDENCE & HONESTY (the default, and the reason this console is different)
# ---------------------------------------------------------------------------------------------

def view_evidence(scan, records):
    coverage = scan["coverage"]
    verdict = coverage_verdict(coverage)
    total = len(records)
    proven = proven_use(records)
    declined, named = unresolved_split(records)
    histogram = assurance_counts(records)

    st.subheader("What this scan proves, and what it does not")
    st.markdown(
        "A discovery tool that reports only a finding count is asking you to trust it. This view "
        "is the audit trail behind every number in the other three: what was read, what failed, "
        "what was never in scope, and how much of the inventory is proven use rather than a "
        "capability.")

    # --- the coverage verdict, stated before any count ---------------------------------------
    colour = {"covered": "#1F5C3A", "incomplete": "#9A4A06", "nothing-examined": "#8C1D18"}[
        verdict["state"]]
    headline = {"covered": "Scan complete and fully read",
                "incomplete": "Scan incomplete -- some files were never read",
                "nothing-examined": "Nothing was examined"}[verdict["state"]]
    callout(f"<p><b>{escape(headline)}.</b> {escape(verdict['message'])}</p>", colour)

    metric_row([
        ("Findings (raw total)", total, "Every artefact the rule table matched."),
        ("Proven use", proven, "Assurance 'used' or 'observed': a call site, or a real artefact."),
        ("Capability / declared only", total - proven,
         "Reachable or permitted, with nothing showing it is called."),
        ("Assurance 'declared'", histogram.get("declared", 0),
         "Found in configuration: stated policy, not an execution."),
        ("Assurance 'capability'", histogram.get("capability", 0),
         "A dependency or library that implements the algorithm; nothing invokes it."),
        ("Purpose unresolved", len(declined) + len(named),
         "No target named (declined), or named despite an unsettled purpose (review)."),
    ])

    closing = ("All of them are proven use." if total == proven else
               f"The remaining {total - proven} are capabilities or declared configuration: real "
               "inventory, but no evidence that anything calls them. Quoting the raw total alone "
               "would overstate the exposure.")
    st.markdown(
        f'<div class="ecdat-callout" style="border-left-color:#1F5C3A">'
        f'<p><b>The headline number is a pair, not a scalar.</b> {total} artefact(s) were '
        f'matched; {proven} of them are proven use. {closing}</p></div>', unsafe_allow_html=True)

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**Assurance histogram** -- what the evidence proves, not how sure we are")
        st.markdown(assurance_chart_svg(histogram), unsafe_allow_html=True)
        dataframe([{
            "Assurance": level,
            "Findings": histogram.get(level, 0),
            "Share": f'{histogram.get(level, 0) / total:.0%}' if total else "n/a",
            "What it means": ASSURANCE_MEANING.get(level, ""),
        } for level in ("observed", "used", "declared", "capability")])
        st.caption("Assurance is not confidence. Confidence answers 'is the algorithm "
                   "identification right?'; assurance answers 'what does this evidence prove?' "
                   "(engine/purpose.py).")
    with right:
        st.markdown("**Risk tiers** -- from Mosca's inequality, X + Y against Z")
        st.markdown(tier_chart_svg(tier_counts(records)), unsafe_allow_html=True)
        st.caption("Tiers come from the inequality, never from the algorithm family: a primitive "
                   "the inequality does not apply to is LOW however old it looks.")

    st.markdown(tier_tiles(records), unsafe_allow_html=True)


    st.divider()
    st.subheader("Coverage: files seen, files read, files refused")
    metric_row([
        ("Files seen", verdict["files_seen"], "Every file the directory walk encountered."),
        ("Files scanned", verdict["files_scanned"],
         "Read and matched against the rule table, binaries and container layers."),
        ("Files not read", verdict["files_skipped"],
         "Credential stores, symlinks leaving the scan root, files that could not be decoded. "
         "Each is listed below with its reason."),
        ("Read fraction", f'{verdict["read_fraction"]:.0%}',
         "Scanned / seen. Below 100% means part of the tree is unexamined."),
    ])
    st.markdown(
        f'<div class="ecdat-foot">Scanners that ran: <span class="ecdat-mono">'
        f'{escape(", ".join(coverage.get("scanners_run") or []) or "none produced a finding")}'
        f'</span> &middot; ML engine: <span class="ecdat-mono">'
        f'{escape(str(coverage.get("ml_reason", "unknown")))}</span> (it sees only the first '
        f'{coverage.get("ml_window_chars", "n/a")} characters of a file; the rest is covered by '
        f'the rule table).</div>', unsafe_allow_html=True)

    st.subheader("Every scan error, with its reason")
    errors = verdict["errors"]
    if errors:
        st.error(f"{len(errors)} file(s) could NOT be read. They are excluded from every count on "
                 f"this page, and a zero-finding result does not cover them.")
        dataframe([{"#": index, "File": entry.get("file"), "Reason": entry.get("reason")}
                   for index, entry in enumerate(errors, start=1)])
    else:
        st.success("No file failed to be read in this scan. Stated explicitly, because the "
                   "absence of errors is itself a claim: the only exclusions are files this "
                   "scanner never claimed to understand (see 'never in scope' below).")

    st.subheader("Never in scope for this sensor")
    st.markdown("These are not oversights to be patched in the UI -- each needs a different kind "
                "of sensor, or an attestation from a system ECDAT cannot see into. Saying so is "
                "the honest position; implying coverage would not be.")
    gaps = coverage.get("never_in_scope") or []
    st.markdown("\n".join(f"- {escape(gap)}" for gap in gaps) or "- (none reported)")
    st.caption("Source: engine/scanner.py coverage_manifest().")

    st.divider()
    st.subheader("Purpose honesty: where the tool refused to guess")
    metric_row([
        ("Target declined", len(declined),
         "The recommender refused to name a post-quantum target because the evidence does not "
         "settle what the primitive is FOR."),
        ("Target named, purpose open", len(named),
         "Purpose is unresolved, but the scanner already typed the primitive -- that "
         "classification is itself evidence, so a target is given and the finding is flagged."),
    ])
    if declined or named:
        st.markdown(
            "An unresolved finding a human reviews is worth more than a resolved one that is "
            "wrong, so the count is published rather than buried. The Migration Planner lists "
            "each one with the specific evidence that would resolve it.")
    else:
        st.info("No finding in this scan needs a post-quantum target whose purpose is unsettled.")

    st.subheader("Coverage manifest")
    st.caption("The same object the CLI writes to ecdat_coverage.json, and the same object the "
               "CBOM embeds as ecd: properties. Download it and anyone can check the claims on "
               "this page.")
    json_download("Download coverage manifest (JSON)", coverage, "ecdat_coverage")
    with st.expander("Coverage manifest, verbatim"):
        st.json(coverage)


# ---------------------------------------------------------------------------------------------
# View 2 -- AUDITOR (findings, risk tiers, and the rule trace behind every verdict)
# ---------------------------------------------------------------------------------------------

def view_auditor(records):
    st.subheader("Findings, risk tiers and the arithmetic behind each verdict")
    st.markdown("Every tier here is an application of Mosca's inequality, X + Y against Z, and "
                "every input is shown with the reason it holds that value. Expand any row for the "
                "rule that fired, the code that matched, and the Z-sensitivity band.")

    counts = tier_counts(records)
    hndl = hndl_records(records)
    unrated = [r for r in records if r.get("rating_error")]
    metric_row([
        ("CRITICAL", counts.get("CRITICAL"),
         "Exposed to harvest-now-decrypt-later, or a margin of 10 years or more over Z."),
        ("HIGH", counts.get("HIGH"), "X + Y exceeds Z: migration should already have started."),
        ("MEDIUM", counts.get("MEDIUM"),
         "Subject to the inequality but not yet over it, or a Grover-weakened key needing "
         "confirmation."),
        ("LOW", counts.get("LOW"), "Not broken by Shor, or adequate strength after Grover."),
        ("HNDL exposed now", len(hndl),
         "Ciphertext captured today is retroactively readable once a CRQC exists; migrating later "
         "cannot undo that."),
        ("Unrated", len(unrated),
         "Findings the risk calculator could not rate. Listed at the bottom rather than dropped."),
    ])

    if hndl:
        st.error(f"{len(hndl)} artefact(s) are exposed to harvest-now-decrypt-later. Traffic or "
                 f"ciphertext captured today is retroactively readable once a CRQC exists, and "
                 f"migrating later cannot undo that.")

    if not records:
        st.info("No artefact was matched in this scan. Before reading that as 'clean', check the "
                "Evidence view: a tree that could not be read produces exactly the same empty "
                "result.")
        return

    f1, f2, f3 = st.columns([2, 2, 1])
    needle = f1.text_input("Filter on name, primitive or file", value="", key="auditor-filter",
                           placeholder="e.g. RSA, ECDSA, kex_mlkem")
    tiers = f2.multiselect("Risk tiers", SEVERITY_ORDER, default=SEVERITY_ORDER,
                           key="auditor-tiers")
    only_hndl = f3.checkbox("HNDL only", value=False, key="auditor-hndl")

    rows = auditor_rows(records)
    if needle:
        low = needle.lower()
        rows = [row for row in rows if any(low in str(value).lower() for value in row.values())]
    # An EMPTY selection means "no tiers match", not "no filter". Testing the truthiness of the
    # multiselect returned every row whenever the user cleared the control, so the table silently
    # went from filtered to unfiltered -- the opposite of what clearing a filter should do.
    rows = [row for row in rows if row["Tier"] in tiers]
    if only_hndl:
        rows = [row for row in rows if row["HNDL now"] == "YES"]
    st.caption(f"{len(rows)} of {len(records)} finding(s) shown after filtering.")
    dataframe(rows)


    st.markdown("#### Why each verdict")
    st.caption("Rule IDs map 1:1 to the detection table in engine/scanner.py. X and Y come from "
               "documented, overridable tables in engine/mosca.py -- never from model confidence, "
               "so a model retrain cannot silently re-rate the estate.")
    rank = {tier: index for index, tier in enumerate(SEVERITY_ORDER)}
    ordered = sorted(records, key=lambda r: (rank.get(r.get("tier"), 9),
                                             -((r.get("risk") or {}).get("margin") or 0)))
    for record in ordered:
        risk = record.get("risk")
        name = f'{record.get("name")} ({record.get("primitive")}) - {location(record)}'
        if not risk:
            with st.expander(f"{name} - UNRATED"):
                st.error("The risk calculator raised: " + str(record.get("rating_error")))
            continue
        label = f'{name} - {record.get("tier")}'
        if risk.get("hndl_exposed"):
            label += "  [HNDL EXPOSED]"
        with st.expander(label):
            st.markdown(
                f'{tier_chip(record.get("tier"))} &nbsp; `{escape(str(record.get("rule_id", "")))}`'
                f' &middot; scanner `{escape(str(record.get("scanner", "")))}`'
                f' &middot; assurance **{escape(str(record["assurance"]["value"]))}**'
                f' &middot; purpose **{escape(str(record["purpose"]["value"]))}**',
                unsafe_allow_html=True)
            st.markdown(f'- **Break model:** {escape(str(risk.get("break_model")))} '
                        f'({escape(str(risk.get("threat")))})')
            st.markdown(f'- **Mosca:** X({risk.get("x")}) + Y({risk.get("y")}) = '
                        f'{risk.get("x_y")} vs Z({risk.get("z")}) &rarr; margin '
                        f'{risk.get("margin")} &rarr; **{escape(str(record.get("tier")))}**')
            st.markdown(f'- **X came from:** {escape(str(risk.get("x_reason")))}')
            adjustment = (f' + {risk.get("y_complexity_adjustment")}y complexity adjustment'
                          if risk.get("y_complexity_adjustment") else "")
            st.markdown(f'- **Y came from:** {escape(str(risk.get("y_reason")))} '
                        f'(base {risk.get("y_base")}y{adjustment})')
            band = risk.get("z_band") or {}
            st.markdown("- **Z-band:** "
                        + " &rarr; ".join(f'{escape(str(k))}: {escape(str(v))}'
                                           for k, v in band.items())
                        + f' &nbsp; (stable across the window: {risk.get("z_stable")})')
            bits = risk.get("grover_effective_bits")
            st.markdown("- **Post-Grover effective strength:** "
                        f'{bits if bits is not None else "not determinable from the finding"} bits')
            horizon = ("subject to the inequality" if risk.get("subject_to_inequality")
                       else "inequality does not apply to this primitive")
            st.markdown(f'- **Horizon:** {escape(str(risk.get("horizon_type")))} - {horizon}')
            deadline = (risk.get("policy_deadline") or {}).get("year")
            st.markdown(f'- **Latest safe migration start:** {risk.get("latest_safe_migration_start")}'
                        f' (active policy deadline: {escape(str(deadline))})')
            st.markdown(f'- **Evidence class:** {escape(str(record.get("evidence_class")))}'
                        f' &middot; detector confidence {record.get("dl_confidence")}'
                        f' &middot; AST depth {record.get("ast_depth")}')
            if record.get("match"):
                st.markdown(f'- **Matched text:** `{escape(str(record.get("match"))[:160])}`')
            signals = record["purpose"]["signals"]
            st.markdown(f'- **Purpose evidence:** {escape(str(record["purpose"]["reason"]))}'
                        + (f' (signals: {escape(", ".join(signals))})' if signals
                           else " (no purpose signal found)"))
            st.markdown(f'- **Assurance:** {escape(str(record["assurance"]["reason"]))}')
            for assumption in risk.get("assumptions", []):
                st.caption(f"assumption: {assumption}")


# ---------------------------------------------------------------------------------------------
# View 3 -- MIGRATION PLANNER (the actionable queue, unresolved purpose first)
# ---------------------------------------------------------------------------------------------

def view_planner(scan, records, policy, z_years):
    deadline = (POLICY_DEADLINES.get(policy) or {}).get("year")
    declined, named = unresolved_split(records)
    starts = [(r.get("risk") or {}).get("latest_safe_migration_start") for r in records]
    starts = [year for year in starts if year]
    late = late_records(records, deadline)
    unrated = unrated_records(records, deadline)

    st.subheader("The actionable queue")
    st.markdown("Ordered by what needs a decision first. Each row carries the target, the cost, "
                "the standard it comes from, and the latest year migration can start and still "
                "finish before the active deadline.")
    metric_row([
        ("Items in the queue", len(records), "Every finding, with the action it implies."),
        ("Need a human, not a target", len(declined),
         "Unresolved purpose: the tool declined to name a post-quantum target. See below."),
        ("Earliest safe start", min(starts) if starts else "n/a",
         "The first latest-safe-start year across the queue. Anything earlier is already late."),
        ("Start after the deadline", len(late),
         f"Artefacts whose migration window closes after {deadline}, the active policy deadline."),
        ("Could not be rated", len(unrated),
         "No risk verdict -- X, Y or Z was unavailable. NOT counted as compliant; resolve the "
         "inputs to assess these."),
        ("HNDL exposed", len(hndl_records(records)),
         "No start date helps these: the data becomes readable once a CRQC exists."),
    ])

    # --- unresolved purpose, first and unmissable --------------------------------------------
    st.subheader("Unresolved purpose: no post-quantum target is named for these")
    callout(
        "<p><b>These are not failures, and they are not hidden.</b> Where the evidence does not "
        "settle what a primitive is <i>for</i>, ECDAT declines to name a target: ML-KEM does not "
        "substitute for ML-DSA, so a confident guess would be confidently wrong. What follows is "
        "the exact evidence that resolves each one, cheapest first.</p>", "#8C1D18")

    if not declined and not named:
        st.success("Nothing in this scan has an unresolved purpose. Every finding that needs a "
                   "post-quantum target has enough evidence to name one.")
    else:
        metric_row([
            ("Target declined", len(declined),
             "No algorithm named. A human must settle the purpose before migration can be planned "
             "for this artefact."),
            ("Target named, purpose open", len(named),
             "The primitive is already typed by the scanner (that classification is itself "
             "evidence), so a target is given -- but the purpose is still worth confirming."),
        ])


        for record in declined:
            signals = record["purpose"]["signals"]
            title = (f'{record.get("name")} ({record.get("primitive")}) - '
                     f'{location(record)} - NO TARGET NAMED')
            with st.expander(title, expanded=len(declined) <= 3):
                st.markdown(
                    f'{tier_chip(record.get("tier"))} &nbsp; assurance '
                    f'**{escape(str(record["assurance"]["value"]))}** &nbsp; rule '
                    f'`{escape(str(record.get("rule_id", "")))}`', unsafe_allow_html=True)
                st.markdown(f'**Why no target is named:** '
                            f'{escape(str(record["purpose"]["reason"]))}.')
                if signals:
                    st.markdown("**Evidence that was seen but does not settle it:** "
                                f'`{escape(", ".join(signals))}`')
                st.markdown("**What would resolve it, cheapest evidence first:**")
                st.markdown("\n".join(f"{index}. {escape(step)}"
                                      for index, step in enumerate(evidence_needed(record), 1)))
                st.markdown(f'**Recommendation of record:** '
                            f'{escape(str((record.get("recommendation") or {}).get("action")))} '
                            f'(`{escape(str((record.get("recommendation") or {}).get("rule_trace")))}`)')

        if named:
            with st.expander(f"{len(named)} finding(s) with a named target but an open purpose"):
                st.markdown(
                    "For these the scanner already resolved the primitive class, which is itself "
                    "evidence, so the recommender named a target. The purpose is still open, so "
                    "they are listed for confirmation rather than treated as settled.")
                dataframe([{"Artefact": r.get("name"), "Primitive": r.get("primitive"),
                            "Target": (r.get("recommendation") or {}).get("algorithm"),
                            "Why purpose is open": r["purpose"]["reason"],
                            "Location": location(r)} for r in named])

    st.divider()
    st.subheader("Queue")
    label = str((POLICY_DEADLINES.get(policy) or {}).get("label"))
    dataframe(queue_rows(records, deadline_year=deadline))
    st.caption(f"Deadline applied: {escape(label)} ({deadline}). Z is {z_years} years and is a "
               f"cryptanalytic estimate, not a deadline; the two are never conflated.")


    with st.expander("Cost, standards and deployment notes per artefact"):
        for record in records:
            rec = record.get("recommendation") or {}
            risk = record.get("risk") or {}
            with st.expander(f'{record.get("name")} ({record.get("primitive")}) -> '
                             f'{rec.get("algorithm")}'):
                st.markdown(f'**Action:** {escape(str(rec.get("action")))}')
                st.markdown(f'**Why:** {escape(str(rec.get("justification")))}')
                st.markdown(f'**Rule trace:** `{escape(str(rec.get("rule_trace")))}`')
                st.markdown('**Standard basis:** '
                            f'{escape(", ".join(rec.get("standard_basis") or []) or "n/a")}')
                st.markdown(f'**Size impact:** {escape(str(rec.get("tradeoff_size")))} &nbsp; '
                            f'**Latency impact:** {escape(str(rec.get("tradeoff_latency")))} '
                            f'&nbsp; **Cost band:** {escape(str(rec.get("cost_band")))}')
                if rec.get("hybrid_semantics"):
                    st.markdown(f'**Hybrid semantics:** {escape(str(rec.get("hybrid_semantics")))}')
                if rec.get("ossification_risk", "N/A") != "N/A":
                    st.markdown(f'**Deployment risk:** {escape(str(rec.get("ossification_risk")))}')
                st.markdown(f'**Assurance:** {escape(str(record["assurance"]["reason"]))} '
                            f'&middot; **margin:** {risk.get("margin")} '
                            f'&middot; **latest safe start:** '
                            f'{risk.get("latest_safe_migration_start")}', unsafe_allow_html=True)
                for note in rec.get("notes", []):
                    st.caption(note)

    st.subheader("Export the queue")
    st.caption("Verdict, target, purpose, assurance and the rating inputs travel together, so a "
               "reviewer can recompute the decision instead of trusting the tool.")
    json_download("Download recommendations (JSON)",
                  recommendations_payload(records, target=scan["target"], policy=policy,
                                          z_years=z_years),
                  "ecdat_recommendations")


# ---------------------------------------------------------------------------------------------
# View 4 -- STANDARDS & COMPLIANCE (policy deadlines, and a CBOM proven conformant on screen)
# ---------------------------------------------------------------------------------------------

def view_compliance(scan, records, policy, z_years):
    from engine.cbom import generate_cbom

    this_year = datetime.date.today().year
    active = POLICY_DEADLINES.get(policy, {})
    deadline = active.get("year")
    late = late_records(records, deadline)
    unrated = unrated_records(records, deadline)
    hndl = hndl_records(records)

    st.subheader("Quantum-readiness against the active policy")
    st.markdown("A deadline is a procurement date published by an authority. Z is a cryptanalytic "
                "estimate of when a CRQC may exist. They are different instruments, so they are "
                "shown separately and never merged into one number.")
    metric_row([
        ("Active policy", str(policy), str(active.get("label", ""))),
        ("Deadline", deadline if deadline else "n/a",
         deadline_countdown(deadline, this_year)),
        ("Z (estimate)", f"{z_years} years", z_basis(z_years)),
        ("Artefacts starting too late", len(late),
         "Latest safe migration start falls after the active deadline: start now, or record a "
         "formal exception."),
        ("Could not be rated", len(unrated),
         "No risk verdict available. These are NOT compliant and NOT late -- they are unassessed, "
         "and are shown as UNRATED so the gap stays visible rather than reading as a pass."),
        ("HNDL exposed now", len(hndl),
         "Already decryptable-on-existence. No migration date changes the exposure window."),
    ])

    st.subheader("Deadlines ECDAT reports")
    rows = []
    for key in sorted(POLICY_DEADLINES):
        row = policy_deadline_row(key, this_year)
        row["Active"] = "YES" if key == policy else ""
        rows.append(row)
    dataframe(rows)
    st.caption("Sources are inside this repository: engine/mosca.py POLICY_DEADLINES for the dates, "
               "engine/recommender.py for what each regime requires. Nothing is fetched at runtime.")

    st.subheader("Where the estate stands against the deadline")
    if not records:
        st.info("No findings to compare against the deadline. Check the Evidence view first: an "
                "unreadable tree and a clean one look identical here.")
    else:
        dataframe([{
            "Artefact": r.get("name"),
            "Tier": r.get("tier"),
            "Assurance": r["assurance"]["value"],
            "X+Y": (r.get("risk") or {}).get("x_y"),
            "Z": (r.get("risk") or {}).get("z"),
            "Margin": (r.get("risk") or {}).get("margin"),
            "Latest safe start": (r.get("risk") or {}).get("latest_safe_migration_start"),
            "Deadline": deadline,
            "Verdict": deadline_verdict(r, deadline),
        } for r in records])


    st.divider()
    st.subheader("CycloneDX 1.7 CBOM")
    st.markdown("The CBOM is generated from the same findings, enriched with the Mosca verdict and "
                "the recommendation as `ecd:`-namespaced properties. It is validated against the "
                "published CycloneDX 1.7 JSON Schema **before** the download is offered, against "
                "the copy cached in `schemas/` -- no network call is made at any point.")

    subject = os.path.basename(str(scan["target"]).rstrip("/\\")) or "ECDAT-Scanned-Artefact"
    document = None
    build_error = ""
    try:
        document = json.loads(generate_cbom(records, enriched=True, subject_name=subject,
                                            coverage=scan["coverage"]))
    except Exception as exc:                                    # noqa: BLE001
        build_error = f"{type(exc).__name__}: {exc}"

    if document is None:
        st.error("The CBOM could not be generated for this scan, so no download is offered: "
                 + escape(build_error))
        st.caption("The findings and the coverage manifest are unaffected; use the Evidence view.")
        return

    validation = validate_cbom_document(document)
    colour = "#1F5C3A" if validation["ok"] else (
        "#9A4A06" if validation["state"] == "invalid" else "#8C1D18")
    st.markdown(
        f'<div class="ecdat-callout" style="border-left-color:{colour}">'
        f'<p><b>Schema validation: {escape(validation["state"].upper())}</b></p>'
        f'<p>{escape(validation["message"])}</p></div>', unsafe_allow_html=True)
    if validation.get("schema_id"):
        st.caption(f'Schema: {validation["schema_id"]} (loaded from '
                   f'{os.path.basename(validation["schema_path"])}). '
                   f'Repeat the check from the shell with:  '
                   f'python validate_cbom.py ecdat_report.json')

    if validation["errors"]:
        st.error(f'{len(validation["errors"])} schema error(s), first 25 shown:')
        dataframe(validation["errors"])

    if validation["ok"]:
        json_download("Download CBOM (CycloneDX 1.7 JSON)", document, "ecdat_report")
    else:
        st.warning("Download withheld: this document has not been proven conformant, and an "
                    "unvalidated CBOM is not evidence. The validation result above says why.")

    with st.expander("CBOM document, verbatim"):
        st.json(document)
    st.caption(f'{validation["component_count"]} component(s); the coverage manifest is embedded '
               f'as ecd: metadata properties, so the CBOM carries the honesty claims too.')


# ---------------------------------------------------------------------------------------------
# Shell: header, sidebar, failure states, role dispatch
# ---------------------------------------------------------------------------------------------

def render_no_streamlit():
    """The one state that cannot be rendered in the console itself: no console to render in.

    Printed rather than raised, so a fresh clone without Streamlit gets an instruction instead
    of an ImportError traceback.
    """
    print("=" * 78)
    print("ECDAT console -- Streamlit is not available in this environment.")
    print(f"  import error: {STREAMLIT_IMPORT_ERROR or 'streamlit is not installed'}")
    print("  install it with:  pip install streamlit")
    print("  then run:         streamlit run app.py")
    print("")
    print("  The engine needs no UI and no Streamlit. From the command line:")
    print("      python cli.py <target> --format cbom --out reports/")
    print("      python validate_cbom.py reports/ecdat_report.json")
    print("=" * 78)


def render_pre_scan(role):
    """What the console promises before any target is scanned. This is also the panel a judge
    sees first, so it states the honesty contract rather than showing an empty dashboard."""
    st.subheader("Start with a target")
    st.markdown(
        "Point the scanner at a directory, a single file, or a container-image tarball, then run "
        "the scan. Every number on every page comes from that one scan, and the console keeps "
        "showing what it could not read.")
    st.markdown("#### The four views, and who each is for")
    st.markdown("\n".join([
        "- **Evidence & Honesty** - findings *and* proven use, the assurance histogram, files seen "
        "vs read vs refused, every scan error with its reason, and the never-in-scope list. The "
        "default view, because this is the part other tools bury.",
        "- **Auditor** - every finding with its risk tier, the X/Y/Z arithmetic, the rule that "
        "fired and the matched text.",
        "- **Migration Planner** - the actionable queue, with the unresolved-purpose findings "
        "listed first and the exact evidence that would resolve each one.",
        "- **Standards & Compliance** - the active policy deadline, the estate against it, and a "
        "CycloneDX 1.7 CBOM validated against the published schema before download.",
    ]))
    callout(
        "<p><b>What this tool will not do:</b> report a bare finding total as if it were a risk "
        "number, name a post-quantum target for a primitive whose purpose the evidence does not "
        "settle, or imply coverage of the things listed under 'never in scope'.</p>", "#1F5C3A")
    st.caption(f"You are viewing: {role}. The view can be changed above; all four read the same "
               f"scan.")


def render_scan_failure(error):
    """A failed scan, explained. No traceback: the operator needs to know what to do next, and an
    internal stack is not that."""
    st.error("The scan did not complete, so there are no findings to report.")
    st.markdown(f'- **Target:** `{escape(str(error.get("target")))}`\n'
                f'- **Failure:** `{escape(str(error.get("message")))}`\n'
                f'- **Stage:** {escape(str(error.get("stage")))}')
    st.markdown("**What to try:**")
    st.markdown("\n".join([
        "- Check that the path exists and is readable by this process: a typo and a permissions "
        "problem look identical from here.",
        "- If the target is a filesystem ECDAT refuses by policy, the reason is in the message "
        "above; the policy lives in engine/fspolicy.py.",
        "- Turn the ML branch off in the sidebar to rule the model out. The rule table needs no "
        "torch.",
        "- Run the same scan from the command line, where the exit code is unambiguous: "
        "`python cli.py <target> --format text`.",
    ]))
    st.caption("A failed scan is not a clean scan. Nothing on this page is evidence about the "
               "target.")


def sidebar():
    """Scan configuration. Every control here changes a number that is labelled with its source."""
    from engine.mosca import DATA_CLASS_LIFETIME, DEFAULT_Z, POLICY_DEADLINES, Z_PRESETS

    st.sidebar.markdown("### Target")
    target = st.sidebar.text_input("Directory, file or container tar", value="./dummy_target",
                                   key="target")
    enable_ml = st.sidebar.checkbox("Enable the PyTorch transformer (supplemental signal)",
                                    value=True, key="enable-ml",
                                    help="A second opinion on top of the rule table. It never "
                                         "sets a risk value, and the Evidence view always reports "
                                         "whether it loaded.")
    run = st.sidebar.button("Run discovery scan", type="primary", key="run")

    st.sidebar.markdown("### Mosca parameters")
    z_years = st.sidebar.slider("Z - years until a CRQC", min_value=1, max_value=30,
                                value=int(DEFAULT_Z), key="z")
    st.sidebar.caption(z_basis(z_years))
    st.sidebar.caption("Z is a cryptanalytic estimate, not a compliance deadline. Policy deadlines "
                       "are reported under Standards & Compliance.")
    policy = st.sidebar.selectbox("Active policy", sorted(POLICY_DEADLINES),
                                  index=sorted(POLICY_DEADLINES).index("india_dst_nqm"),
                                  key="policy")
    st.sidebar.caption(str(POLICY_DEADLINES[policy]["label"]))

    st.sidebar.markdown("### Classification inputs")
    data_class = st.sidebar.selectbox("Data lifetime class (X)", list(DATA_CLASS_LIFETIME),
                                      index=list(DATA_CLASS_LIFETIME).index("operational-record"),
                                      key="data-class")
    st.sidebar.caption(str(DATA_CLASS_LIFETIME[data_class]["note"]))
    x_override = st.sidebar.number_input("Override X (years, 0 = use the class)", min_value=0,
                                         value=0, key="override-x")
    y_override = st.sidebar.number_input("Override Y (years, 0 = use the artefact class)",
                                         min_value=0, value=0, key="override-y")
    st.sidebar.caption("X and Y come from documented tables in engine/mosca.py. They are never "
                       "derived from detector confidence, so a model retrain cannot re-rate the "
                       "estate.")
    st.sidebar.caption("Presets: " + ", ".join(
        f'{name} = {preset["years"]}y' for name, preset in Z_PRESETS.items()))
    return {"target": target, "enable_ml": enable_ml, "run": run, "z": float(z_years),
            "policy": policy, "data_class": data_class, "x": x_override or None,
            "y": y_override or None}


def execute_scan(config):
    """Run the scan the operator asked for and record the outcome in the session.

    Every failure mode lands in `session_state["scan_error"]` with a plain-language stage, so the
    page can explain itself. Nothing raises out of here.
    """
    target = (config["target"] or "").strip()
    if not target:
        st.warning("Enter a target in the sidebar before running a scan.")
        return
    if not os.path.exists(target):
        st.session_state.pop("last_scan", None)
        st.session_state["scan_error"] = {"target": target, "stage": "path check",
                                          "message": "the path does not exist"}
        return
    try:
        with st.spinner(f"Scanning {short_path(target)} ..."):
            # The fingerprint is what makes this memoised call correct rather than merely fast:
            # without it, re-scanning an edited target returns the previous findings and the
            # previous `scanned_at`, i.e. stale evidence presented as a fresh scan.
            st.session_state["last_scan"] = run_scan(target, config["enable_ml"],
                                                    _target_fingerprint(target))
        st.session_state.pop("scan_error", None)
    except Exception as exc:                                    # noqa: BLE001
        st.session_state.pop("last_scan", None)
        st.session_state["scan_error"] = {"target": target, "stage": "scanner",
                                          "message": f"{type(exc).__name__}: {exc}"}


def main():
    """The whole console. Runs only under `__main__`, which is exactly what `streamlit run` does.

    Importing this module must stay side-effect free: `python -c "import app"` is part of the
    acceptance criteria, so nothing above this point touches Streamlit.
    """
    if not STREAMLIT_AVAILABLE:
        render_no_streamlit()
        return

    st.set_page_config(page_title="ECDAT console", layout="wide")
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown('<p class="ecdat-title">ECDAT &mdash; cryptographic discovery console</p>'
                '<p class="ecdat-sub">Enterprise Cryptographic Discovery &amp; Analysis Tool '
                '&middot; Smart India Hackathon 2026 &middot; SIH26164 &middot; every view reads '
                'one scan, and every number is shown with the numbers that qualify it.</p>',
                unsafe_allow_html=True)

    config = sidebar()
    role = st.radio("View the console as", ROLES, horizontal=True, key="role")
    st.divider()

    if config["run"]:
        execute_scan(config)

    error = st.session_state.get("scan_error")
    if error:
        render_scan_failure(error)
        return

    scan = st.session_state.get("last_scan")
    if not scan:
        render_pre_scan(role)
        return

    findings_json = json.dumps(scan["findings"], sort_keys=True, default=str)
    try:
        records = rate_findings(findings_json, config["z"], config["policy"], config["data_class"],
                                config["x"], config["y"])
    except Exception as exc:                                    # noqa: BLE001
        st.error("The findings were read but could not be rated, so no verdict is shown: "
                 f"{type(exc).__name__}: {exc}")
        st.caption("This is a console failure, not a scan result. Nothing on this page is evidence "
                   "about the target.")
        return

    scan_header(scan, records)
    integrity_strip(records, scan["coverage"])
    st.divider()

    if not records:
        st.info("Zero findings. Whether that is good news depends entirely on the coverage "
                "manifest: an unreadable tree produces exactly the same empty result, which is why "
                "Evidence & Honesty is the default view.")

    if role == "Evidence & Honesty":
        view_evidence(scan, records)
    elif role == "Auditor":
        view_auditor(records)
    elif role == "Migration Planner":
        view_planner(scan, records, config["policy"], config["z"])
    else:
        view_compliance(scan, records, config["policy"], config["z"])

    st.divider()
    st.markdown(
        '<div class="ecdat-foot">Exports: coverage manifest (Evidence &amp; Honesty) &middot; '
        'recommendations JSON (Migration Planner) &middot; schema-validated CycloneDX 1.7 CBOM '
        '(Standards &amp; Compliance). Everything renders offline: no CDN, no network call, no '
        'telemetry.</div>', unsafe_allow_html=True)


if __name__ == "__main__":
    main()
