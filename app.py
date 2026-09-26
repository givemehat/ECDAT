"""ECDAT Streamlit dashboard.

Two views over the same scan: an ENGINEER view (provenance, dependency topology, rule traces) and
a COMPLIANCE view (tier counts, policy deadlines, coverage gaps). The split mirrors the two
audiences the brief names: security engineers and non-technical/compliance stakeholders.
"""
import json
import os

import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk, DEFAULT_Z, Z_PRESETS, POLICY_DEADLINES, DATA_CLASS_LIFETIME
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom
from engine.graph import generate_crypto_graph

st.set_page_config(page_title="ECDAT", layout="wide", page_icon="🔐")
st.title("ECDAT — Enterprise Cryptographic Discovery & Analysis Tool")
st.caption("Smart India Hackathon 2026 · SIH26164 · NTRO · Blockchain & Cybersecurity")


@st.cache_resource(show_spinner="Initialising scanner…")
def get_scanner(enable_ml):
    return ECDATScanner(enable_ml=enable_ml)


st.sidebar.header("Configuration")
target_dir = st.sidebar.text_input("Target (directory, file, or container-image tar)", value="./dummy_target")
enable_ml = st.sidebar.checkbox("Enable PyTorch transformer (supplemental signal)", value=True)

st.sidebar.subheader("Mosca parameters")
z_name = st.sidebar.selectbox("Z preset (years until a CRQC)", list(Z_PRESETS), index=1)
z_years = st.sidebar.slider("Z (years)", min_value=1, max_value=30, value=int(Z_PRESETS[z_name]["years"]))
st.sidebar.caption(Z_PRESETS[z_name]["basis"])
policy = st.sidebar.selectbox("Compliance policy", list(POLICY_DEADLINES), index=0)
st.sidebar.caption(POLICY_DEADLINES[policy]["label"])
st.sidebar.caption(
    "Z is a cryptanalytic estimate, not a compliance deadline. Deadlines are shown separately.")

st.sidebar.subheader("Classification overrides")
data_class = st.sidebar.selectbox("Data lifetime class (X)", list(DATA_CLASS_LIFETIME),
                                  index=list(DATA_CLASS_LIFETIME).index("operational-record"))
st.sidebar.caption(DATA_CLASS_LIFETIME[data_class]["note"])
x_override = st.sidebar.number_input("Override X (years, 0 = use class)", min_value=0, value=0)
y_override = st.sidebar.number_input("Override Y (years, 0 = use artefact class)", min_value=0, value=0)

run = st.sidebar.button("Run discovery scan", type="primary")

if not run:
    st.info("Configure the target on the left, then run a scan. "
            "Everything below reflects a single scan at a single point in time.")
    st.stop()

if not os.path.exists(target_dir):
    st.error(f"Target not found: {target_dir}")
    st.stop()

scanner = get_scanner(enable_ml)
with st.spinner("Scanning…"):
    findings = scanner.scan_directory(target_dir)
    coverage = scanner.coverage_manifest()

for f in findings:
    f["data_class"] = data_class
    f["risk"] = calculate_risk(f, user_x=(x_override or None), user_y=(y_override or None),
                               z_collapse_time=z_years, policy=policy)
    f["recommendation"] = get_pqc_recommendation(f)

st.success(f"{len(findings)} cryptographic artefact(s) discovered.")

crit = [f for f in findings if f["risk"]["tier"] == "CRITICAL"]
high = [f for f in findings if f["risk"]["tier"] == "HIGH"]
med = [f for f in findings if f["risk"]["tier"] == "MEDIUM"]
low = [f for f in findings if f["risk"]["tier"] == "LOW"]
hndl = [f for f in findings if f["risk"]["hndl_exposed"]]

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Critical", len(crit))
m2.metric("High", len(high))
m3.metric("Medium", len(med))
m4.metric("Low", len(low))
m5.metric("HNDL exposed now", len(hndl))

st.subheader("Coverage — what this scan did and did not examine")
c1, c2 = st.columns(2)
with c1:
    st.markdown("**Scanned**")
    st.write(f"- Files scanned: **{coverage['files_scanned']}**")
    st.write(f"- Files skipped: **{coverage['files_skipped']}**")
    st.write(f"- Scanners run: `{', '.join(coverage['scanners_run']) or 'n/a'}`")
    st.write(f"- ML engine: `{coverage['ml_reason']}`")
    if coverage["errors"]:
        st.warning("These files could NOT be read. A zero-finding result is not evidence of safety here.")
        st.dataframe(pd.DataFrame(coverage["errors"]), use_container_width=True)
with c2:
    st.markdown("**Never in scope** (need a different sensor or an attestation)")
    for gap in coverage["never_in_scope"]:
        st.write(f"- {gap}")

if hndl:
    st.error(f"**{len(hndl)} artefact(s) are exposed to harvest-now-decrypt-later.** "
             "Traffic or ciphertext captured today is retroactively readable once a CRQC exists, "
             "and migrating later cannot undo that.")

view = st.radio("View", ["Compliance", "Engineer", "Topology", "Recommendations", "CBOM"],
                horizontal=True)

if view == "Compliance":
    st.subheader("Quantum-readiness posture")
    st.write(f"Policy: **{POLICY_DEADLINES[policy]['label']}** — deadline "
             f"**{POLICY_DEADLINES[policy]['year']}** · Z = **{z_years} years**")
    rows = []
    for f in findings:
        r = f["risk"]
        band = r.get("z_band", {})
        rows.append({
            "Artefact": f["name"], "Primitive": f["primitive"], "Tier": r["tier"],
            "HNDL now": "YES" if r["hndl_exposed"] else "",
            "X": r["x"], "Y": r["y"], "X+Y": r["x_y"], "Z": r["z"], "Margin": r["margin"],
            "Z-band": " → ".join(f"{k}:{v}" for k, v in band.items()),
            "Stable across Z": "yes" if r["z_stable"] else "**flips**",
            "Location": f"{f['file']}:{f.get('line')}",
        })
    df = pd.DataFrame(rows).sort_values(["Tier", "Margin"], ascending=[True, False])
    st.dataframe(df, use_container_width=True)

    st.subheader("Why each tier")
    for f in findings:
        r = f["risk"]
        with st.expander(f"{f['name']} — {r['tier']}"
                         + ("  ⚠ HNDL EXPOSED" if r["hndl_exposed"] else "")):
            st.write(f"- **Break model:** {r['break_model']} ({r['threat']})")
            st.write(f"- **Mosca:** X({r['x']}) + Y({r['y']}) = {r['x_y']} vs Z({r['z']}) → "
                     f"margin {r['margin']} → **{r['tier']}**")
            st.write(f"- **Z-band:** {r.get('z_band')} (stable across the window: {r['z_stable']})")
            st.write(f"- **X came from:** {r['x_reason']}")
            st.write(f"- **Y came from:** {r['y_reason']}")
            st.write(f"- **Recommendation:** {f['recommendation']['algorithm']} — "
                     f"{f['recommendation']['action']}")

elif view == "Engineer":
    st.subheader("Findings with provenance")
    rows = [{
        "File": f["file"], "Line": f.get("line"), "Artefact": f["name"],
        "Primitive": f["primitive"], "Key size": f.get("key_length", ""),
        "Uses": f.get("uses", ""), "Evidence": f.get("evidence_class", ""),
        "Rule": f.get("rule_id", ""), "Scanner": f.get("scanner", ""),
        "Detector confidence": f.get("dl_confidence", ""),
        "AST depth": f.get("ast_depth", ""),
    } for f in findings]
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    st.caption("Rule IDs map 1:1 to the detection table in engine/scanner.py (RULES).")

elif view == "Topology":
    st.subheader("Cryptographic topology")
    st.caption("Edges are 'uses'. A library finding is presence evidence, not proof that a "
               "consumer calls it.")
    components.html(generate_crypto_graph(findings), height=650, scrolling=False)

elif view == "Recommendations":
    st.subheader("PQC / hybrid recommendations")
    for f in findings:
        rec = f["recommendation"]
        with st.expander(f"{f['name']} ({f['primitive']}) → {rec['algorithm']}"):
            st.write(f"**Action:** {rec['action']}")
            st.write(f"**Why:** {rec['justification']}")
            st.write(f"**Rule:** `{rec['rule_trace']}`")
            st.write(f"**Standard basis:** {', '.join(rec['standard_basis']) or 'n/a'}")
            st.write(f"**Size impact:** {rec['tradeoff_size']}")
            st.write(f"**Latency impact:** {rec['tradeoff_latency']}")
            st.write(f"**Cost band:** {rec['cost_band']}")
            if rec.get("hybrid_semantics"):
                st.write(f"**Hybrid semantics:** {rec['hybrid_semantics']}")
            if rec.get("ossification_risk", "N/A") != "N/A":
                st.write(f"**Deployment risk:** {rec['ossification_risk']}")
            for note in rec.get("notes", []):
                st.caption(note)

else:
    st.subheader("CycloneDX v1.7 CBOM")
    st.caption("Validates against the published 1.7 schema: "
               "`python validate_cbom.py ecdat_report.json`")
    doc = generate_cbom(findings, enriched=True,
                        subject_name=os.path.basename(target_dir.rstrip("/\\")),
                        coverage=coverage)
    st.download_button("Download CBOM (JSON)", "ecdat_report.json", "application/json", doc)
    st.download_button("Download recommendations (JSON)", "ecdat_recommendations.json",
                       "application/json",
                       json.dumps([{"artefact": f["name"], "risk": f["risk"],
                                    "recommendation": f["recommendation"]} for f in findings],
                                  indent=2))
    st.download_button("Download coverage manifest", "ecdat_coverage.json", "application/json",
                       json.dumps(coverage, indent=2))
    st.json(json.loads(doc))

