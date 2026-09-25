import streamlit as st
import pandas as pd
import json
import os
from engine.scanner import scan_directory
from engine.mosca import calculate_risk
from engine.recommender import get_recommendation
from engine.cbom import generate_cbom

st.set_page_config(page_title="ECDAT Dashboard", layout="wide")

st.title("ECDAT: Enterprise Cryptographic Discovery & Analysis Tool")
st.markdown("Smart India Hackathon 2026 - PQC Migration Prototype")

# Sidebar for controls
with st.sidebar:
    st.header("Configuration")
    target_dir = st.text_input("Target Directory to Scan", value="./dummy_target")
    
    st.subheader("Mosca's Theorem Parameters")
    st.markdown("Formula: $X + Y > Z$")
    z_time = st.slider("Z (Years to Quantum Computer)", min_value=1, max_value=20, value=8)
    
    default_x = st.number_input("Default X (Data Shelf Life)", value=10)
    default_y = st.number_input("Default Y (Migration Time)", value=2)
    
    scan_btn = st.button("Run Discovery Scan", type="primary")

if scan_btn:
    if not os.path.exists(target_dir):
        st.error(f"Directory {target_dir} not found!")
    else:
        with st.spinner("Scanning directory for cryptographic primitives..."):
            findings = scan_directory(target_dir)
            
        if not findings:
            st.warning("No cryptographic assets found in the target directory.")
        else:
            # Enrichment phase
            enriched_findings = []
            for f in findings:
                # Mocking logic: assigning higher X for AES (assume DB) and lower for RSA (assume transit)
                x = 25 if f.get('name') == 'AES' else default_x
                y = default_y
                
                f['risk'] = calculate_risk(f, x, y, z_time)
                f['recommendation'] = get_recommendation(f, f['risk'])
                enriched_findings.append(f)
                
            st.success(f"Discovered {len(findings)} cryptographic assets!")
            
            # --- TABS ---
            tab1, tab2, tab3 = st.tabs(["📊 Executive Dashboard (Risk Heatmap)", "📋 Asset Inventory & Remediation", "📦 CycloneDX CBOM"])
            
            with tab1:
                st.subheader("Quantum Risk Distribution")
                col1, col2, col3 = st.columns(3)
                
                critical_count = sum(1 for f in enriched_findings if f['risk']['tier'] == 'CRITICAL')
                high_count = sum(1 for f in enriched_findings if f['risk']['tier'] == 'HIGH')
                low_count = sum(1 for f in enriched_findings if f['risk']['tier'] in ['LOW', 'MEDIUM'])
                
                col1.metric("Critical Quantum Risk", critical_count)
                col2.metric("High Quantum Risk", high_count)
                col3.metric("Low/Medium Risk", low_count)
                
                # Table for executive view
                df = pd.DataFrame([{
                    "Artefact": f['file'].split('/')[-1],
                    "Algorithm": f['name'],
                    "X (Data Life)": f['risk']['x'],
                    "Y (Migration)": f['risk']['y'],
                    "X+Y > Z (Worry?)": f['risk']['is_vulnerable'],
                    "Risk Tier": f['risk']['tier']
                } for f in enriched_findings])
                
                st.dataframe(df.style.applymap(
                    lambda v: 'background-color: #ff4b4b' if v == 'CRITICAL' else ('background-color: #ff9f36' if v == 'HIGH' else ''),
                    subset=['Risk Tier']
                ), use_container_width=True)
                
            with tab2:
                st.subheader("Remediation Engine")
                for f in enriched_findings:
                    with st.expander(f"{f['name']} found in {f['file']} ({f['risk']['tier']})"):
                        rc, rcol1, rcol2 = st.columns([1, 2, 2])
                        with rcol1:
                            st.markdown("**Risk Analysis:**")
                            st.write(f"- **Threat:** {f['risk']['threat']}")
                            st.write(f"- **Mosca Score:** $X({f['risk']['x']}) + Y({f['risk']['y']}) = {f['risk']['x_y']}$")
                            st.write(f"- **Vulnerable Before Z({z_time})?** {'Yes' if f['risk']['is_vulnerable'] else 'No'}")
                        with rcol2:
                            st.markdown("**PQC Recommendation:**")
                            st.write(f"- **Action:** {f['recommendation']['action']}")
                            st.write(f"- **Target Algorithm:** {f['recommendation']['algorithm']}")
                            st.write(f"- **Latency Trade-off:** {f['recommendation']['tradeoff_latency']}")
                            st.write(f"- **Payload Trade-off:** {f['recommendation']['tradeoff_size']}")
                            
            with tab3:
                st.subheader("CycloneDX v1.6 CBOM")
                cbom_json = generate_cbom(enriched_findings, enriched=True)
                st.download_button(
                    label="Download CBOM JSON",
                    file_name="ecdat_cbom.json",
                    mime="application/json",
                    data=cbom_json
                )
                st.json(json.loads(cbom_json))
