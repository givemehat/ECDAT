import streamlit as st
import pandas as pd
import json
import os
import streamlit.components.v1 as components
import networkx as nx
import matplotlib.pyplot as plt
from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk
from engine.recommender import get_recommendation
from engine.cbom import generate_cbom
from engine.graph import generate_crypto_graph

st.set_page_config(page_title="ECDAT Dashboard", layout="wide", page_icon="🔐")

st.title("ECDAT: Enterprise Cryptographic Discovery & Analysis Tool")
st.markdown("Smart India Hackathon 2026 - Advanced Deep Learning Prototype")

@st.cache_resource
def get_scanner():
    # Cache the scanner so the PyTorch model isn't reloaded on every button click
    return ECDATScanner()

scanner = get_scanner()

# Sidebar for controls
with st.sidebar:
    st.header("Configuration")
    target_dir = st.text_input("Target Directory to Scan", value="./dummy_target")
    
    st.subheader("Mosca's Theorem Parameters")
    st.markdown("Formula: $X + Y > Z$")
    z_time = st.slider("Z (Years to Quantum Computer)", min_value=1, max_value=20, value=8)
    
    st.markdown("*(Note: X and Y are now dynamically calculated by the AI using AST Depth & Confidence, but you can override them below)*")
    override_x = st.number_input("Override X (0 for AI-driven)", value=0)
    override_y = st.number_input("Override Y (0 for AI-driven)", value=0)
    
    scan_btn = st.button("Run Deep Discovery Scan", type="primary")

if scan_btn:
    if not os.path.exists(target_dir):
        st.error(f"Directory {target_dir} not found!")
    else:
        with st.spinner("Initializing Multi-Modal PyTorch Engine and Scanning..."):
            findings = scanner.scan_directory(target_dir)
            
        if not findings:
            st.warning("No cryptographic assets found in the target directory.")
        else:
            # Enrichment phase using AI metrics
            enriched_findings = []
            for f in findings:
                x_val = override_x if override_x > 0 else None
                y_val = override_y if override_y > 0 else None
                
                f['risk'] = calculate_risk(f, x_val, y_val, z_time)
                f['recommendation'] = get_recommendation(f, f['risk'])
                enriched_findings.append(f)
                
            st.success(f"Discovered {len(findings)} cryptographic assets using AI Engine!")
            
            # --- TABS ---
            tab1, tab2, tab3, tab4, tab5 = st.tabs(["📊 Risk Heatmap", "🧠 Deep Learning Analysis", "🕸️ Topology", "📋 Remediation", "📦 CBOM"])
            
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
                    "X+Y > Z": f['risk']['is_vulnerable'],
                    "Risk Tier": f['risk']['tier']
                } for f in enriched_findings])
                
                st.dataframe(df.style.applymap(
                    lambda v: 'background-color: #ff4b4b' if v == 'CRITICAL' else ('background-color: #ff9f36' if v == 'HIGH' else ''),
                    subset=['Risk Tier']
                ), use_container_width=True)
                
            with tab2:
                st.subheader("Multi-Modal AI Inference Results")
                st.markdown("Here you can see the inner workings of our Transformer model. It extracts the AST (Abstract Syntax Tree) depth to estimate Migration Complexity (Y), and assigns a Neural Network confidence score.")
                
                ai_df = pd.DataFrame([{
                    "File": f['file'].split('/')[-1],
                    "AI Prediction": f['name'],
                    "Neural Confidence": f"{f.get('dl_confidence', 0)*100:.2f}%",
                    "AST Code Depth": f.get('ast_depth', 0),
                    "Derived Y (Migration)": f['risk']['y']
                } for f in enriched_findings])
                
                st.dataframe(ai_df, use_container_width=True)
                
            with tab3:
                st.subheader("Interactive Cryptographic Topology")
                st.markdown("This graph shows how cryptographic primitives are distributed across your application. Red nodes indicate CRITICAL quantum risks.")
                graph_html = generate_crypto_graph(enriched_findings)
                components.html(graph_html, height=650, scrolling=False)
                
            with tab4:
                st.subheader("Remediation Engine")
                for f in enriched_findings:
                    with st.expander(f"{f['name']} in {f['file'].split('/')[-1]} ({f['risk']['tier']})"):
                        rc, rcol1, rcol2 = st.columns([1, 2, 2])
                        with rcol1:
                            st.markdown("**AI Risk Analysis:**")
                            st.write(f"- **Threat:** {f['risk']['threat']}")
                            st.write(f"- **Mosca Score:** $X({f['risk']['x']}) + Y({f['risk']['y']}) = {f['risk']['x_y']}$")
                            st.write(f"- **AI Confidence:** {f.get('dl_confidence', 0)*100:.1f}%")
                        with rcol2:
                            st.markdown("**PQC Recommendation:**")
                            st.write(f"- **Action:** {f['recommendation']['action']}")
                            st.write(f"- **Target Algorithm:** {f['recommendation']['algorithm']}")
                            st.write(f"- **Latency Trade-off:** {f['recommendation']['tradeoff_latency']}")
                            st.write(f"- **Payload Trade-off:** {f['recommendation']['tradeoff_size']}")
                            
            with tab5:
                st.subheader("CycloneDX v1.6 CBOM")
                cbom_json = generate_cbom(enriched_findings, enriched=True)
                st.download_button(
                    label="Download CBOM JSON",
                    file_name="ecdat_cbom.json",
                    mime="application/json",
                    data=cbom_json
                )
                st.json(json.loads(cbom_json))
