# Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)

This repository contains the prototype for the Smart India Hackathon 2026 Problem Statement: **Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)**.

## Features
1. **Scanning Engine:** Performs static analysis on Python source files to extract cryptographic usage.
2. **CBOM Generator:** Exports standardized CycloneDX v1.6 Cryptographic Bill of Materials (CBOM).
3. **Risk & Classification (Mosca's Theorem):** Automatically calculates Quantum Vulnerability using $X + Y > Z$.
4. **Recommendation Engine:** Suggests PQC Hybrid migration strategies (e.g., ML-KEM, ML-DSA) based on latency and payload size trade-offs.
5. **Interactive Dashboard:** Built with Streamlit for executive and engineering review.

## Installation
```bash
pip install -r requirements.txt
streamlit run app.py
```
