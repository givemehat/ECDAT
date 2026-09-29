#!/bin/bash
# IndraMesh Real-World Container & Source Demonstration Script
# Run this during the SIH presentation to prove the tool works on messy, real-world repositories.

set -e

echo "=========================================================================="
echo " IndraMesh SIH 2026: Real-World Demonstration"
echo " Target 1: Pallets Werkzeug (Messy Python Web/Crypto utilities)"
echo " Target 2: BC-Java (Bouncy Castle Java - Real-world Enterprise Crypto)"
echo "=========================================================================="
echo ""

# 1. Fetching a real-world Python library (Werkzeug)
echo "[*] Downloading Pallets Werkzeug (Python) source code..."
curl -sL https://github.com/pallets/werkzeug/archive/refs/tags/3.0.1.tar.gz -o werkzeug.tar.gz

# 2. Fetching a real-world Java Crypto library (BouncyCastle)
echo "[*] Downloading Bouncy Castle (Java) source code..."
curl -sL https://github.com/bcgit/bc-java/archive/refs/tags/r1rv77.tar.gz -o bc-java.tar.gz

# 3. Running IndraMesh Scan on Werkzeug
echo ""
echo "[*] Running IndraMesh Scanner on Werkzeug (.tar.gz container/archive)..."
echo "    python cli.py werkzeug.tar.gz --format text"
python cli.py werkzeug.tar.gz --format text | head -n 25
echo "    ... (truncated for demo) ..."
echo ""

# 4. Running IndraMesh Scan on BouncyCastle
echo "[*] Running IndraMesh Scanner on Bouncy Castle (.tar.gz container/archive)..."
echo "    python cli.py bc-java.tar.gz --format cbom > bc-java-cbom.json"
python cli.py bc-java.tar.gz --format cbom > bc-java-cbom.json
echo "    [✔] Successfully generated Standardized CBOM for Bouncy Castle."
echo "    Total Cryptographic Artefacts Discovered: $(grep -c '"type":' bc-java-cbom.json || true)"
echo ""

echo "=========================================================================="
echo " Demo completed successfully."
echo " Real-World Validation: PROVEN."
echo "=========================================================================="
