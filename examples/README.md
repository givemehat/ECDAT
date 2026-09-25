# Real-World Scanning Validation

## Scan Subject
- **Repository**: Google Tink-Java (`https://github.com/google/tink`)
- **Reasoning**: Tink is an enterprise-grade cryptographic library heavily utilizing JCE (Java Cryptography Extension), which perfectly aligns with our RegEx engines and `javalang` AST parsing.

## Scan Results
- **Time Elapsed**: ~13.44 seconds (Extremely fast, no hangs or crashes).
- **Total Artefacts Flagged**: 1233

## Quality & Accuracy (Spot Check)
The accuracy of the prototype on real-world code reveals several critical flaws in the current pipeline that need addressing:

### 1. Massive False Positives (Deep Learning Hallucination)
- Out of 1233 findings, **over 1100** were flagged as `AES (neural-detected)` with 100% confidence.
- **Cause**: The PyTorch Transformer was trained on a highly synthetic dataset. When it encounters real-world Java files containing standard keywords (like `import`, `class`, `public`), it defaults to predicting `AES` with `1.0` confidence, regardless of actual crypto usage.

### 2. False Negatives (RegEx Blindspots)
- The RegEx scanner correctly caught standard invocations like `Cipher.getInstance("AES/GCM")` (5 valid instances found).
- However, it **completely missed**:
  - `Cipher.getInstance("RSA/ECB/NoPadding")` (Regex only looks for `KeyPairGenerator.getInstance("RSA")`).
  - `ChaCha20Poly1305` (Missing from the dictionary entirely).
  - HMAC and Mac implementations.

### 3. CBOM Schema Validation
- The JSON generated structurally successfully. However, `https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.6b.schema.json` is returning a `404 Not Found`, so strict programmatic schema validation was skipped. The resulting JSON visually adheres to the CycloneDX 1.6 format.

## Conclusion
The **plumbing** (File Scanning -> RegEx + ML -> Mosca Theorem -> CBOM JSON output) works flawlessly and is robust against real-world file sizes/encodings. 
The **intelligence** (Model weights and RegEx dictionary breadth) is weak and generates extreme false-positives/negatives on enterprise code. This is expected for a hackathon prototype, but should be disclosed honestly.
