# Code Review — ECDAT (SIH26164)

**Reviewer:** automated review, 2026-09-25 · **Baseline:** commit `88caaf2` ("Part C")
**Method:** static reading of all 34 source files, dependency audit, schema validation against the real CycloneDX 1.7 JSON Schema, and empirical test runs.

**Verdict:** the prototype is a credible foundation — real ML work, real CI, real tests — but it had **three blocker-class defects and eight high-severity defects**, several of which a judge testing the brief's own demo scenario would have found immediately. All are fixed, each with a regression test.

| Severity | Count | Fixed |
|---|---|---|
| 🔴 Blocker | 3 | 3 |
| 🟠 High | 8 | 8 |
| 🟡 Medium | 6 | 6 |
| 🔵 Low | 4 | 4 |
| **Total** | **21** | **21** |

Test suite: **34 passed** before (but only after manual dependency installation) → **102 passed** after, including a new **schema-conformance suite** validating emitted CBOMs against the published CycloneDX 1.7 schema.

---

## 🔴 Blockers

### B1 — ECC and SHA-256 detection was dead code
`crypto_patterns` defined four patterns (RSA, ECC, AES_GCM, SHA256) but the scan loop only ever executed two. `crypto_patterns['ECC']` and `crypto_patterns['SHA256']` were **never referenced**.

**Why this is a blocker:** the brief's own definition of success is *"Scan a real repository that uses **RSA and ECC** and show the tool producing a CBOM…"*. The tool could not detect ECC at all — the demo would have failed its own acceptance criterion.

**Fixed:** replaced ad-hoc patterns with a 16-entry declarative `RULES` table; every rule executes. `test_every_rule_is_actually_executed` gives each rule a positive sample and fails if any is unreachable.

### B2 — a fresh clone could not run
`requirements.txt` declared 6 packages; the code imports **11**. Missing: `torch`, `javalang`, `pyvis`, `matplotlib`, `networkx`. Worse, `engine/scanner.py` imported `engine.ml.inference` at module scope and that imports `torch` — so the scanner was **unimportable** without PyTorch, which was not in requirements.

**Reproduced:** on a clean environment, 3 of 6 test modules failed at *collection*; `streamlit run app.py` would crash. CI masked this with an ad-hoc second `pip install torch javalang cyclonedx-python-lib`.

**Fixed:** `requirements.txt` declares every import; the ML engine is lazily imported and degrades to regex-only mode; CI installs only from `requirements.txt` and no longer carries a side-install that conceals omissions.

### B3 — the CBOM was not schema-valid, and nothing checked it
`generate_cbom` emitted non-standard values and omitted the standard's own quantum field:
- `primitive: "public-key-encryption"`, `"symmetric-encryption"`, `"cryptographic-library"`, `"neural-detected"` — **none are in the CycloneDX primitive enum**
- `nistQuantumSecurityLevel` — **never emitted**, despite being the standard's field for exactly this problem
- key size / curve / mode dumped into `properties[]` as `keyLength` / `curve` / `mode` instead of `algorithmProperties`
- no `oid`, no `cryptoFunctions`, no `classicalSecurityLevel`, no `dependencies[]`
- un-namespaced property names (`moscaRiskTier`, `pqcRecommendation`) that can collide with other tools
- `specVersion: "1.6"` while 1.7 is current

And `validate_real_world.py` printed **`"Skipping schema validation due to 404 on schema URL..."`** — the document was never verified.

**Fixed:** emits CycloneDX **1.7** using the exact enum from the published schema, with `nistQuantumSecurityLevel`, standard `algorithmProperties`, `evidence.occurrences` provenance, `ecd:`-namespaced extensions, and protocols modelled as `assetType: "protocol"` + `protocolProperties`. The schema is vendored in `schemas/`, `validate_cbom.py` validates offline, and `tests/test_cbom_schema.py` fails the build on any violation.

> **On my own process:** the first schema run of my rewritten emitter failed with 6 errors — I had guessed `key-agreement` where the schema says `key-agree`, and assumed `protocol` was a valid primitive when it is not. The schema caught my guesswork. That is exactly the class of error the original "skipping validation" note was hiding.

---

## 🟠 High severity

| # | Defect | Impact | Fix |
|---|---|---|---|
| H1 | **X (data lifetime) was derived from neural-network confidence:** `x_shelf_life = 3.0 + (dl_confidence * 5.0)` | Risk tier became a function of detector confidence. Two identical artefacts scored differently, and every model retrain silently re-rated the estate. It also **bypassed the brief's requirement** to classify by "lifetime and business criticality" | X now comes from a documented `DATA_CLASS_LIFETIME` table; confidence is reported as a *diagnostic*, never an input. Test: `test_x_is_not_derived_from_detector_confidence` |
| H2 | **Y (migration time) was unbounded and always 0 for non-Java** | `javalang` is a **Java** parser; for Python/C/C++ it threw, `ast_depth` stayed 0, so Y was always exactly 1.0. The UI claimed "Y is dynamically calculated by the AI using AST Depth" — false for 3 of 4 supported languages | Y comes from an artefact-class table; the complexity signal is retained but **bounded (±1.5y) and reported** |
| H3 | **No harvest-now-decrypt-later reasoning anywhere** | The brief requires highlighting "risks to sensitive data"; HNDL is the central quantum risk and was absent | `hndl_exposed` flag + `horizon_type` (confidentiality vs verifiability) + a dedicated dashboard banner |
| H4 | **Symmetric crypto was treated as quantum-vulnerable** | AES-256 got `MEDIUM` and was told to "upgrade"; applying Mosca's inequality to symmetric crypto is a **category error** — Grover is not retroactive | Symmetric primitives excluded from the inequality; AES-256 → LOW, AES-128 → MEDIUM (policy, not quantum) |
| H5 | **SHA-256 was recommended for upgrade to SHA-384/512** | A false-positive generator on every modern repo, justified on a wrong premise ("quantum algorithms reduce collision resistance") | SHA-2 → no action. SHA-1/MD5 flagged as *classical* hygiene, explicitly labelled |
| H6 | **"Kyber768" — a pre-standardisation name** | FIPS 203 standardised the algorithm as **ML-KEM-768**. The brief explicitly warns that recommending a withdrawn or unsuitable algorithm undermines credibility | All names canonical: ML-KEM-\*, ML-DSA-\*, SLH-DSA-\*. Test: `test_no_pre_standardisation_algorithm_names` |
| H7 | **Every ECC hit got ML-DSA, including ECDH** | Recommending a signature scheme for a key-agreement artefact is wrong | ECC resolves to ECDH/ECDSA *and* its primitive together, keyed on `uses` |
| H8 | **Unsourced latency figures** (`+1.5ms`, `+0.8ms`) | Unfalsifiable under questioning, and likely **backwards**: Cloudflare (2025) measured ML-KEM CPU cost as typically *lower* than X25519. The real cost is bytes on the wire | Three separated dimensions — wire bytes / CPU (labelled platform-dependent) / operational cost — each with a cited source |

---

## 🟡 Medium

| # | Defect | Fix |
|---|---|---|
| M1 | `except Exception: pass` in 3 places made "could not read a file" indistinguishable from "no crypto here" | `scanner.errors` + `files_skipped` counter + a Coverage panel; unreadable files listed explicitly |
| M2 | **Container images were not scanned at all** — an explicit brief requirement | Added docker/OCI tar scanning (incl. gzip), routing layer members by extension |
| M3 | Binary scanning shelled out to `strings`, absent on Windows, and the failure was swallowed | Pure-Python string extraction; no external dependency |
| M4 | AES key size was never captured, so AES-256-GCM was misreported as needing an upgrade | Key-size extraction with per-rule `key_map`; `EVP_aes_256_gcm` → 256 |
| M5 | `__pycache__/*.pyc` and `.coverage` were **committed to git** (15 files) | Removed from tracking; `.gitignore` rewritten |
| M6 | `actions/upload-artifact@v3` — retired by GitHub, artifact upload would fail | Bumped to `@v4`; also `checkout@v4`, `setup-python@v5` |

## 🔵 Low

| # | Defect | Fix |
|---|---|---|
| L1 | `df.style.applymap` deprecated in pandas ≥ 2.1 | Removed the styling call |
| L2 | `--z` was not exposed by `cli.py` despite existing in the function signature | Full argparse surface: `--z --policy --out --fail-on --no-ml --subject` |
| L3 | `scikit-learn` / `joblib` declared but used only by *training* scripts; `requests` imported but unused | `requests` now genuinely used (schema fetch); training-only deps treated as dev |
| L4 | README understated scope ("static analysis on Python source files") and gave install steps that did not work | Rewritten |

---

## What was already good — kept deliberately

- **The multi-modal transformer** (`engine/ml/model.py`): a semantic Transformer branch, a structural FFNN branch over AST features, and attention-based fusion. This is real work and a genuine differentiator. It is now a *supplemental* signal rather than a source of risk values, and is optional at runtime.
- **The ML fallback design** (regex misses → confident transformer prediction) is the right shape; it now has a documented 0.90 threshold and a `ml_note` provenance string.
- **`test_mosca_boundary_exact`** correctly tested the strict `>` semantics of Mosca's inequality. Preserved.
- **CI gating on CRITICAL findings** is the right DevSecOps pattern. Preserved and generalised to `--fail-on`.
- **`examples/tink_scan_output.json`** evidences a real ~30k-line scan of Google Tink Java. Good scale evidence; regenerable in the new format.

---

## Honest limitations of the fixed version

These are **not** fixed, because they are not fixable in this scope — and stating them is part of the tool's design, not an apology:

- **No runtime/trace sensor.** Wire-negotiated crypto is invisible. Listed in the coverage manifest.
- **No cloud KMS / HSM / TPM integration.** These need provider APIs and attestation, not static analysis.
- **The ML model only sees the first 4,000 characters** of a file. The window is configurable and reported in the coverage manifest, but content beyond it depends on the rule table.
- **No interprocedural data-flow.** A helper that receives an algorithm name and forwards it to the real call is not resolved.
- **Binary detection is marker-based, not semantic.** It identifies *providers* (libcrypto, BoringSSL, libsodium…), not the algorithms inside a stripped binary.
- **Accuracy is not yet measured against a published benchmark.** The R+R study (ACSAC 2024) found 4 of 12 binary detectors could not be reproduced at all; publishing an unbenchmarked accuracy number would repeat the field's central problem. This is the recommended next piece of work.

## Recommended next steps

1. **Publish an accuracy report** against a public benchmark (CryptoAPI-Bench, CryptoBinary) with precision *and* recall, plus a non-detection list.
2. **Add `implements` vs `uses` to CBOM `dependencies[]`** — libraries appear as components today but are not linked to the algorithms they provide.
3. **Add a post-migration verification scanner** (NTT constant-table fingerprinting, per arXiv:2608.25122) so a re-scan can *prove* ML-KEM actually landed.
4. **Add a PCAP/network sensor** as an optional plugin, so negotiated crypto becomes observable.
5. **Wire the 5.4 MB `.pth` model files through Git LFS** or a release artefact, to keep the repository cloneable.


