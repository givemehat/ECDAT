# Competitive Analysis — SIH26164 (ECDAT)

**Method.** 24 GitHub Search API queries → **349 unique repositories** scraped → relevance-scored
against the four brief requirements → **119 shortlisted** → README + metadata fetched for the
**17 most relevant**. Every claim is traceable: raw API responses in `raw/`, shortlist in
`shortlist.csv`, README text in `raw_readme/`, metadata in `repos.json`. Re-runnable:
`scrape_github.py` → `filter.py` → `fetch_readmes.py`.

**Caveat.** GitHub *repository* search does not support parentheses or boolean `OR`; an early attempt
with `(a OR b)` silently degraded to an unfiltered search and returned DeFiHackLabs and an IoT list
for a "Mosca AND quantum" query. All queries are therefore single conjunctions, with coverage coming
from many narrow queries plus `topic:` qualifiers. **6 of 24 queries hit the unauthenticated rate
limit** and returned no data — all in the `in:description` slice; the `topic:` and `in:readme`
slices succeeded, so competitor coverage is good but not provably complete.

---

## 1. The most important finding: this problem is already being built

**At least two other teams are on SIH26164 right now**, and one is well ahead of us in engineering
discipline. This is the single most useful thing the scrape produced.

| | Repo | Team | Commits | Stars | Stack | Artefact coverage |
|---|---|---|---|---|---|---|
| **Sibling A** | [`sgtsujith141-wq/cryptodrishti`](https://github.com/sgtsujith141-wq/cryptodrishti) | Zero-Day (146876) | 27 | 1 | Python 3.11, FastAPI, vanilla-JS console, SQLite | **7 sensors**: source (Python AST + 6 rule packs), dependencies (13 manifests), binaries (ELF), certificates (X.509/KeyUsage), config, container (OCI layout/tar/`docker save`), **live TLS handshake** |
| **Sibling B** | [`saitharunpotluri-creator/ECDAT`](https://github.com/saitharunpotluri-creator/ECDAT) | — | 3 | 2 | Next.js + FastAPI + Semgrep | Source only |

Sibling A is the one to study: **664 tests** (we have 102), an architecture diagram, a benchmark
corpus, a 6-slide deck, two demo films, a presenter script and a Q&A sheet — i.e. it already manages
the *whole* SIH deliverable, not just the code.

**What this changes.** Our differentiation cannot be "we scan source, binaries and containers" —
sibling A does that and more. It has to be narrower, defensible, and we must be honest about being
behind on test breadth and submission assets.

---

## 2. Single-repo analysis — CryptoDrishti (sibling A), the benchmark to beat

### What it does better than we do

| # | Capability | Evidence from their README | Our gap |
|---|---|---|---|
| C1 | **Assurance taxonomy separate from confidence** — `capability` (reachable, nothing shows it is called) · `declared` (config permits it) · `used` (code invokes it) · `observed` (seen in a real artefact) | "Distinct from confidence, which asks whether the identification is correct. A dependency on a library implementing RSA can be a *certain* identification of something that proves very little." They publish `proven_use` **alongside** the raw total | We have `evidence_class` and conflate *confidence* with *what the evidence proves*. The sharpest idea in the scrape. |
| C2 | **Purpose resolution with a deliberate UNRESOLVED state** | `padding.PSS` / `Signature.getInstance` → signature; `padding.OAEP` / `Cipher.getInstance("RSA/…")` → key establishment; cert `KeyUsage: digitalSignature\|keyCertSign` → signature; `KeyUsage: keyEncipherment\|keyAgreement` → key establishment; **`padding.PKCS1v15`, `GenerateKey`, `KeyPairGenerator`, dual-use KeyUsage → nothing** | "Where the evidence does not settle it, no target is named and the recommendation says what would resolve it. An unresolved finding a human reviews is worth more than a resolved one that is wrong." We always name a target. |
| C3 | **Refuses to estimate latency or cost** | "This tool has never run a benchmark or priced an engineer… Both fields report a status — `not-measured`, `not-estimated` — with the reason. Migration effort is a band, not a number." | We cite third-party figures (defensible) but should carry an explicit status field. This is a *discipline*, not a feature gap. |
| C4 | **Q-Day as a scenario, not a forecast** | The slider sets the *mode* of a triangular distribution; the CBOM emits `assessment:qdayIsForecast = false`. They caught and corrected their own median/mode error (1.6 years, always understating exposure). | We use a point Z + 5/10/15 band. Their probability framing is richer; our band is simpler but honest. |
| C5 | **Security policy modules** — `netpolicy.py` refuses loopback/private/link-local/metadata-endpoint/NAT64-wrapped targets and connects to a vetted literal address to close DNS-rebinding; `fspolicy.py` stops symlinked files escaping the scan root and never reads `shadow`/`.netrc`/`.git-credentials`; refuses to start when bound off-loopback without a token | "The tool takes a filesystem path and a list of hosts over HTTP and acts on both. That is a server-side request forgery primitive and an arbitrary file read unless something stands between the two." | **We have none of this.** Our scanner walks any path and follows symlinked files. A real, exploitable gap in our own tool. |
| C6 | **Live TLS handshake sensor** whose refused probe is reported as *"no hybrid accepted, mechanism not observed"*, never as a specific classical group | "Reading the actual negotiated group needs OpenSSL 3.5+ locally. Without it the key-exchange mechanism stays unobserved rather than being guessed." | We list wire-negotiated crypto as "never in scope". The guessing-resistance is the lesson. |
| C7 | **664 tests on 3 Python versions**; benchmark corpus with committed results; vendored schemas **pinned and checksummed** | "Schema conformance is against a pinned copy… a snapshot. Upstream moves; updating is a deliberate, reviewable change." | We vendor the schema but do not checksum it. |
| C8 | **Differential scans** — track readiness over time, not a snapshot | Their roadmap | We planned this in Phase 2; not built. |

### What it does *worse* than we do

| # | Their gap | Evidence | Our advantage |
|---|---|---|---|
| W1 | **Rule packs, not real parsers** | Their roadmap: "Migrate the seven rule-pack languages to real parsers, and give Rust and Swift rule packs at all (tree-sitter would cover all of them with one dependency)." | We have a 16-rule table **plus a real PyTorch multi-modal transformer** (semantic Transformer + structural FFNN + attention fusion) — the only genuine ML detector we found. |
| W2 | **ELF only for binaries** | "Binary analysis is ELF only." Roadmap: "Mach-O and PE symbol-table parsing." | We scan `.exe`/`.dll`/`.dylib` with pure-Python string extraction on all platforms. |
| W3 | **Containers: local archives only** | "No registry pulls, no Windows images, no zstd layers, no signature or attestation verification." | We are also archive-only, but we do not overclaim. |
| W4 | **Accuracy is synthetic and self-authored** | "**They are not real-world accuracy.** This is a synthetic corpus written by [the author]… a corpus scoring 1.000 is a corpus that needs harder cases, not a finished one." | **The gap we can win honestly:** measure against a *published external* benchmark (CryptoAPI-Bench; CryptoBinary per the ACSAC 2024 R+R study) and publish precision **and** recall. |
| W5 | **Not independently audited** | "The classifications follow NIST IR 8547 and the CycloneDX 1.6 specification as I read them; they have not been reviewed by a cryptographer." | Same for us — which makes the standards-anchored argument necessary rather than optional. |
| W6 | **Guesses when purpose is ambiguous** by assuming the more urgent model | "The unresolved case assumes the *more* urgent model on purpose." | We can do better: refuse the target rather than assume. |

**Assessment.** Sibling A is ahead on engineering discipline, test breadth, sensor count and
submission completeness. We are ahead on detection technique (real ML + rule table vs regex packs)
and platform coverage (PE/Mach-O). **The honest strategic position: we do not win on breadth. We
win on (a) measured accuracy against an external benchmark, (b) a security-hardened scanner, and
(c) a risk engine whose every number is traceable to a published source.**

---

## 3. The wider field — what else exists

| Repo | Stars | Distinctive angle | Take? |
|---|---|---|---|
| `XiantingWu/PQCensus` | **219** | "Evidence-grounded"; **refuses** to run `setup.py`, lifecycle hooks, Makefiles, tests, binaries, containers or arbitrary builds; benchmarks + GitHub Action | ✅ **The refusal posture.** Naming what you will *not* execute is a security property. |
| `mpaymenremora/QuantumSeal` | 96 | Migration *workbench*; ships a **"False positives & limitations"** section; a "CI baseline recipe" | ✅ Publish limitations (we do) and adopt a CI baseline recipe. |
| `jimbo111/open-quantum-secure` | 3 | Live `--enumerate-groups` probing 13 codepoints (classical + hybrid + **pure ML-KEM + deprecated Kyber**), `--enumerate-sigalgs` probing 17 schemes; JAR/wheel/ELF/PE/Mach-O/.NET; **CycloneDX 1.7** | ✅ **Post-migration verification**, separating deprecated Kyber from standardised ML-KEM. Closes Phase-1 **G13**. |
| `Savaid-Khan-Official/Quantum-Migration-Toolkit` | 20 | **Hand-labeled precision on OpenSSH: 96.88% (124/128), all 117 RSA findings true positives**; 9+ languages; regex + tree-sitter; vendored liboqs 0.10+ with rollback manifest | ✅ **The only real-corpus precision number we found.** Our validation template. |
| `Arpan0995/pqc-migration-readiness` | 6 | Precision/recall vs hand-labeled ground truth; **"PQC is not uniformly slower — ML-KEM encapsulate/decapsulate are *faster*"**; JMH campaign | ✅ Independently confirms Phase-1 §4.2. |
| `qubitac/AC-Scanner` | 9 | Live TLS **and SSH**; classifies KEX against PQC-safe patterns; tiers aligned to IR 8547 2030/2035; air-gap friendly | ✅ SSH is a field-wide gap. |
| `csnp/cryptodeps` | 5 | Manifest scanning (Go/npm/Python/Maven); "Context-aware confidence: distinguishes confirmed usage from mere availability"; **"Manifests that cannot be read are named, with the reason, and exit 2"** | ✅ Availability-vs-usage, and named-unreadable + non-zero exit. |
| `CipherIQ/cbom-generator` | 8 | 4-level **SERVICE→PROTOCOL→CIPHER_SUITE→ALGORITHM**; 60 services; **VERNEED/SONAME version extraction from ELF**; break-year column from NIST IR 8413 + CNSA 2.0; CycloneDX 1.6 *and* 1.7 | ✅ The hierarchy and ELF version extraction — both answer the brief's "versions/modes". |
| `Danny-397/Quantum-Safe-Scan` | 3 | "**Measured, not asserted** — a labeled benchmark with **adversarial decoys**"; Flask API; dark dashboard with history and trend | ✅ **Adversarial decoys.** |
| `PQCWorld/pqaudit` | 3 | Tree-sitter AST for JS/TS; Docker crypto-library installs; npm/Cargo/Go/pip/Gradle/Maven manifests | ✅ Manifest formats we lack. |
| `systemslibrarian/crypto-lab-harvest-timeline` | 0 | HNDL risk *simulator*; sibling `crypto-lab-pq-rotation` planner | ⚠️ Simulators are a good demo affordance. |
| `AbstractionsLab/pqc-mat` | 0 | VECTOR-GUI: Flask UI for code + network scans with live terminal output | ⚠️ Live output is a nice demo touch. |
| `quantakrypto/pqc-tools` | 12 | The commercial practice from Phase 1 §3.5, now open-sourced | ✅ Confirms our Phase-1 read. |
| `SiteQ8/miftah` | 0 | "Cryptographic inventory and post quantum readiness. Scans code, certificates…" | — |

**Filtered as non-competitors:** `sbom-tool/sbom-tools` (SBOM diff/quality scoring — mature but not
PQC), `cbomkit/*` (the IBM reference implementation we benchmarked against in Phase 1), and ~120
library implementations of ML-KEM/ML-DSA (crypto *primitives*, not discovery *tools*).

---

## 4. What we should adopt — ranked, with the source of each idea

| Rank | Adoption | From | Why it matters for SIH26164 |
|---|---|---|---|
| **1** | **Adversarial decoy regression suite** | Quantum-Safe-Scan, sib-A | Our false-positive rate is unmeasured. Decoys (comments, docstrings, test fixtures, `my_crypto_helper`, hex blobs) are the cheapest credibility win available. |
| **2** | **Assurance taxonomy** (`capability`/`declared`/`used`/`observed`) + a `proven_use` count | sib-A, cryptodeps | Implements the brief's "evidence" discipline and Phase-1 **G5/G16**. Separates *is the ID right* from *what does this prove*. |
| **3** | **Purpose resolution with UNRESOLVED** | sib-A | Implements Phase-1 **G6**. Stops us recommending ML-DSA for ECDH, or ML-KEM for a signature. |
| **4** | **Filesystem security policy** in our own scanner | sib-A | We are *currently* the vulnerable one: symlink escape, no credential-store skip. A judge running our CLI on a hostile tree would find this. |
| **5** | **Hand-labelled precision on a real corpus** (OpenSSH template) | Quantum-Migration-Toolkit | The only externally-published real-corpus number we found (96.88%, 124/128). Closes Phase-1 **P10/G10**. |
| **6** | **Dependency-manifest sensor** + named-unreadable + non-zero exit | sib-A, cryptodeps, pqaudit | Whole evidence class we have zero coverage of; yields `capability`-tier evidence. |
| **7** | **PQC-presence verification** (standardised ML-KEM vs deprecated Kyber) | open-quantum-secure | Closes Phase-1 **G13**. |
| **8** | **Break-year column** per artefact (2030/2035 from IR 8547 + CNSA 2.0) | cbom-generator | Cheap; directly answers "when must this go?". |
| **9** | **ELF SO-name/VERNEED version extraction** | cbom-generator | The brief demands assets "including **versions**". We detect `libcrypto` but not its version. |
| **10** | **Schema checksum pinning** | sib-A | Upstream drift should be a deliberate PR, not a silent break. |
| **11** | **Service→protocol→cipher-suite→algorithm hierarchy** in `dependencies[]` | cbom-generator | Richer than our flat subject→asset graph. |
| **12** | **Named non-execution posture** ("we do not run setup.py, Makefiles, hooks") | PQCensus | One sentence in the README; a real security property. |

## 5. What we should *not* copy

| Idea | Why not |
|---|---|
| `open-quantum-secure` listing "kyber" among PQC-safe KEX patterns | Deprecated name; Phase-1 **H6**. We standardise on ML-KEM-768 only. |
| A single 0–100 "Quantum Risk Score" (sibling B) | Phase-1 **G11**: a scalar cannot express "exposed now" vs "exposed in 3 years". |
| Assuming the more urgent model for an unresolved purpose | Silent assumption is exactly what we are trying to eliminate. Refuse, and say what would resolve it. |
| Streamlit / heavy SPA for the console | Sibling A's vanilla-JS, zero-dependency, no-CDN console is better engineering for a security tool: no supply chain, air-gap friendly, no runtime CDN fetch. We should consider the same. |
| Emitting `qdayIsForecast=false` while still picking a single year | Our Z-band (5/10/15 + `z_stable`) states instability directly and needs no probability model. |

---

## 6. Strategic position for SIH26164

**Do not compete on breadth.** Sibling A has 7 sensors, 664 tests and a full submission package.
Attacking breadth is a losing move against a team with more time invested.

**Compete on the three things they cannot claim:**

1. **Measured, externally-benchmarked accuracy.** Their README says their figures are for a
   synthetic corpus written by themselves. We can publish precision *and* recall against a named
   external benchmark, plus a non-detection list. That is a different category of claim.
2. **A scanner that is safe to point at an untrusted tree.** Symlink containment, credential-store
   refusal, explicit non-execution posture. Security tooling that reads whatever path it is given is
   a liability; we can be the tool an engineer is willing to run on hostile input.
3. **A risk engine where every number is traceable.** Ours cites FIPS parameter sizes, published
   Cloudflare/rustls measurements, NIST IR 8547 and CNSA 2.0 dates, and reports the Z-band. Every
   figure is a standard, a citation, or an explicit `not-measured`.

**And we must fix fast on:** test breadth (102 → target 300+), the dependency-manifest sensor, and
the decoy suite. Those are the three gaps a judge can check in five minutes.



