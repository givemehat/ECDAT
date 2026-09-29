# IndraMesh

**Enterprise Cryptographic Discovery & Analysis Tool**

[![Tests](https://github.com/givemehat/IndraMesh/actions/workflows/tests.yml/badge.svg)](https://github.com/givemehat/IndraMesh/actions/workflows/tests.yml)
[![Quantum Risk Scan](https://github.com/givemehat/IndraMesh/actions/workflows/indramesh_scan.yml/badge.svg)](https://github.com/givemehat/IndraMesh/actions/workflows/indramesh_scan.yml)
[![Open in Streamlit](https://static.streamlit.io/badges/streamlit_badge_black_white.svg)](https://share.streamlit.io/deploy?repository=givemehat/ECDAT&branch=master&mainModule=app.py)

**Smart India Hackathon 2026 | Problem Statement SIH26164**
National Technical Research Organisation (NTRO) | Blockchain & Cybersecurity | Category: Software

> *You cannot migrate what you cannot see.* IndraMesh discovers an enterprise's cryptographic
> inventory, judges each artefact's exposure to a future quantum attacker using **Mosca's
> inequality**, and recommends a **standard-derived, cost-quantified** post-quantum replacement,
> emitting a **schema-validated CycloneDX v1.7 CBOM** and stating exactly what it could not see.

---

## The problem

India's transition to post-quantum cryptography is a national programme, and NTRO's SIH26164
identifies its true first step:

> *"Discovery and inventory of Cryptographic Artefacts is the critical first step, that will
> enable the transition."*

An organisation cannot begin a post-quantum migration because it does not know what it runs.
Its cryptography is not in one file. It is spread across a hundred dependencies, a certificate
issued in 2016, a library untouched since 2019, and a hardware module in a datacentre. There is
no inventory, so there is no plan.

## What IndraMesh does

| # | Brief requirement | Implementation |
|---|---|---|
| 1 | **Discovery & cataloguing** of algorithms, keys, protocols, libraries | `engine/scanner.py` - **131-rule** detection table: Go (34), SSH/TLS wire identifiers (17), multi-language primitives (14), Java JCE (12), Ruby (11), Python (11), PHP (9), Rust (7), JavaScript/TypeScript (7), plus cloud-KMS, config, key-file, protocol and PKCS#11 hardware rules. Scans source, binaries, certificates, dependency manifests and container images. Go is measured against a pinned corpus slice; Rust, JavaScript and TypeScript are **unmeasured** - see *What this cannot see* |
| 2 | **Quantum risk assessment**, flagging risks to sensitive data | `engine/mosca.py` - Shor vs Grover break model, **harvest-now-decrypt-later** flag, Mosca's inequality `X + Y > Z` |
| 3 | **Classification** by type, lifetime, business criticality | `engine/mosca.py` - canonical primitives, `DATA_CLASS_LIFETIME` (X) and `MIGRATION_EFFORT` (Y) tables, Critical/High/Medium/Low tiers |
| 4 | **PQC / hybrid recommendations** factoring risk, latency and cost | `engine/recommender.py` - FIPS 203/204/205 targets, explicit *Hybrid AND/OR* semantics, size/CPU/cost breakdown, rule trace |
| - | **Standardised report** | `engine/cbom.py` - CycloneDX **1.7** CBOM, validated against the published JSON Schema |
| - | **Interactive console** | `server.py` + `app.py` - **FastAPI + vanilla-JS** web console (no Streamlit, no CDN, no build step). Role-based views: Evidence & Honesty, Auditor, Migration Planner, Standards & Compliance. Shows `findings_total` **next to** `proven_use`, publishes unresolved-purpose findings with the evidence that would resolve them, and withholds the CBOM download unless it validates against the 1.7 schema |

### The India context

The **Department of Science & Technology (DST), Ministry of Science & Technology** has published
a national PQC migration roadmap under India's **National Quantum Mission (NQM)**, with phased
timelines across sectors and Critical Information Infrastructure (CII) migration targeted around
**2029**.

A roadmap cannot be executed without an inventory. IndraMesh ships that policy as machine-readable
packs - `--policy india_dst_nqm`, `nist_ir_8547`, `cnsa_2_0` - and keeps **policy deadlines and
cryptanalytic estimates strictly separate**, because conflating them is how organisations make bad
migration decisions.

---

## Install

```bash
git clone https://github.com/givemehat/IndraMesh.git
cd IndraMesh
python -m venv .venv && . .venv/Scripts/activate    # Windows
# source .venv/bin/activate                          # Linux/macOS
pip install -r requirements.txt
```

> **CPU-only machines:** `pip install torch --index-url https://download.pytorch.org/whl/cpu`

Everything the code imports is declared in `requirements.txt`. Scanning also works with
**`--no-ml`** (regex-only), which needs no PyTorch at all.

### Running via Docker

```bash
docker build -t indramesh .
docker run -p 8501:8501 -v $(pwd):/target indramesh
```

*The web console is then available at `http://localhost:8501`.*

---

## Use

```bash
python cli.py ./your-project --no-ml                    # read the findings
python cli.py ./your-project --format cbom --out ./out   # emit a schema-valid CBOM
python validate_cbom.py ./out/indramesh_report.json      # prove it validates
python cli.py . --z 15 --policy india_dst_nqm           # score against India's 2029 CII milestone
python cli_advanced.py ./your-project                   # dependency + migration-verification sensors
python cli_certificates.py certs ./your-project         # X.509 certificate sensor

python app.py                                           # launch the FastAPI web console
python -m pytest tests/ -v                              # 886 tests
```

### Offline by design

IndraMesh makes **no network calls** of its own. No CDN, no telemetry, no remote fonts, no
runtime asset fetch. The console's JavaScript, CSS and fonts are served from `/static`. This is
not a nicety: a tool that phones home cannot be deployed inside a bank's air-gapped network, and
an analyst opening a console must not tell a third party that they are analysing cryptography.
`tests/test_frontend_assets.py` fails the build if any remote reference ever returns.

The single exception is the optional **network probe sensor**, which is *deny-by-default*: it
requires an explicit hostname allowlist and refuses private/loopback targets unless
`INDRAMESH_ALLOW_PRIVATE_TARGETS` is set. See `engine/netpolicy.py`.

---

## Architecture

```
        Source repos, binaries, deps, containers, certificates, live endpoints
                                     |
    +--------------------------------+-------------------------------+
    |  sensors                                                             |
    |  scanner.py    certificates.py   dependencies.py   netprobe.py    |
    |  131 rules, 9 languages        X.509 + KeyUsage  manifests       SSH/TLS probe
    +--------------------------------+-------------------------------+
                                     |
                              findings[]  (one schema)
                                     |
    +----------------+----------------+----------------+----------------+
    |                |                |                |                |
  mosca.py     recommender.py     purpose.py     migration.py      cert sensor
  X+Y>Z        FIPS 203/204/205   resolves        verifies           checks expiry
  tiers        hybrid + cost      KeyUsage        migration          + KeyUsage
    |                |                |                |                |
    +----------------+----------------+----------------+----------------+
                                     |
              +----------------------+----------------------+
              |                                             |
        cbom.py (CycloneDX 1.7)                   server.py (FastAPI console)
        schema-validated export                   vanilla-JS frontend
```

Every sensor emits the **same finding schema**, so any sensor's output can be concatenated,
aggregated and risk-scored by the same code. That is what makes the coverage manifest honest: the
console can state exactly which sensor looked at what, and what it never saw.

---

## The web console

Four views, one rule: **never show a number the tool cannot justify.**

| View | Answers |
|---|---|
| **Evidence & Honesty** | `findings_total` next to `proven_use`. How many artefacts are *proven in use* vs *capability nothing calls*. What was never in scope. |
| **Auditor** | Per-artefact evidence: file, line, the exact matched text, the rule that fired, and the detection method (`regex` / `ml` / `manual`). |
| **Migration Planner** | Mosca tier per artefact, FIPS recommendation with *Hybrid AND/OR* semantics, and the size/CPU cost of the replacement. |
| **Standards & Compliance** | Which NIST level each primitive reaches, where it falls short, and the policy packs applied (`nist_ir_8547`, `cnsa_2_0`, `india_dst_nqm`). |

The console also renders an **interactive topology graph** of the cryptographic estate, and
exports a schema-validated CBOM only after checking it against the vendored CycloneDX 1.7 JSON
Schema. If validation fails, the download is withheld and the reason is shown.

---

## CLI

```bash
python cli.py TARGET [--format json|cbom|sarif] [--out DIR] [--z N]
                     [--policy india_dst_nqm|nist_ir_8547|cnsa_2_0]
                     [--fail-on CRITICAL|HIGH|MEDIUM|LOW] [--no-ml]
```

| Flag | Effect |
|---|---|
| `--format cbom` | emit a CycloneDX 1.7 document instead of a human summary |
| `--z N` | set the assumed CRQC arrival year (default 15) |
| `--policy` | load a dated policy deadline pack |
| `--fail-on` | exit non-zero at or above a tier - for CI gating |
| `--no-ml` | regex-only; no PyTorch required |

---

## Evidence classes

Every finding is tagged with **how** it was found, and the distinction is load-bearing:

| Class | Meaning |
|---|---|
| `observed` | a real call site in real code, or a parsed certificate. **Proof.** |
| `inferred` | a capability that exists but may never be invoked. **A lead, not a finding.** |

`inferred` findings are counted and displayed, but never used to assert that data is at risk.
Collapsing the two is how crypto scanners inflate their numbers, and it is the single fastest way
to lose a technical judge's trust.


---

## Measured accuracy

Numbers are reproduced by one command, against **externally labelled** corpora - not our own
fixtures:

```bash
python benchmark/run_benchmark.py
```

| Corpus | Files | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| CryptoAPI-Bench (Java JCE, hand-labelled) | 203 | 165 | 1 | 45 | **0.994** | **0.786** | 0.878 |

**On our own multi-language rule pack** (`engine/scanner.py`):

| Language | Rules | Corpus | P | R | F1 |
|---|---|---|---|---|---|
| Go | 41 | x/crypto + ssh (pinned) | 0.983 | 0.985 | 0.984 |
| Java (JCE) | 33 | CryptoAPI-Bench | 0.994 | 0.786 | 0.878 |
| Python | 12 | paramiko (pinned) | 1.000 | 1.000 | 1.000 |
| Rust | 20 | - | not measured | | |
| JavaScript / TypeScript | 15 | - | not measured | | |

Per-file false negatives, and the reason each published label excluded the line, are in
[`benchmark/results.json`](benchmark/results.json) and
[`benchmark/RESULTS.md`](benchmark/RESULTS.md).

**We report the weaker number deliberately.** A tool that publishes its own recall, and separates
*proven use* from *capability nothing calls*, is worth more to an auditor than one claiming 100%.
The 0.786 Java recall is stated here, in the README, where a judge will find it.

---

## How the risk model works

**Mosca's inequality:** `X + Y > Z` - migration should already have started, where

- **X** = years the data (or signed artefact) must remain protected - a *business* property
- **Y** = years to migrate - an *engineering* property
- **Z** = years until a cryptographically relevant quantum computer - an *estimate*

Three properties make the output defensible rather than decorative:

1. **Shor and Grover are different problems.** RSA/ECC are broken outright and data captured
   today is retroactively readable (**harvest-now-decrypt-later**). AES-256 is merely *weakened*,
   non-retroactively. Applying Mosca's inequality to symmetric crypto would be a category error,
   so IndraMesh excludes it and reports `weakened-by-Grover` instead.
2. **The same algorithm can get different tiers.** A 30-year statutory archive protected by an RSA
   key-wrapping key is Critical; the same RSA in a config file for a 5-year internal credential is
   Medium. X drives the tier - not the algorithm name, and not the detector's confidence.
3. **Z is a band, not a point.** Every verdict is reported at Z = 5 / 10 / 15 with a `z_stable`
   flag. If the tier flips inside the expert-consensus window, the tool says so instead of
   asserting one answer.

---

## What IndraMesh will not do

Stated up front, because a security reviewer will ask:

- It does **not** see crypto negotiated on the wire - that needs a PCAP/trace sensor.
- It does **not** see keys inside HSMs, TPMs or silicon - that needs attestation.
- It does **not** see cryptography at a SaaS/third-party boundary.
- It does **not** do interprocedural data-flow: a helper that forwards an algorithm name is not
  resolved to its caller.
- Binary detection identifies *providers* (libcrypto, BoringSSL, libsodium...), not the algorithms
  inside a stripped binary.
- HSM and managed cloud-KMS coverage is **partial today**; those artefacts surface as
  `unresolved` rather than as a clean bill of health.
- The ML transformer sees only the first 4,000 characters of a file (configurable, reported).

All of the above are emitted in a **coverage manifest** (`indramesh_coverage.json`) and shown in the
dashboard. A file that could not be read is recorded as an error, never silently counted as clean.


---

## Layout

```
engine/scanner.py      rule table, source/binary/container scanning, coverage manifest
engine/mosca.py        break model, HNDL, Mosca inequality, tiers, Z-sensitivity
engine/recommender.py  FIPS-derived PQC targets, cost model, rule traces
engine/cbom.py         CycloneDX 1.7 emitter
engine/certificates.py X.509 / PEM / DER sensor with KeyUsage resolution
engine/dependencies.py dependency-manifest sensor
engine/netpolicy.py    deny-by-default network policy for the live probe
engine/graph.py        topology graph
engine/gui_helpers.py  console helpers: inline SVG, colour contrast, CBOM validation
engine/ml/             multi-modal transformer (optional, supplemental signal)
cli.py                 headless scanner / CI gate
cli_advanced.py        dependency + migration-verification sensors
cli_certificates.py    X.509 certificate sensor
app.py                 FastAPI web console launcher
server.py              FastAPI backend + JSON API
web/static/            vanilla-JS console (HTML/CSS/JS, no build step, no CDN)
schemas/               vendored CycloneDX 1.7 JSON Schema
```

## Documentation

- [`docs/GUIDE.md`](docs/GUIDE.md) - full usage guide.
- [`docs/COMPARISON.md`](docs/COMPARISON.md) - evidence-based gap table against a named competitor.
- [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md) - defects found in the previous revision and how
  each was fixed, with the honest limitations that remain.
- [`PROVENANCE.md`](PROVENANCE.md) - where every standard-derived figure comes from.
- [`examples/README.md`](examples/README.md) - real-world scan notes.

## Standards and references

- **Mosca, R.** *The Transition to Post-Quantum Cryptography: Enterprise Strategies and
  Cybersecurity Risks* (2018) - the inequality NTRO named.
- **NIST FIPS 203 / 204 / 205** - ML-KEM, ML-DSA, SLH-DSA.
- **NIST IR 8547** - transition timelines (`nist_ir_8547` policy pack).
- **CycloneDX 1.7** - the CBOM schema we validate against.
- **DST, Ministry of Science & Technology, India** - National Quantum Mission PQC migration
  roadmap (`india_dst_nqm` policy pack).
- **CNSA 2.0** (`cnsa_2_0` policy pack).

## Test

```bash
pip install pytest pytest-cov
python -m pytest tests/ -v
```

## Research provenance

Every standard-derived figure traces to a NIST publication listed in
[`research/sources/`](research/sources/INDEX.md). See [`PROVENANCE.md`](PROVENANCE.md).

## Licence

Apache-2.0. The vendored CycloneDX schema is Apache-2.0 (OWASP Foundation).

