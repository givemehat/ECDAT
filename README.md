# ECDAT â€” Enterprise Cryptographic Discovery & Analysis Tool

[![Tests](https://github.com/givemehat/ECDAT/actions/workflows/tests.yml/badge.svg)](https://github.com/givemehat/ECDAT/actions/workflows/tests.yml)
[![Quantum Risk Scan](https://github.com/givemehat/ECDAT/actions/workflows/ecdat_scan.yml/badge.svg)](https://github.com/givemehat/ECDAT/actions/workflows/ecdat_scan.yml)

**Smart India Hackathon 2026 Â· Problem Statement SIH26164** Â· National Technical Research Organisation (NTRO) Â· Blockchain & Cybersecurity

> *You cannot migrate what you cannot see.* ECDAT discovers an enterprise's cryptographic
> inventory, judges each artefact's exposure to a future quantum attacker using **Mosca's
> inequality**, and recommends a **standard-derived, cost-quantified** post-quantum replacement â€”
> emitting a **schema-validated CycloneDX v1.7 CBOM** and stating exactly what it could not see.

---

## What it does

| # | Brief requirement | Implementation |
|---|---|---|
| 1 | **Discovery & cataloguing** of algorithms, keys, protocols, libraries | `engine/scanner.py` â€” **124-rule** detection table covering **Python, Java (JCA), C/C++ (OpenSSL), PHP, Ruby, Go, Rust, JavaScript and TypeScript**, plus SSH/TLS wire identifiers, config files, binaries, certificates, dependency manifests, container images and a live network probe. Go is measured against a pinned corpus slice; Rust, JavaScript and TypeScript are **unmeasured** â€” see *What this cannot see* |
| 2 | **Quantum risk assessment**, flagging risks to sensitive data | `engine/mosca.py` â€” Shor vs Grover break model, **harvest-now-decrypt-later** flag, Mosca's inequality `X + Y > Z` |
| 3 | **Classification** by type, lifetime, business criticality | `engine/mosca.py` â€” canonical primitives, `DATA_CLASS_LIFETIME` (X) and `MIGRATION_EFFORT` (Y) tables, Critical/High/Medium/Low tiers |
| 4 | **PQC / hybrid recommendations** factoring risk, latency and cost | `engine/recommender.py` â€” FIPS 203/204/205 targets, explicit *Hybrid AND/OR* semantics, size/CPU/cost breakdown, rule trace |
| â€” | **Standardised report** | `engine/cbom.py` â€” CycloneDX **1.7** CBOM, validated against the published JSON Schema |
| â€” | **Interactive console** | `app.py` â€” Streamlit, four role-based views (Evidence & Honesty, Auditor, Migration Planner, Standards & Compliance). Shows `findings_total` **next to** `proven_use`, publishes unresolved-purpose findings with the evidence that would resolve them, and withholds the CBOM download unless it validates against the 1.7 schema |

---

## Install

```bash
git clone https://github.com/givemehat/ECDAT.git
cd ECDAT
python -m venv .venv && . .venv/Scripts/activate    # Windows
# source .venv/bin/activate                          # Linux/macOS
pip install -r requirements.txt
```

> **CPU-only machines:** `pip install torch --index-url https://download.pytorch.org/whl/cpu`

Everything the code imports is declared in `requirements.txt`. Scanning also works with
**`--no-ml`** (regex-only), which needs no PyTorch at all.


### Running via Docker
For enterprise environments, ECDAT can be run entirely via a Docker container without installing any local dependencies.

```bash
docker build -t ecdat .
docker run -p 8501:8501 -v $(pwd):/target ecdat
```
*The interactive GUI will be available at `http://localhost:8501`.*

## Use

```bash
python cli.py ./your-project --no-ml                  # read the findings
python cli.py ./your-project --format cbom --out ./out # emit a schema-valid CBOM
python validate_cbom.py ./out/ecdat_report.json        # prove it validates
python cli.py . --z 15 --policy nist_ir_8547           # tune horizon + policy
python cli.py . --format cbom --fail-on CRITICAL      # fail a CI build
python cli.py ./image.tar                              # container image
python -m streamlit run app.py                         # interactive dashboard
```

**On Windows, launch the GUI with `python -m streamlit`, not `streamlit`.** `pip` installs
Streamlit's launcher into the interpreter's `Scripts` directory, which is not on `PATH` by
default, so `streamlit run app.py` fails with *"'streamlit' is not recognized"*. Invoking it as
a module always works because it uses the interpreter you installed it into. The other fix, if
you prefer the bare command, is to add `%APPDATA%\Python\Python3XX\Scripts` to `PATH`.

Run this before opening the app — it renders `app.py` headlessly and exercises the engine
against a real pinned corpus file, so a crash surfaces here instead of on screen:

```bash
python validate_gui.py     # 8 checks, exit 0 = clean
```

**Policy packs** â€” `india_dst_nqm` (default; CII migration by 2029), `nist_ir_8547` (disallow 2035),
`cnsa_2_0` (exclusive NSS use 2033).
**Z presets** â€” 5y (plan-as-if-early), 10y (GRI 2026 consensus midpoint, default), 15y (upper bound).
Z is a *cryptanalytic estimate*; compliance deadlines are reported separately and never conflated.

## Measured accuracy

Precision and recall are measured against **external, pinned public corpora** â€” not fixtures we
wrote ourselves. Reproduce with `python benchmark/run_benchmark.py`.

| Corpus | What it is | Precision | Recall | F1 |
|---|---|---|---|---|
| [CryptoAPI-Bench](https://github.com/CryptoAPI-Bench/CryptoAPI-Bench) | Java JCE, 203 files, hand-labelled | **0.994** (165/166) | **0.786** (165/210) | 0.878 |
| [golang.org/x/crypto](https://github.com/golang/crypto) `ssh/` | Real production Go crypto, 3 files | **0.922** (47/51) | **1.000** (47/47) | 0.959 |
| [paramiko](https://github.com/paramiko/paramiko) | Real production SSH library, Python | **0.894** (143/160) | **0.596** (143/240) | 0.715 |

The Go figure is reported at both label variants. **L1** counts a line only if it names or
binds a primitive; **L2** also counts lines that merely *operate* on one. L2 is the lower bound
on recall and is the honest number to quote first:

| Go corpus | Precision | Recall | F1 |
|---|---|---|---|
| L1 | 0.922 (47/51) | 1.000 (47/47) | 0.959 |
| L2 | **0.961** (49/51) | **1.000** (49/49) | **0.980** |

Three things this table is meant to make obvious:

* **Recall is not uniform, and we say so.** 0.786 on Java, 0.596 on Python and 1.000 on the Go
  slice are all honest measurements. The Java and Python numbers are lower than a finished
  product should ship. `benchmark/RESULTS.md` breaks every miss down by algorithm family so the
  gap is specific rather than a round number.
* **The Go corpus is three files, and that is not a strong claim.** It is the
  `cipherModes`/`macModes`/`ML-KEM` algorithm tables — the three files that enumerate a Go
  estate's cryptographic surface, and the three that have been read in full and annotated. The
  other 28 non-test files in `ssh/` are **not** annotated and **not** scanned. Recall of 1.000
  is relative to those three files and says nothing about the rest of x/crypto. Widening the
  label set is the next task, and the number is expected to fall.
* **The corpora are not committed.** They are cloned at a pinned commit by the harness, so the
  measurement is reproducible without shipping someone else's code in our repository. See
  [`PROVENANCE.md`](PROVENANCE.md).

The corpus supplies *locations*; the labels come from `benchmark/annotate.py`, which opens each
file at the labelled line and classifies it by a stated rule. That separation is deliberate: a
corpus that graded our own output would be measuring nothing.

---

## What this cannot see

Stated plainly, because a discovery tool that overstates its coverage is worse than no tool.

**Measured**
- The benchmark scores **detection only**. It says nothing about whether our *risk tiers* or
  *recommendations* are correct. Those are the parts a reviewer will actually challenge, and they
  are **not** covered by an external corpus.
- **PHP and Ruby recall is unmeasured.** There is no labelled corpus for either language. The rule
  packs are verified against real API calls and adversarial decoys, and that is the whole of the
  evidence. No recall figure is claimed for them.
- Detection accuracy on a corpus of hand-constructed micro-programmes (CryptoAPI-Bench) is not the
  same as accuracy on a large production codebase. paramiko is the real-library number, and it is
  the lower one.

**Not implemented**
- **Go has a measured slice; Rust, JavaScript and TypeScript do not.** The Go pack is measured
  against three hand-read files of `golang.org/x/crypto` (see the table above), and the figure is
  published with its scope attached: recall 1.000 on those three files, and nothing is claimed for
  the other 28. **No precision or recall figure is claimed for Rust, JavaScript or TypeScript** --
  those packs are verified against real API call sites and adversarial decoys
  (`tests/test_multilang_pack.py`), and that is the whole of the evidence.
- **The new rule packs contained dead rules, and measuring is what found them.** `rsa.PssOptions`
  does not exist (the type is `PSSOptions`). `chacha20.New` does not exist (the constructors are
  `NewUnauthenticatedCipher` and `HChaCha20`). `mlkem.GenerateKey512` does not exist, because Go
  ships two of FIPS 203's three parameter sets. Each of those rules scored ZERO against 322 real
  Go files while reading as coverage on paper. A rule that cannot match anything is worse than no
  rule, because it is counted in a rule total and trusted like one.
- **Small DH group sizes are not detected.** A rule for Node's sub-2048-bit `modp1|modp2|modp5`
  groups was written and removed. Bare, the group names matched `String g = "modp5"` in a Java
  file; anchored to a `createDiffieHellman` call, every call it can match is already matched by
  `ECD-SRC-ECDH-001` on the same line. Two components at one `(file, line)` cannot be collapsed
  downstream, so the weaker rule would have been pure duplication. A DH group's *size* is a real
  gap and is left as one.
- No interprocedural data-flow. A helper that forwards an algorithm name to a real call is not
  connected to it; rules match text, and the miss is reported rather than guessed.
- Obfuscated or runtime-assembled cipher names (`"AE"+"S"`) produce no finding.
- A cipher name assigned to a constant in one function and used in another is found at the
  **declaration**, not linked to the call site.

**Not independently reviewed**
- The classifications follow **NIST IR 8547** (an *Initial Public Draft* â€” not a final standard)
  and the **CycloneDX 1.7** specification as we read them. They **have not been reviewed by an
  external cryptographer.**
- Byte sizes for ML-KEM and ML-DSA parameter sets are consistent with the round-3 submissions but
  are **not yet traced to the FIPS PDFs**; both standards carry errata notices dated after
  publication. See [`research/sources/INDEX.md`](research/sources/INDEX.md).
- NIST IR 8547's transition table is *strength-dependent*: 112-bit classical public-key is
  **deprecated** rather than disallowed, while â‰¥ 128-bit is disallowed after 2035. We currently
  apply one flat year. This is a known simplification, recorded rather than hidden.

---

## Provenance

No third-party or competing implementation was copied, referenced, or consulted. Every detection
rule was derived from **our own measurements of our own misses** against public corpora, and the
standard-derived figures trace to NIST publications listed in
[`research/sources/`](research/sources/INDEX.md). See [`PROVENANCE.md`](PROVENANCE.md).

---

## Test

```bash
pip install pytest pytest-cov
python -m pytest tests/ -v
```

---

## How the risk model works

**Mosca's inequality:** `X + Y > Z` â‡’ migration should already have started, where

- **X** = years the data (or signed artefact) must remain protected â€” a *business* property
- **Y** = years to migrate â€” an *engineering* property
- **Z** = years until a cryptographically relevant quantum computer â€” an *estimate*

Three properties make the output defensible rather than decorative:

1. **Shor and Grover are different problems.** RSA/ECC are broken outright and data captured
   today is retroactively readable (**harvest-now-decrypt-later**). AES-256 is merely *weakened*,
   non-retroactively. Applying Mosca's inequality to symmetric crypto would be a category error,
   so ECDAT excludes it and reports `weakened-by-Grover` instead.
2. **The same algorithm can get different tiers.** A 30-year statutory archive protected by an RSA
   key-wrapping key is Critical; the same RSA in a config file for a 5-year internal credential is
   Medium. X drives the tier â€” not the algorithm name, and not the detector's confidence.
3. **Z is a band, not a point.** Every verdict is reported at Z = 5 / 10 / 15 with a `z_stable`
   flag. If the tier flips inside the expert-consensus window, the tool says so instead of
   asserting one answer.

## What ECDAT will not do

Stated up front, because a security reviewer will ask:

- It does **not** see crypto negotiated on the wire â€” that needs a PCAP/trace sensor.
- It does **not** see keys inside HSMs, TPMs or silicon â€” that needs attestation.
- It does **not** see cryptography at a SaaS/third-party boundary.
- It does **not** do interprocedural data-flow: a helper that forwards an algorithm name is not
  resolved to its caller.
- Binary detection identifies *providers* (libcrypto, BoringSSL, libsodiumâ€¦), not the algorithms
  inside a stripped binary.
- The ML transformer sees only the first 4,000 characters of a file (configurable, reported).

All of the above are emitted in a **coverage manifest** (`ecdat_coverage.json`) and shown in the
dashboard. A file that could not be read is recorded as an error, never silently counted as clean.

## Layout

```
engine/scanner.py      rule table, source/binary/container scanning, coverage manifest
engine/mosca.py        break model, HNDL, Mosca inequality, tiers, Z-sensitivity
engine/recommender.py  FIPS-derived PQC targets, cost model, rule traces
engine/cbom.py         CycloneDX 1.7 emitter
engine/graph.py        PyVis topology
engine/gui_helpers.py  streamlit-free console helpers: inline SVG, colour contrast, CBOM validation
engine/ml/             multi-modal transformer (optional, supplemental signal)
cli.py                 headless scanner / CI gate
validate_cbom.py       offline schema validation
app.py                 role-based Streamlit console
schemas/               vendored CycloneDX 1.7 JSON Schema
docs/CODE_REVIEW.md    review of the previous revision + what changed
```

## Documentation

- [`docs/CODE_REVIEW.md`](docs/CODE_REVIEW.md) â€” 21 defects found in the previous revision and how
  each was fixed, with the honest limitations that remain.
- [`examples/README.md`](examples/README.md) â€” real-world scan notes.

## Licence

Apache-2.0. The vendored CycloneDX schema is Apache-2.0 (OWASP Foundation).
