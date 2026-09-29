# SIH 2026 — Idea PPT Keyword & Content Map
### Problem Statement 26164 · NTRO · Blockchain & Cybersecurity · Software

**For:** team use while building the 6-slide idea deck.
**Rule:** the official template is mandatory. Max **6 slides including title**. PDF only. Points and
diagrams, not paragraphs. Do not change the template's idea.

---

## Read this first — what we know about the screening

There is reportedly an internal screening step we are not told about. Two things follow, and they
point in opposite directions:

1. **We cannot optimise for a system we cannot inspect.** Nobody — including us — knows its
   matching rules, keyword list, or weighting. Anyone claiming a "verified ATS keyword list" for
   SIH 2026 is guessing.
2. **But the robust play is unaffected by that uncertainty.** The terms that would match an
   internal filter are almost certainly the terms *in the problem statement itself*, because the
   filter would have been built from the PS. The PS vocabulary is also exactly what a human judge
   scans for. **So: mirror the problem statement's own language, and the deck wins under either
   screening model.**

That is the whole strategy. Use the PS's words, in the PS's structure, once each, inside real
sentences. Not a keyword wall — instruction 2 forbids paragraphs and rewards points/diagrams, and
a dense term list reads to a human judge as a team that did not understand the problem.

---

## The five phrases from the PS that must appear

Lifted from SIH26164 itself. Highest-value strings in the deck.

| # | Phrase (verbatim) | PS clause |
|---|---|---|
| 1 | **cryptographic artefacts** | "discovery and inventory of Cryptographic Artefacts is the critical first step" |
| 2 | **Mosca's algorithm** | "Apply structured frameworks such as Mosca's algorithm" |
| 3 | **harvest now, decrypt later** | "highlight risks to sensitive data" (HNDL is the modern name) |
| 4 | **CBOM analytics tool** | "A Comprehensive CBOM analytics tool" |
| 5 | **PQC / hybrid algorithms** | "Recommend suitable alternatives (PQC/ Hybrid algorithms)" |

Note on #2: the PS says **Mosca's algorithm**; the literature says **Mosca's inequality**. Put
**both**: "Mosca's algorithm (X + Y > Z inequality)".

Also cover the PS's own artefact list, since the filter was built from that sentence:
`algorithms · keys · certificates · protocols · libraries · hardware modules · cloud services`
and `internal and external facing applications, products and infrastructure`.


---

# SLIDE-BY-SLIDE

## SLIDE 1 — TITLE PAGE

Fixed fields: PS ID 26164 · PS Title · Theme: Blockchain & Cybersecurity · Category: Software ·
Team ID · Team Name.

**IDEA TITLE line** — most-read text in the deck. Must contain problem + mechanism.

> **"Quantum-Risk Cryptographic Bill of Materials: automated discovery of cryptographic artefacts
> with Mosca's-algorithm risk prioritisation and NIST PQC migration guidance"**

Carries: *cryptographic artefacts · CBOM · discovery · quantum risk · Mosca's algorithm · PQC ·
migration* — all six PS concepts in one line.

---

## SLIDE 2 — PROPOSED SOLUTION

Template sub-points: detailed explanation · how it addresses the problem · innovation and uniqueness.

**Keywords to place here**
`cryptographic artefacts` · `algorithms, keys, certificates, protocols, libraries` ·
`internal and external facing applications` · `CBOM analytics` · `Cryptographic Bill of Materials` ·
`CycloneDX 1.7` · `schema-validated` · `quantum risk assessment` · `Shor's algorithm` ·
`Grover's algorithm` · `harvest now, decrypt later` · `sensitive data` · `Mosca's algorithm` ·
`X + Y > Z` · `data lifetime` · `migration time` · `business criticality` · `risk classification` ·
`Critical / High / Medium / Low` · `PQC and hybrid algorithms` · `latency` · `cost`

**Content**
- Problem: post-quantum migration is blocked by cryptographic invisibility — you cannot migrate
  what you cannot discover.
- Solution: a CBOM analytics tool scanning source repositories, binaries, libraries, containers.
- Risk: Mosca's algorithm applied per artefact, not per organisation; HNDL flagged separately.
- Output: CycloneDX 1.7 CBOM + interactive visualisation.

⭐ **Innovation bullet — ours, verbatim:**
> *"The engine **refuses to guess**. Where an artefact's purpose is ambiguous it reports UNRESOLVED
> and names the specific evidence that would resolve it, instead of asserting a confident but
> potentially wrong PQC target."*

---

## SLIDE 3 — TECHNICAL APPROACH

Template sub-points: technologies · methodology and process (flow chart / images / prototype).

Must be a **diagram**. Label the pipeline with the keywords:

```
Source Code Repositories · Compiled Binaries · Third-Party Libraries · Container Images
                                  ↓
        STATIC ANALYSIS ENGINE — AST + rule-based, 141 rules, 7 languages
        Python · Java · Go · Rust · JS/TS · C/C++ · C#
                                  ↓
        PURPOSE + ASSURANCE RESOLUTION — capability / declared / used / observed
                                  ↓
        QUANTUM RISK ENGINE — Mosca's algorithm: X + Y > Z
        Shor (RSA, ECC, DH) · Grover (AES, SHA) · HNDL
                                  ↓
        RECOMMENDATION ENGINE — NIST PQC standards
        ML-KEM (FIPS 203) · ML-DSA (FIPS 204) · SLH-DSA (FIPS 205) · hybrid classical-PQC
        factored by risk profile · latency · implementation cost
                                  ↓
   ┌─────────────┬──────────────────┬────────────────────┐
   │ CycloneDX   │ Interactive GUI  │ Prioritised PQC    │
   │ CBOM 1.7    │ + visualisation   │ migration roadmap  │
   └─────────────┴──────────────────┴────────────────────┘
```

**Technology line:** Python · FastAPI · static analysis (AST + rule engine) · CycloneDX 1.7 ·
NIST PQC standards FIPS 203/204/205 · X.509 certificate & KeyUsage parsing · Docker/OCI layer
inspection · dependency manifest analysis.

⭐ **Evidence line** (judges reward demonstrated capability):
> *"Validated on two external pinned-commit corpora — precision 0.994 / 0.910, recall 0.786 /

---

## SLIDE 4 — FEASIBILITY AND VIABILITY

Template sub-points: feasibility · potential challenges and risks · strategies to overcome.

**Keywords:** `challenges and risks` · `limitations` · `static analysis` · `dynamically loaded
cryptography` · `obfuscated code` · `coverage transparency` · `false positives` · `precision and
recall` · `open source` · `Python 3.11` · `Docker` · `offline` · `air-gapped` · `no telemetry` ·
`scalable` · `reproducible`

| Challenge | Mitigation |
|---|---|
| Static analysis misses dynamically loaded / wrapped / obfuscated crypto | Publishes per-run coverage: files seen, scanned, skipped with a recorded reason |
| Recall is 0.72 on Python, not 1.0 | Every remaining miss enumerated by file and line in the published benchmark — a measured work list |
| PHP / Ruby rule packs not implemented | Declared as a scope limitation, not implied away |
| HSM / TPM / cloud KMS internals need attestation | Out of scope for static analysis; live network probe sensor implemented for reachable endpoints |

**Deployment line:** *"Runs offline and air-gapped. No CDN, no telemetry, no outbound calls —
verified by test. Dockerised; Python 3.11 plus declared dependencies."*

---

## SLIDE 5 — IMPACT AND BENEFITS

Template sub-points: potential impact on target audience · benefits (social, economic, environmental).

**Audience:** `NTRO` · `national security` · `defence` · `critical infrastructure` · `BFSI` ·
`healthcare` · `government departments` · `SOC` · `compliance and audit`

**Benefits — the domain's own vocabulary, this is what scores:**
`post-quantum migration` · `cryptographic agility` · `crypto-agility readiness` · `NIST IR 8547` ·
`CNSA 2.0` · `data confidentiality lifetime` · `long-lived data` · `zero-knowledge exposure` ·
`harvest now decrypt later exposure` · `compliance and auditability` · `machine-readable inventory` ·
`digital sovereignty` · `prioritised remediation roadmap` · `risk-based prioritisation` ·
`reduced migration cost` · `audit readiness`

**One line:** *"Replaces a multi-week manual cryptographic audit with an automated, evidence-linked
inventory, and converts 'migrate to PQC' into a dated, prioritised, costed migration roadmap."*

---

## SLIDE 6 — RESEARCH AND REFERENCES

Real citations only. This is what separates a credible submission from a prototype.

**Standards & policy**
- NIST **FIPS 203** (ML-KEM) · **FIPS 204** (ML-DSA) · **FIPS 205** (SLH-DSA)
- **NIST IR 8547** — transition to PQC standards
- **NSA CNSA 2.0** — post-quantum migration timelines
- **Global Risk Institute** Quantum Threat Timeline Report
- **OWASP** Cryptographic Bill of Materials project
- **CycloneDX 1.7 / ECMA-424** — CBOM schema

**Risk framework — the credibility anchor**
- **Mosca, C.**, *On Evaluating Cryptographic Agility* — the **X + Y > Z** inequality

**Evidence discipline — the citation that sets us apart**
- **Glanz et al.**, *Quantifying Reproducibility in Cryptographic Bug Detection*, **ACM CCS 2024** —
  found **4 of 12** academic PQ tools could not be reproduced. Direct justification for our mutation
  testing and external benchmarking.

**Validation corpora — proves real data, not fixtures**
- **CryptoAPI-Bench** (ACSAC 2024), pinned commit
- **OpenSSL** and **paramiko** (real production library), pinned commits

> 0.717. Test suite 893 passing. Mutation-tested: 19/19 injected defects caught."*

---

# MASTER KEYWORD SET

**Problem framing**
cryptographic artefacts · cryptographic discovery · cryptographic inventory · Cryptographic Bill of
Materials · CBOM · CBOM analytics · post-quantum migration · cryptographic agility · quantum risk
assessment · harvest now decrypt later · HNDL · cryptographically relevant quantum computer · CRQC

**Artefact taxonomy (from the PS sentence)**
algorithms · keys · certificates · protocols · libraries · hardware modules · cloud services ·
internal and external facing applications · products and infrastructure

**Cryptography & risk**
RSA · ECC · ECDSA · ECDH · Diffie-Hellman · AES · SHA-1 · SHA-2 · Shor's algorithm · Grover's
algorithm · Mosca's algorithm · Mosca's inequality · X + Y > Z · data lifetime · migration time ·
business criticality · sensitive data · long-lived data

**PQC standards — FIPS names, not draft names**
ML-KEM · ML-DSA · SLH-DSA · FIPS 203 · FIPS 204 · FIPS 205 · NIST IR 8547 · CNSA 2.0 · hybrid
classical-PQC · post-quantum algorithm · migration roadmap

**Discovery technique**
static analysis · AST analysis · rule-based detection · source code repository · compiled binary ·
third-party library · dependency manifest · container image scanning · OCI layer inspection ·
X.509 certificate parsing · KeyUsage · TLS cipher suite · hardware security module / HSM · cloud KMS

**Classification & output**
risk classification · risk tier Critical High Medium Low · assurance level · capability · declared ·
used · observed · confidence · evidence · coverage transparency · false positive · precision ·
recall · CycloneDX 1.7 · ECMA-424 · schema-validated · machine-readable · compliance and
auditability · interactive GUI · visualisation · risk heatmap · dependency graph

**Impact**
digital sovereignty · critical infrastructure · national security · audit readiness · risk-based
prioritisation · reduced migration cost · air-gapped · no telemetry

**Evaluation-proof terms — near-unique to us**
external benchmark corpus · pinned commit · reproducible benchmark · mutation testing · mutant kill
rate · regression test suite · NIST quantum security level · reproducibility · false positive analysis

---

# WHAT NOT TO DO

| ✗ Don't | Why |
|---|---|
| Keyword-stuff a slide | Breaks instruction 2. A human judge reads a term wall as a team that misunderstood the problem. |
| Exceed 6 slides | Instruction 1 is explicit; over-length is a format penalty. |
| Write "Kyber", "Dilithium", "SPHINCS+" as the recommendation | Those are draft names. Use **ML-KEM / ML-DSA / SLH-DSA**. |
| Claim "100% detection" or "complete coverage" | Static analysis provably cannot do this. Invite the probe that ends the pitch. |
| Quote accuracy without naming the corpus | An unbacked number reads as marketing. Pair every figure with corpus + pinned commit. |
| Lead with AI/ML | Not an evaluation criterion. Our ML is supplemental, never load-bearing on the risk verdict. |

---

# OPEN ITEM FOR THE TEAM

SIH publishes the template and process flow but **not** the marks weightage. Confirm with your SPOC
which criterion carries the most marks — that tells you which of the six slides deserves the most
effort, and it is worth more than any keyword on this page.

