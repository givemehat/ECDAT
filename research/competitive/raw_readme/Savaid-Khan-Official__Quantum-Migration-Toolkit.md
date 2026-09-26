# Quantum Migration Toolkit — Post-Quantum Cryptography Migration Tool

**Enterprise Post-Quantum Cryptography Migration Tool** — Automatically scan
codebases for quantum-vulnerable RSA/ECC encryption, remediate with AI, and
ship quantum-safe code.

> Detect quantum-vulnerable cryptography, rewrite it with AI, inject a working PQC SDK, and patch your build system — in one command.

---

## What is Quantum Migration Toolkit?

Quantum Migration Toolkit is an open-source post-quantum cryptography (PQC)
migration tool that automatically detects quantum-vulnerable cryptographic
algorithms — RSA, ECC, DSA, ECDSA — in your codebase and replaces them with
NIST-standardized quantum-safe alternatives (ML-KEM, ML-DSA, SLH-DSA).

It works across 9+ programming languages using static analysis and AI-assisted
remediation, making it one of the most complete quantum cryptography scanners
available today.

## Who is this for?

- **Security engineers** migrating enterprise systems to quantum-safe cryptography
- **DevSecOps teams** needing automated PQC scanning in CI/CD pipelines
- **Researchers** studying post-quantum cryptography migration strategies
- **Organizations** complying with NSA CNSA 2.0, OMB M-23-02, or EU NIS2 mandates

---

## Why Quantum-Safe Cryptography?

Large-scale quantum computers will break today's public-key cryptography (RSA, ECC, DSA, ECDSA) in polynomial time via Shor's algorithm. Adversaries are already collecting encrypted traffic under the **"harvest now, decrypt later"** model. Regulatory deadlines are firming up: U.S. OMB M-23-02 / NSM-10, NSA CNSA 2.0 (mandates ML-KEM and ML-DSA for National Security Systems by 2030–2035), EU NIS2, BSI TR-02102-1.

**Quantum-Migration-Toolkit** is a unified, end-to-end migration tool that:

- **Scans** 9+ languages for vulnerable cryptographic patterns (regex + Tree-sitter AST)
- **Remediates** findings with a local LLM grounded in real PQC API definitions (no hallucinated calls)
- **Vendors** a working ML-KEM + ML-DSA + AES-256-GCM SDK directly into your project
- **Patches** your build system (CMake, pip, Cargo, Maven, Gradle, Go, NPM)
- **Backs up** every modified file and writes a manifest for safe rollback

Unlike scanners that stop at finding generation, this tool produces **concrete change artifacts** (unified-diff patches, vendored SDK headers, build-file edits) — the manual work between "you have a problem" and "you have a fix" goes away.

---

## What's New in v2.4

Two engineering passes shipped on top of the v2.0 baseline:

**Hardening pass (eleven correctness/observability fixes + one build fix).** OqsGuard premature-destroy race; unchecked `map.at()` that could throw mid-scan; arg-parser that silently swallowed bad input; AutoRemediator silently overwriting divergent AI fixes; AstEngine column window matching the wrong line; non-atomic backups; silent rules.json fallback; silent file-open failures; O(n²) rule lookup; swallowed backup errors; one-level-only file-search bug. Plus the `liboqs` FetchContent include-path fix that the research paper called out as a build-reproducibility blocker.

**False-positive reduction pass (five layers).** L1 test-path entropy suppression, L2 tighter entropy heuristics (test-vector context, MAC-address-style colon-hex, ASN.1 OIDs), L3 default ignore patterns for noise dirs (`vendor/`, `node_modules/`, `build/`, `dist/`, `target/`, `.venv/`, `__pycache__/`, `.idea/`, `.vs/`, …), L4 inline `// quantum-migrate: ignore` suppression comments, L5 algorithm-named-file downgrade (a finding of MD5 in `MD5Digest.java` becomes WARNING rather than CRITICAL — the file *implements* the algorithm rather than *uses* it).

Empirical impact on five real OSS projects (7,409 files): total findings dropped from **23,279 → 1,660 (-93%)** with **zero loss of real (non-ENTROPY) findings**. Hand-labeled precision on OpenSSH: **96.88% (124/128)** with all 117 RSA findings true positive. See [`research_paper.md`](research_paper.md) §3.5–§3.6 and [`benchmarks/reports/SUMMARY.md`](benchmarks/reports/SUMMARY.md).

---

## Architecture

```
quantum-migrate (CLI)
  └─ libquantum_migrate (static library)
       ├─ engine/scan/     — Regex + Tree-sitter AST + entropy + proximity
       ├─ engine/ai/       — PqcContext (anti-hallucination) + AiRemediator (llama.cpp)
       ├─ engine/patch/    — AutoRemediator (unified diffs) + DependencyInjector
       └─ engine/pqc/      — ML-KEM, ML-DSA, SLH-DSA, hybrid X25519+ML-KEM, AES-256-GCM
```

A 12-stage CLI pipeline orchestrates: load rules → load ignore patterns → load baseline → discover files → multi-threaded scan → baseline filtering → output report → AI remediation → backup & patch → vendor PQC SDK → patch build system → exit-code policy.

---

## Quick Start

### Prerequisites

- **C++17 compiler** (GCC 7+, Clang 5+, MSVC 2019+)
- **CMake 3.18+**
- **OpenSSL 3.0+** (required — the toolkit uses the OpenSSL 3.x `EVP_KDF` / `EVP_MD_CTX` APIs; 1.1.1 is no longer supported)
- **liboqs 0.10+** — auto-fetched via CMake `FetchContent` if not system-installed. 0.10 is the first release with standardized FIPS 203 ML-KEM; the pinned tag is 0.12.0. (Round-3 "Kyber" is **not** a substitute.)
- ~10–15 GB free disk space *only if* you also download the AI model (recommended: **Qwen2.5-Coder-14B-Instruct Q4_K_M / Q5_K_M GGUF, ~9–11 GB**; the F16 build ~29 GB is optional for maximum fidelity)

### Build — Linux/macOS

```bash
git clone https://github.com/Savaid-Khan-Official/Quantum-Migration-Toolkit.git
cd Quantum-Migration-Toolkit

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

First-time build fetches and compiles liboqs (~5–10 min over the network). Subsequent builds are seconds.

### Build — Windows (MSVC + Visual Studio Build Tools)

```powershell
# Install OpenSSL Developer build (one-time):
winget install --id ShiningLight.OpenSSL.Dev --silent --accept-package-agreements --accept-source-agreements

# Tell CMake where OpenSSL lives (one-time):
[System.Environment]::SetEnvironmentVariable('OPENSSL_ROOT_DIR', 'C:\Program Files\OpenSSL-Win64', 'User')

# Open a NEW PowerShell so the env var is picked up, then:
git clone https://github.com/Savaid-Khan-Official/Quantum-Migration-Toolkit.git
cd Quantum-Migration-Toolkit

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release `
  "-DOPENSSL_ROOT_DIR=C:/Program Files/OpenSSL-Win64"
cmake --build build --config Release
```

The executable lands at `build/cli/Release/quantum-migrate.exe`.

### Optional features (all OFF by default)

```bash
cmake -S . -B build \
    -DUSE_RE2=ON         \  # Google RE2 regex (linear-time guarantee)
    -DUSE_TREESITTER=ON  \  # Tree-sitter AST (7 grammars: c/cpp/py/java/js/go/rust)
    -DUSE_LLAMA=ON          # llama.cpp local AI remediation
```

`USE_LLAMA=ON` adds ~5 minutes to the build for the inference engine.

### AI Model Setup (only if `USE_LLAMA=ON`)

Recommended model: **Qwen2.5-Coder-14B-Instruct, Q4_K_M or Q5_K_M quantization** (~9–11 GB). This is the default recommendation — it fits comfortably in ~12–16 GB RAM and gives near-F16 remediation quality.

```
# Q4_K_M (~9 GB, recommended default):
# https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF/resolve/main/qwen2.5-coder-14b-instruct-q4_k_m.gguf
# Q5_K_M (~11 GB, slightly higher fidelity):
# https://huggingface.co/Qwen/Qwen2.5-Coder-14B-Instruct-GGUF/resolve/main/qwen2.5-coder-14b-instruct-q5_k_m.gguf
# Place in: models/
```

The **F16 build (~29 GB)** remains an optional high-fidelity path for machines with ample RAM/VRAM. See `models/DOWNLOAD_MODEL.txt`. The model is *not* needed for scanning, baselining, vendoring, or build-system patching — only for AI-driven function rewrites.

---

## Run

```bash
# Basic scan (text report to stdout)
./build/cli/quantum-migrate /path/to/code

# Scan with entropy + proximity + SARIF output for CI
./build/cli/quantum-migrate /path/to/code \
    --entropy --proximity \
    --format=sarif --output=results.sarif --fail-on=critical

# Full pipeline: scan + AI rewrite PROPOSAL + vendor SDK + patch build system + backup
./build/cli/quantum-migrate /path/to/code \
    --remediate --model models/qwen2.5-coder-14b-instruct-q4_k_m.gguf \
    --vendor-into /path/to/code \
    --patch-build-system \
    --backup

# Same, but actually apply the fixes to source (compile-gated, auto-rollback):
./build/cli/quantum-migrate /path/to/code \
    --remediate --apply --model models/qwen2.5-coder-14b-instruct-q4_k_m.gguf
```

### Cryptographic Bill of Materials (CBOM)

Emit a **CycloneDX 1.6 CBOM** for cryptographic-asset inventory and quantum-risk
tracking. Each finding becomes a `cryptographic-asset` component with
`cryptoProperties` (assetType, algorithmProperties → primitive /
parameterSetIdentifier / cryptoFunctions / `nistQuantumSecurityLevel`), the
source location under `evidence.occurrences`, and a `quantum:classification`
property (`quantum-vulnerable` / `quantum-safe`) plus the recommended migration
target.

```bash
# CBOM as the primary report:
./build/cli/quantum-migrate /path/to/code --format=cbom --output=cbom.json

# CBOM alongside a text or SARIF report:
./build/cli/quantum-migrate /path/to/code --format=sarif --output=r.sarif --cbom=cbom.json
```

The emitted JSON conforms to the CycloneDX 1.6 crypto-asset structure
(`bomFormat`/`specVersion`/`components[].cryptoProperties`); validation is
structural only (no network calls).

### Docker

```bash
docker build -t quantum-migrate .
docker run --rm -v /path/to/code:/scan quantum-migrate \
    /scan --vendor-into /scan --patch-build-system --backup
```

---

## CLI Flags

### Scan

| Flag | Default | Purpose |
|---|---|---|
| `--rules=<path>` | `rules.json` | Custom rule file (overrides defaults) |
| `--format=text\|sarif\|cbom` | `text` | Output format (`cbom` = CycloneDX 1.6 Cryptographic Bill of Materials) |
| `--output=<path>` | stdout | Write report to file |
| `--cbom=<path>` | none | Also emit a CycloneDX 1.6 CBOM to `<path>` (in addition to the primary `--format` report) |
| `--baseline=<path>` | none | Filter findings against a baseline JSON |
| `--update-baseline` | off | Save current findings as the new baseline |
| `--no-ignore` | off | Skip `.gitignore` / `.quantumignore` |
| `--no-default-ignores` | off | **(v2.4)** Disable built-in noise-dir filter (`vendor/`, `node_modules/`, etc.) |
| `--threads=N` | auto | Worker thread count (capped at 4× hardware concurrency) |
| `--entropy` | off | Enable Shannon-entropy secret detection |
| `--entropy-threshold=<N>` | 4.5 | Minimum entropy bits to flag (range 0–8) |
| `--entropy-include-tests` | off | **(v2.4)** Run entropy detection on test files (default skips them) |
| `--proximity` | off | Cluster related findings (e.g., RSA + weak-RNG in the same function) |
| `--no-ast` | off | Disable Tree-sitter AST validation pass |
| `--fail-on=critical\|high\|warning` | `critical` | Exit non-zero when any finding ≥ this severity is present |
| `--mlkem-level=1\|3\|5` | `3` | ML-KEM (FIPS 203) parameter set used in remediation guidance: 1=ML-KEM-512, 3=ML-KEM-768, 5=ML-KEM-1024 (CNSA 2.0 for NSS) |

### AI Remediation

| Flag | Default | Purpose |
|---|---|---|
| `--remediate` | off | Generate remediation **proposals** (unified diff). Human review is the default — source files are **not** modified |
| `--apply` | off | Write the fixes to source files. Each file is backed up and compile-checked (where a compiler is available); a patched file that fails to compile is rolled back and left as a proposal |
| `--model=<path>` | none | Path to a GGUF model file (recommended: Qwen2.5-Coder-14B `q4_k_m`) |
| `--ai-ctx=<N>` | 4096 | Context window in tokens (range 256–131072) |
| `--ai-threads=<N>` | auto | CPU threads for inference |
| `--ai-temp=<N>` | 0.1 | Sampling temperature (range 0–2; lower = more deterministic) |
| `--patch=<path>` | `quantum_fixes.patch` | Output unified-diff patch file |

### PQC Vendoring

| Flag | Default | Purpose |
|---|---|---|
| `--vendor-into <dir>` | none | Copy PQC SDK headers into the target project |
| `--patch-build-system` | off | Auto-detect and patch CMake / pip / Cargo / Maven / Gradle / Go / NPM |
| `--dry-run` | off | Show what *would* be vendored without writing |
| `--no-vendor` | off | Skip vendoring (AI remediation only) |
| `--backup` | off | Create `.quantum_migrate_backup/` before any modification |

### Inline Suppression (v2.4)

Silence individual findings with a comment on the finding's line or the line above:

```c
RSA_generate_key_ex(rsa, 2048, e, NULL); // quantum-migrate: ignore
```

Optional rule scoping:

```c
RSA_generate_key_ex(rsa, 2048, e, NULL); // quantum-migrate: ignore VULN-RSA-001
```

The marker is case-insensitive and works regardless of comment syntax (`//`, `#`, `--`, `/* */`, `<!-- -->`).

---

## Detection Rules

Eighteen rule patterns spanning quantum-vulnerable public-key crypto, broken hashes, weak ciphers/modes, weak RNG, hardcoded secrets, and insecure transport. Each rule carries a CWE mapping and an optional Tree-sitter S-expression query for AST validation.

RSA is split by usage: `VULN-RSA-ENC-001` (encryption/key transport → ML-KEM-768), `VULN-RSA-SIG-001` (signatures → ML-DSA-65), and `VULN-RSA-001` (generic/ambiguous fallback). The regex layer classifies via patterns like `RSA_public_encrypt` / `Cipher.getInstance("RSA/...")` (encryption) vs `RSA_sign` / `Signature.getInstance("…withRSA")` / `crypto.createSign` (signature); Tree-sitter AST queries refine this where available.

| Severity | Rule IDs |
|---|---|
| **Critical** (7) | `VULN-RSA-001`, `VULN-RSA-ENC-001`, `VULN-RSA-SIG-001`, `VULN-DES-001`, `VULN-RC4-001`, `VULN-ECB-001`, `VULN-HARDCODE-001` |
| **High** (10) | `VULN-AES128-001`, `VULN-MD5-001`, `VULN-SHA1-001`, `VULN-3DES-001`, `VULN-BF-001`, `VULN-PKCS1-001`, `VULN-DSA-001`, `VULN-ECC-001`, `VULN-DH-001`, `VULN-RAND-001` |
| **Warning** (3) | `VULN-HTTP-001`, `VULN-TELNET-001`, `VULN-SHA224-001` |

Plus `ENTROPY-001` (Shannon entropy ≥ 4.5 over Base64/hex/URL-safe character sets, with v2.4 negative-context filtering for test-vector vocabulary).

---

## PQC Migration Targets

| Replaces | Migration target | Rationale |
|---|---|---|
| RSA (enc/kex), DH, ECDH | **ML-KEM-768** (FIPS 203), default | NIST-standardised lattice KEM. ML-KEM-768 is the industry default; select the level with `--mlkem-level` (1=ML-KEM-512, 3=ML-KEM-768, 5=ML-KEM-1024). **CNSA 2.0 requires ML-KEM-1024 for National Security Systems.** This is standardized ML-KEM, **not** round-3 Kyber (they are non-interoperable). |
| RSA (enc/kex), DH, ECDH (transitional) | **Hybrid X25519 + ML-KEM-768** *(preferred for TLS/key-exchange)* | The accepted industry transition pattern: stays secure if either primitive is later broken |
| DSA, ECDSA | **ML-DSA** (FIPS 204) | NIST-standardised lattice signature |
| Long-lived signatures | **SLH-DSA / SPHINCS+** (FIPS 205) | Stateless hash-based signatures, larger but conservative |
| DES, 3DES, ECB, RC4, Blowfish | **AES-256-GCM** | Authenticated encryption (AEAD) |
| MD5, SHA-1, SHA-224 | **SHA-256 / SHA-3** | Quantum-resistant hash functions |
| Weak RNG | OS / language CSPRNG | `RAND_bytes`, `os.urandom`, `crypto.getRandomValues`, … |
| HTTP, Telnet | HTTPS, SSH | Encrypted transport |

The `engine/pqc/` wrappers (`QuantumWrapper`, `DilithiumWrapper`, `SphincsPlusWrapper`, `HybridKemWrapper`) are exposed to the AI remediator via `PqcContext`, which injects verbatim API signatures into prompts to suppress hallucinated function names.

---

## Empirical Evaluation

Five real open-source projects scanned end-to-end at `--entropy --proximity --fail-on=critical`. Cloned versions are pinned in `benchmarks/reports/SUMMARY.md`.

| Project | Files | v1 findings | v2.4 findings | Δ | Wall time |
|---|---:|---:|---:|---:|---:|
| rustls 0.23.21 *(negative control)* | 177 | 18 | **16** | -11% | 3.2 s |
| OpenSSH-portable v9.8p1 | 415 | 176 | **128** | -27% | 5.3 s |
| libssh2 1.11.1 | 126 | 177 | **165** | -7% | 2.1 s |
| PyCryptodome v3.20.0 | 325 | 331 | **272** | -18% | 7.3 s |
| Bouncy Castle v1.78 | 6,366 | 22,577 | **1,079** | **-95%** | 51.8 s |
| **Total** | **7,409** | **23,279** | **1,660** | **-93%** | ~70 s |

Average: ~107 files/second across the corpus. Real (non-ENTROPY) rule frequency vectors for every project are bit-identical between v1 and v2.4 once severity downgrades are accounted for — only noise dropped.

### Hand-labeled precision (OpenSSH)

Every one of the 128 OpenSSH findings was inspected at its source location and labeled TP/FP. The 11 non-RSA findings were verified individually; the 117 RSA findings were verified via stratified random sample (n=20: 4 each from `ssh-rsa.c`, `ssh-pkcs11*.c`, `ssh-keygen.c`, `sshkey*.{c,h}`, `regress/`) — 20/20 TP. Per-finding labels and reasoning are in [`benchmarks/reports/openssh_labels.csv`](benchmarks/reports/openssh_labels.csv); the protocol is in [`benchmarks/reports/openssh_labels.py`](benchmarks/reports/openssh_labels.py).

| Rule | TP | FP | n | Precision |
|---|---:|---:|---:|---:|
| VULN-RSA-001 | 117 | 0 | 117 | **1.000** |
| VULN-ECB-001 | 4 | 0 | 4 | 1.000 |
| VULN-DES-001 | 1 | 0 | 1 | 1.000 |
| VULN-SHA1-001 | 1 | 0 | 1 | 1.000 |
| VULN-MD5-001 | 1 | 1 | 2 | 0.500 |
| ENTROPY-001 | 0 | 3 | 3 | 0.000 |
| **Overall** | **124** | **4** | **128** | **0.969** |

The 4 false positives cluster in two characterisable patterns: 3 alphabet/charset constants flagged as entropy (bcrypt, base64, mktemp), and 1 multi-line C string continuation that escaped the comment stripper. Both are individually fixable.

Recall is not yet measured. The labeling protocol is documented in `benchmarks/reports/openssh_labels.py` and is designed to be reproducible by an independent reviewer.

---

## Test Repository

The `test_repo/` directory contains seven deliberately-vulnerable files spanning C++, Python, Java, Go, Rust, and JavaScript. Use it as a smoke test:

```bash
./build/cli/quantum-migrate test_repo/ --entropy --proximity --output=audit.txt
```

Expected: ~36–42 findings (depending on whether entropy/proximity are enabled). Per-language expected-finding matrix is in `test_repo/README.md`.

---

## Project Structure

```
Quantum-Migration-Toolkit/
├── CMakeLists.txt              # Root build orchestrator
├── Dockerfile                  # Multi-stage Alpine build (~minimal runtime)
├── README.md                   # This file
├── research_paper.md           # Full v2.0–v2.4 paper (1,075 lines, 38 refs)
├── audit_report.txt            # Sample text scan report
│
├── cli/
│   ├── CMakeLists.txt
│   └── main.cpp                # 12-stage pipeline orchestrator
│
├── engine/
│   ├── CMakeLists.txt          # libquantum_migrate static library
│   ├── SimpleJson.hpp          # In-tree JSON parser
│   ├── rules.json              # 18 vulnerability rules with CWE mappings
│   ├── ai/
│   │   ├── AiRemediator.hpp    # llama.cpp + ChatML prompts
│   │   └── PqcContext.hpp      # Rule → API mapping (anti-hallucination)
│   ├── patch/
│   │   ├── AutoRemediator.hpp  # Unified-diff patch generation
│   │   ├── DependencyInjector.hpp  # Vendor SDK + patch build files
│   │   └── OutputFormatter.hpp # Text + SARIF 2.1.0
│   ├── pqc/
│   │   ├── AES.hpp             # AES-256-GCM (authenticated)
│   │   ├── FileEncryptor.{hpp,cpp}  # Hybrid ML-KEM + AES-GCM + ML-DSA-signed file format
│   │   ├── QuantumKyber.{hpp,cpp}  # ML-KEM, ML-DSA, SLH-DSA, hybrid X25519+ML-KEM
│   └── scan/
│       ├── AstEngine.hpp       # Tree-sitter AST validation
│       ├── BaselineManager.hpp # FNV-1a fingerprint, .quantum-baseline.json
│       ├── CommentStripper.hpp # Comment + string-literal blanking
│       ├── EntropyDetector.hpp # Shannon entropy + charset filters
│       ├── IgnoreHandler.hpp   # .gitignore / .quantumignore + built-in defaults
│       ├── ProximityAnalyzer.hpp
│       ├── RegexEngine.hpp     # std::regex / RE2 abstraction
│       ├── RuleEngine.hpp      # rules.json loader
│       ├── ScanTypes.hpp       # ScanResult, ScanConfig, etc.
│       └── ThreadPool.hpp      # C++17 worker pool
│
├── models/                     # GGUF model drop point (gitignored — see DOWNLOAD_MODEL.txt)
├── test_repo/                  # 7-language vulnerable smoke-test corpus
└── benchmarks/
    └── reports/                # 5-project scan output, hand labels, SUMMARY.md
```

---

## Citation

If you use Quantum-Migration-Toolkit in academic work, please cite the project paper:

```bibtex
@misc{khan2026qmt,
  author = {Savaid Khan},
  title  = {Quantum Migration Toolkit: A Practical Static Analysis and Automated
            Remediation Framework for Post-Quantum Cryptographic Migration in
            Polyglot Codebases},
  year   = {2026},
  note   = {See research_paper.md in the project repository}
}
```

---

## Contributing

Contributions welcome — adding new vulnerability patterns, language grammars for Tree-sitter, additional PQC algorithms, or documentation improvements. Please open an issue or PR on GitHub.

---

## License

MIT.

---

## Keywords & Topics

post-quantum cryptography · PQC migration · quantum-safe encryption ·
ML-KEM · ML-DSA · FIPS 203 · FIPS 204 · cryptographic vulnerability scanner ·
RSA migration · quantum security · NIST PQC · quantum computing security

---

## Related Projects

- [liboqs](https://github.com/open-quantum-safe/liboqs) — Open Quantum Safe cryptographic library (provides ML-KEM, ML-DSA, SLH-DSA implementations)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography) — FIPS 203, 204, 205
- [llama.cpp](https://github.com/ggml-org/llama.cpp) — Local LLM inference engine
- [tree-sitter](https://github.com/tree-sitter/tree-sitter) — Incremental parser for AST validation
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — IETF hybrid KEM specification

---

**Start your quantum-safe migration today with a single command.**
