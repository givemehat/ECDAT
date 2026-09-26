# crypto-lab-harvest-timeline

[![CI](https://github.com/systemslibrarian/crypto-lab-harvest-timeline/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-harvest-timeline/actions/workflows/ci.yml)
[![Deploy](https://github.com/systemslibrarian/crypto-lab-harvest-timeline/actions/workflows/deploy.yml/badge.svg)](https://github.com/systemslibrarian/crypto-lab-harvest-timeline/actions/workflows/deploy.yml)

## What It Is

This tool operationalizes the Harvest-Now-Decrypt-Later threat into concrete, quantified risk for specific data types, algorithms, and organizations. It is built around the **Mosca Inequality**:

```
X + Y > Z  →  YOUR DATA IS ALREADY AT RISK

  X = data shelf life (years data must stay secret)
  Y = migration time (years to deploy PQC protection)
  Z = CRQC arrival time (years until cryptographically-relevant quantum computer)
```

*Citation: Michele Mosca, "Cybersecurity in an era with quantum computers: will we be ready?" IEEE Security & Privacy, 2018.*

CRQC arrival probabilities use the **GRI/evolutionQ Quantum Threat Timeline Report 2024** (Mosca & Piani, December 2024) — the most recent edition built on a survey of quantum-computing experts. The survey asks each expert for a likelihood band, then averages those bands two ways: an "optimistic" reading takes the upper edge of each band, a "pessimistic" reading the lower edge. The figures below are those **averaged probabilities that a CRQC exists by each horizon** — they are not the share of experts holding a view:

| Horizon | 10-year | 15-year | 20-year |
|---------|---------|---------|---------|
| Averaged probability | ~19% (pessimistic) to ~34% (optimistic) | ~39% (pessimistic) | ~60% (pessimistic) |

The report publishes the pessimistic reading at all three horizons but the optimistic reading only at 5 years (~14%) and 10 years (~34%), so this demo's aggressive and median scenarios extrapolate beyond 10 years rather than quoting the report. Separately, the report also counts respondents — at 15 years, 21 of 32 experts put the likelihood at about 50% or more — but that is a different statistic from the averaged probability and is not what the curves plot.

The simulator covers **20+ cryptographic algorithms** across **4 CRQC scenarios** (aggressive, median, pessimistic, ultra-pessimistic) and analyzes **5 realistic organizational profiles**.

It also teaches the *mechanism* behind the accounting, not just the arithmetic: a **"How the harvest works" mini-timeline** shows ciphertext being copied today, stored for years, and decrypted once a CRQC arrives (so "your data is already at risk" is a mechanism, not a slogan); the load-bearing terms **CRQC**, **Shor's algorithm**, and **Grover's algorithm** carry inline hover/focus glosses wherever they first appear (cross-linked to the dedicated Shor and Grover demos); the exposure-probability chart draws the **surveyed 2024 anchor horizons** as ringed dots distinct from the smoothed interpolation between them; and selecting a Grover-only cipher (AES-128) overlays a **faint full-strength reference curve** so the 0.5 "weakened, not broken" modifier is visible rather than silent.

## When to Use It

- Answering **"do I need to migrate, and when?"** for specific data assets in your organization
- Communicating the HNDL threat to non-technical executives or board members (regulatory risk + data exposure framing)
- Planning **migration priorities** based on data sensitivity lifetime, not just algorithm age
- Comparing the **cost of migrating now vs. waiting** 1, 2, 5, or 10 years
- **Building new systems** quantum-safe from day 1 (personal application section)
- Do NOT use it for making binding legal/regulatory compliance decisions without independent expert review — the Mosca Inequality is a planning framework and this is a teaching demo, not a compliance tool.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-harvest-timeline](https://systemslibrarian.github.io/crypto-lab-harvest-timeline/)**

Six interactive exhibits let you compute X+Y vs Z for a single asset, profile a whole organization's portfolio, watch year-by-year exposure curves from 2026 to 2076 across all four CRQC scenarios, run a cost-of-delay what-if table, and generate quantum-safe architecture recommendations for new systems. Results update live as you change data type, algorithm, lifetimes, and scenario. Exhibit 6 then leaves projection behind and runs the cryptography: protect the organization's records under a real (toy) RSA-KEM, re-key what you still hold to AES-256, and let a CRQC factor the modulus for real.

## What Can Go Wrong

- **CRQC estimates are uncertain.** The 2024 GRI survey gives ranges (~19–34% at 10 years, not point estimates), and averaging coarse likelihood bands is itself a simplification the report warns about. The aggressive scenario assumes breakthroughs that might not happen. The pessimistic assumes engineering bottlenecks that might be solved.
- **Data sensitivity lifetimes vary.** "30 years for medical records" is typical but specific records may be shorter or longer. Regulatory minimums are floors, not averages.
- **Migration times are estimates.** Actual migration time depends heavily on organizational maturity, vendor support, and crypto-agility. 5 years for a small org could be 2 with good architecture or 10 with legacy constraints.
- **Mosca Inequality is a planning tool, not a proof.** Satisfying the inequality doesn't guarantee safety — implementation vulnerabilities (like KyberSlash) could still leak data even with quantum-safe algorithms.
- **Simplifications.** Real organizations have thousands of cryptographic dependencies, complex migration sequencing, and technical debt. This tool gives first-order estimates.
- **Regulatory changes.** CNSA 2.0, NIS2, and other frameworks may update their timelines. "By 2030" or "by 2035" dates are current as of 2025–2026 but subject to political change.

## Real-World Usage

The Mosca Inequality was formalized by Michele Mosca in "Cybersecurity in an era with quantum computers: will we be ready?" (IEEE Security & Privacy, 2018), building on his earlier work at the University of Waterloo and evolutionQ. The Global Risk Institute / evolutionQ Quantum Threat Timeline Report has been published annually since 2019; the 2024 edition (authored by Mosca and Marco Piani) is the most recent expert survey, and reports the highest averaged 5- and 10-year likelihoods the series has recorded. The 2025 GRI publication under that banner, *Quantum Threat Timeline 2025: Executive Perspectives on Barriers to Action*, is a companion report of interviews with financial-industry executives rather than a new survey of quantum-computing experts, so it carries no updated CRQC probability estimates.

The framework has been adopted by NIST, NSA (CNSA 2.0), UK NCSC, Germany BSI, ETSI, and multiple Fortune 500 cryptographic risk programs. The "Harvest-Now-Decrypt-Later" terminology itself was popularized by this risk model and now appears in NIST SP 1800-38B and related guidance documents.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-harvest-timeline
cd crypto-lab-harvest-timeline
npm install
npm run dev
```

## Related Demos

- [crypto-lab-harvest-vault](https://systemslibrarian.github.io/crypto-lab-harvest-vault/) — the HNDL concept demonstration this calculator quantifies. **The two labs share Mosca's inequality deliberately and split the work:** harvest-vault is the *threat* lab (why harvested traffic is already lost, proven by capturing a live handshake and breaking it after a PQC upgrade), and this one is the *planning* lab (which assets in a fleet cross a CRQC unprotected, what each year of delay adds, and — in Exhibit 6 — what a migration does and does not reach).
- [crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/) — hybrid key-rotation and migration planning under CNSA 2.0.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — hybrid PQ+classical TLS 1.3 handshake.
- [crypto-lab-shor](https://systemslibrarian.github.io/crypto-lab-shor/) — what a CRQC actually does to RSA (Shor's algorithm).
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM-768, a quantum-safe destination algorithm.

## Six Exhibits

Above the exhibits, a **"How the harvest works" mini-timeline** grounds *why* X + Y > Z means exposure — three color-coded steps (harvest → store → decrypt) using the same X/Y/Z palette as the inequality, before any algebra appears.

### Exhibit 1 — Personal Risk Calculator
Interactive single-asset Mosca Inequality calculator. Choose a data type, algorithm, data lifetime (X), migration time (Y), and CRQC scenario (Z). Results update live. A **live plain-English sentence** re-narrates the cause-and-effect on every slider move ("Your medical records must stay secret for 30 yrs; you need 5 yrs to migrate; a CRQC likely arrives in 12 yrs — so 35 > 12, exposed for 23 years"), above the visual X+Y vs Z bar and a specific recommendation. The algorithm status badge glosses the **Shor/Grover** mechanism inline.

### Exhibit 2 — Organization Risk Profile
Multi-asset dashboard for 5 preset organizations (small medical clinic, mid-size bank, government intelligence agency, tech startup, research university). Shows per-asset risk table, aggregate TB exposure, and priority migration order.

### Exhibit 3 — Exposure Curve Over Time
SVG year-by-year exposure probability chart (2026–2076). Overlays all 4 CRQC scenarios. Switch algorithms to see how curves shift. Quantum-safe algorithms (ML-KEM-768, etc.) hold flat at 0%. The **surveyed 2024 anchor horizons** are drawn as ringed dots (line between them is smoothed interpolation, captioned as such — not a forecast), and Grover-only ciphers overlay a **dashed full-strength reference curve** so the 0.5 modifier is visible.

### Exhibit 4 — Cost of Delay
What-if table: what does starting migration now vs. in 1, 2, 5, or 10 years look like? Shows exposed assets, exposed TB, and whether you beat or miss the CRQC arrival window.

### Exhibit 5 — Personal Application
Concrete quantum-safe architecture recommendations for new systems. Includes a worked example for a ministry app (PrayerWarriors) with asset-by-asset algorithm recommendations, cross-linked to other tools in this series.

### Exhibit 6 — Migration, Executed
The one exhibit that performs cryptography rather than projecting it (`src/rekey.ts`). The selected organization's first three assets are encrypted under a real RSA-KEM (random integer wrapped with RSA, SHA-256 of that integer as the AES-256-GCM data key), plus two 2026 "wire sessions" the adversary is holding a copy of. You then choose the order of two buttons:

- **Migrate the archive to AES-256** — unwraps each record you still hold with the private key and re-encrypts it under a locally held symmetric key, discarding the RSA wrapper. Symmetric-only protection for data at rest is quantum-safe: Grover halves AES-256 to 128-bit work.
- **CRQC arrives** — really factors the modulus with Pollard's rho, recovers the private exponent, and attempts every record. Re-keyed records are attacked too: the attacker derives a key from the recovered exponent and AES-GCM rejects it.

Migrate first and it reads 2 of 5 (the two copies that already left). Skip the migration and it reads 5 of 5. Every figure in the verdict — iteration count, elapsed time, read counts, byte-identical checks — is measured from that run.

**Toy scale, stated on the page:** the modulus is two 32-bit primes so rho terminates in a browser tab. RSA-2048 is 2048 bits and is not factorable this way; the exhibit stands in for what Shor's period finding does to a real modulus, which is not a search.

## Algorithm Coverage

**Broken by Shor's algorithm (urgent migration needed):**  
RSA-2048, RSA-4096, ECDSA-P256, ECDSA-P384, Ed25519, X25519 ECDH, TLS-ECDSA, and common hybrid combinations thereof.

**Partially affected by Grover's algorithm:**  
AES-128 (64-bit effective security — weak long-term), AES-256 (128-bit — still strong), SHA-256/SHA-384.

**Quantum-safe (migrate TO these):**  
ML-KEM-768, ML-KEM-1024 (NIST FIPS 203, 2024), ML-DSA-65, ML-DSA-87 (FIPS 204, 2024), SLH-DSA (FIPS 205, 2024), LMS_H10, XMSS_H10.

## Stack

- **Vite** + **TypeScript strict** + **Vanilla CSS**
- **Vitest** for unit + DOM + a11y tests (104 tests: Mosca math, exposure curves and their survey anchors / Grover-modifier invariants, aggregate risk, catalog invariants, happy-dom smoke tests that mount the UI and verify all six exhibits plus the harvest mini-timeline, jargon glosses, plain-English narration and the exposure-chart ghost line render, a WCAG-AA contrast guard that parses the CSS palette and asserts every text color clears 4.5:1 in both light and dark themes, and Exhibit 6's cryptography — Miller-Rabin known answers, RSA key/inverse invariants, Pollard's rho recovering exactly the generated primes, and the migrate-then-attack comparison in both orders)
- SVG for timeline visualization (no canvas dependencies)
- No backends, no tracking, no `Math.random()`. Every projection is deterministic; Exhibit 6 draws real key material from `crypto.getRandomValues`, so its keys and ciphertexts differ on every run by design
- GitHub Pages deployment

## Accessibility & Mobile

Built to meet **WCAG 2.1 AA** and work on a phone:

- **Contrast:** every text color is verified ≥4.5:1 against the surfaces it sits on, in **both** light and dark themes (a CSS-parsing contrast test in CI fails the build on any regression). Severity and accent colors are themed per mode so nothing relies on a bright-on-white pairing.
- **Color is never the only signal:** risk levels carry an icon + text label, scenario curves carry a legend and labels, and the exposure chart renders on a fixed dark panel so its multi-hue lines stay legible regardless of theme.
- **Keyboard & screen reader:** skip link, single `banner`/`main`/`nav` landmarks, labelled form controls, `aria-live` result regions, `aria-sort` + keyboard-operable sortable tables, `aria-pressed` preset chips, an SVG `<title>` describing the chart, keyboard-focusable jargon glosses with `aria-description` (no nested-interactive traps), and a visible focus ring (`:focus-visible`).
- **Motion & output:** honors `prefers-reduced-motion`, ships a print stylesheet, and degrades to a styled `<noscript>` fallback when JavaScript is off.
- **Touch & layout:** ≥44px touch targets, responsive breakpoints at 900/640px, horizontally scrollable tables, and `dvh`-based sizing.

## Development

```bash
npm install        # install dependencies
npm run dev        # start Vite dev server (http://localhost:5173)
npm test           # run the Vitest suite once
npm run test:watch # run tests in watch mode
npm run build      # type-check + build to dist/
npm run preview    # preview the production build
```

CI runs `npm test` and `npm run build` on every push and PR to `main`. The
`deploy.yml` workflow publishes `dist/` to GitHub Pages on push to `main`.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
