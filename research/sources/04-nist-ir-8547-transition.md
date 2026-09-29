# NIST IR 8547 — Transition to Post-Quantum Cryptography Standards

| | |
|---|---|
| **Publisher** | NIST, Computer Security Resource Center |
| **Document** | NIST IR 8547 (**Initial Public Draft**) |
| **Published** | 12 November 2024 |
| **Comment period** | closed 10 January 2025; comments received and published 21 January 2025 |
| **DOI** | https://doi.org/10.6028/NIST.IR.8547.ipd |
| **URL fetched** | https://csrc.nist.gov/pubs/ir/8547/ipd |
| **Fetched on** | 2026-09-27 |

## STATUS — READ THIS FIRST

**This is an INITIAL PUBLIC DRAFT, not a final standard.** The DOI itself carries the `.ipd`
suffix. The CSRC page's document history lists exactly one entry: `11/12/24: IR 8547 (Draft)`.
There is no "Final" entry.

Anything IndraMesh says about IR 8547 must therefore be presented as a *proposed* transition plan.
The tool does this correctly today: `engine/mosca.py` labels the policy
`"NIST IR 8547 -- quantum-vulnerable PKC disallowed"`, and the console separately warns that a
policy deadline is a procurement date while Z is a cryptanalytic estimate. That distinction is
the right one and should not be softened.

## What the source says

Verbatim from the abstract:

- "This report describes NIST's expected approach to transitioning from quantum-vulnerable
  cryptographic algorithms to post-quantum digital signature algorithms and key-establishment
  schemes."
- "It identifies existing quantum-vulnerable cryptographic standards and the quantum-resistant
  standards to which information technology products and services will need to transition."
- "It is intended to foster engagement with industry, standards organizations, and relevant
  agencies to facilitate and accelerate the adoption of post-quantum cryptography."

Authors: Dustin Moody, Ray Perlner, Andrew Regenscheid, Angela Robinson, David Cooper.

## VERIFIED AGAINST THE PDF — transition timeline

Downloaded and text-extracted from the official source:
`https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf` (29 pages, 722 379 bytes).
Every page footer in the extracted text reads **"NIST IR 8547 ipd (Initial Public Draft)"**,
confirming the draft status on the document itself, not only in the DOI.

### Table 3 — post-quantum digital signature replacements (verbatim)

| Digital Signature Algorithm | Parameters | Security Strength | Security Category | Transition |
|---|---|---|---|---|
| ML-DSA [FIPS204] | ML-DSA-44 | 128 bits | **2** | — |
| | ML-DSA-65 | 192 bits | **3** | — |
| | ML-DSA-87 | 256 bits | **5** | — |
| ECDSA [FIPS186] | 112 bits of security strength | | | **Deprecated after 2030, Disallowed after 2035** |
| ECDSA [FIPS186] | ≥ 128 bits of security strength | | | Disallowed after 2035 |
| EdDSA [FIPS186] | ≥ 128 bits of security strength | | | Disallowed after 2035 |
| RSA [FIPS186] | 112 bits | | | **Deprecated after 2030, Disallowed after 2035** |
| RSA [FIPS186] | ≥ 128 bits | | | Disallowed after 2035 |

### Key establishment transitions (verbatim)

| Scheme | Parameters | Transition |
|---|---|---|
| Finite Field DH and MQV [SP80056A] | 112 bits | **Deprecated after 2030, Disallowed after 2035** |
| Finite Field DH and MQV [SP80056A] | ≥ 128 bits | Disallowed after 2035 |
| Elliptic Curve DH and MQC [SP80056A] | 112 bits | **Deprecated after 2030, Disallowed after 2035** |
| Elliptic Curve DH and MQC [SP80056A] | ≥ 128 bits | Disallowed after 2035 |
| RSA [SP80056B] | 112 bits | **Deprecated after 2030, Disallowed after 2035** |

### THE NUANCE OUR CODE CURRENTLY GETS WRONG

Verbatim from the draft:

> "These guidelines had projected that NIST would disallow public-key schemes that provide 112
> bits of security on **January 1, 2031**. However, based on the need to migrate to
> quantum-resistant algorithms during this timeframe, **NIST intends to instead deprecate**
> classical digital signatures at the 112-bit security level. **Organizations may continue using
> these algorithms and parameter sets as they migrate** to the post-quantum signatures identified
> in Table 3."

And, for key establishment:

> "NIST intends to instead **deprecate rather than fully disallow** classical key-establishment
> schemes at the 112-bit security level. Organizations may continue using these algorithms and
> parameter sets as they migrate to ML-KEM or other approved quantum-resistant techniques.
> However, in order to mitigate the risk of 'harvest now, decrypt later' attacks on network
> communications, application-specific guidance […]"

So the 2035 disallowance attaches to the **≥ 128-bit** strength tier, while the **112-bit** tier
is **deprecated** (usable during migration) rather than disallowed at the same time. The earlier
"1 January 2031" date was **superseded**.

`engine/mosca.py` currently records `{"label": "NIST IR 8547 -- quantum-vulnerable PKC
disallowed", "year": 2035}` — a single flat year for every artefact, and the word "disallowed".
That is a simplification of a strength-dependent table, and the label overstates the 112-bit case.

**Recommended fix, deliberately NOT applied here** (it changes compliance output and needs its own
test pass): make the policy deadline strength-dependent, and label the 112-bit tier as
"deprecated, usable during migration" rather than "disallowed". Recorded so the change is not lost.

## Origin of the 2035 target

The draft grounds the date in **NSM-10** (National Security Memorandum 10), quoted verbatim:

> "[NSM10]: 'Any digital system that uses existing public standards for public-key cryptography […]
> could be vulnerable to an attack by a Cryptographically Relevant Quantum Computer (CRQC). […]
> the United States must prioritize the timely and equitable transition of cryptographic systems to
> quantum-resistant cryptography, **with the goal of mitigating as much of the quantum risk as is
> feasible by 2035**.'"

The draft also hedges: "migration timelines may vary based on the specific use case or
application", and notes that NIST "will work to ensure that these varying timelines are
acknowledged and supported while maintaining the overall goal of achieving widespread PQC
adoption by 2035."

That hedge is worth honouring in the console. `engine/mosca.py` already refuses to conflate Z with
a policy deadline; this adds a second reason not to present a single hard year as universal.

## A CORRECTION WORTH RECORDING

An earlier draft of these notes cited **NIST SP 800-207** as the PQC migration roadmap. That is
**wrong**: SP 800-207 is *Zero Trust Architecture* (final, August 2020), verified at
https://csrc.nist.gov/pubs/sp/800/207/final. It has nothing to do with post-quantum migration.

Likewise **SP 800-227** is *Recommendations for Key-Encapsulation Mechanisms* (final,
18 September 2025) — KEM implementation guidance, not a transition timeline.

Neither document number is referenced anywhere in `engine/`, so the shipped code was never
wrong. The error existed only in the research notes, and it is recorded here rather than
silently corrected: the PQC migration roadmap that is commonly *assumed* to exist under some
800-2xx number should be located from the NIST publication index before it is cited at all.

## What this means for our tool

- The draft status is the single most important fact. A tool that says "NIST requires X by
  2035" when NIST has published a draft would be making a compliance claim it cannot support.
  `engine/mosca.py` already separates "policy deadline" from "cryptanalytic estimate" in the
  console, which is the right posture.
- IR 8547 is the correct document to cite for the *direction* of travel: quantum-vulnerable
  public-key cryptography is being retired in favour of the FIPS 203/204/205 standards.
