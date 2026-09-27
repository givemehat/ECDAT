# Primary sources

Notes built by **fetching the publisher's own page or PDF**, not from recall. Every claim below
carries the URL it came from. Where a document could not be retrieved, the file says so instead of
guessing — an admitted gap is more useful than a confident fabrication.

## Verified

| # | Source | Status | URL | Authoritative for |
|---|---|---|---|---|
| 01 | **NIST FIPS 203** — Module-Lattice-Based KEM (ML-KEM) | FINAL 2024-08-13 | https://csrc.nist.gov/pubs/fips/203/final | The three ML-KEM parameter sets: 512 / 768 / 1024 |
| 02 | **NIST FIPS 204** — Module-Lattice-Based Digital Signature (ML-DSA) | FINAL 2024-08-13 | https://csrc.nist.gov/pubs/fips/204/final | ML-DSA is the primary NIST signature standard |
| 04 | **NIST IR 8547** — Transition to PQC Standards | **INITIAL PUBLIC DRAFT**, 2024-11-12 | https://csrc.nist.gov/pubs/ir/8547/ipd · PDF: https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf | Deprecation/disallowance timeline, per-algorithm strength tiers, NSM-10 basis for 2035 |

## Verified as a negative result (worth as much as a positive one)

| Source | What it is | URL |
|---|---|---|
| **NIST SP 800-207** | **Zero Trust Architecture** (FINAL 2020-08) — *not* the PQC roadmap | https://csrc.nist.gov/pubs/sp/800/207/final |
| **NIST SP 800-227** | **Recommendations for Key-Encapsulation Mechanisms** (FINAL 2025-09-18) — KEM implementation guidance, *not* a transition timeline | https://csrc.nist.gov/pubs/sp/800/227/final |

Both were assumed to be post-quantum migration documents. Neither is. **No `engine/` file cites
either number**, so the shipped code was never wrong — the error was in a research draft and is
recorded in `04-` rather than quietly deleted. The lesson: locate a document from the NIST
publication index before citing a number that "looks right".

## What the IR 8547 PDF confirmed, and one thing it corrected

Verified verbatim from the PDF (29 pages):

- 112-bit classical public-key: **deprecated after 2030, disallowed after 2035**
- ≥ 128-bit classical public-key: **disallowed after 2035**
- **ML-DSA-44 → category 2**, ML-DSA-65 → 3, ML-DSA-87 → 5

The category numbers independently confirm the fix made in `engine/cbom.py`, where ML-DSA-44 had
been given NIST category 1.

It also exposed a **live imprecision in our code**: `engine/mosca.py` applies a single flat
`year: 2035` labelled "disallowed" to every artefact, but the source table is *strength-dependent*,
and for the 112-bit tier NIST says it intends to **deprecate rather than fully disallow**, letting
organisations "continue using these algorithms … as they migrate". The flat label overstates the
112-bit case. Recorded in `04-`; deliberately not patched here because it changes compliance output
and needs its own test pass.

## Not yet verified — byte sizes

`engine/recommender.py` carries `ML_KEM_SIZES` and `ML_DSA_SIZES` byte figures that are consistent
with the round-3 submissions but are **not yet traced to the FIPS PDFs**. The CSRC landing pages
do not publish them. FIPS 203 and 204 both carry errata notices dated after publication (11/17/2025
and 07/31/2026 respectively), so a revision is expected.

**Do not present these figures as standard-derived until extracted from the PDFs.**

## Not started

- FIPS 205 (SLH-DSA), NSA CNSA 2.0 FAQ, NIST SP 800-57 Rev 5, CycloneDX 1.7 crypto use case,
  Mosca's inequality, and the Kyber→ML-KEM renaming history. FIPS 203/204/205 and the NIST
  renaming history are partly covered by the verified NIST news release above.
- PHP and Ruby corpora. Recall for both language packs remains **unmeasured**.

## Policy

No competing or third-party implementation was fetched, quoted, or consulted in producing these
notes. Every fact traces to a NIST, IETF, or standards-body publication.
