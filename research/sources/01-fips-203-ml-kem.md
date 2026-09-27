# NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)

| | |
|---|---|
| **Publisher** | National Institute of Standards and Technology (NIST), Computer Security Resource Center |
| **Document** | FIPS 203 |
| **Status** | **FINAL** |
| **Published** | 13 August 2024 (draft 24 August 2023) |
| **DOI** | https://doi.org/10.6028/NIST.FIPS.203 |
| **URL fetched** | https://csrc.nist.gov/pubs/fips/203/final |
| **Fetched on** | 2026-09-27 |

## What the source says

Verbatim from the abstract on the CSRC publication page:

- "This standard specifies a key-encapsulation mechanism called ML-KEM."
- "The security of ML-KEM is related to the computational difficulty of the Module Learning with
  Errors problem. At present, ML-KEM is believed to be secure, even against adversaries who
  possess a quantum computer."
- "This standard specifies three parameter sets for ML-KEM. In order of increasing security
  strength and decreasing performance, these are **ML-KEM-512, ML-KEM-768, and ML-KEM-1024**."

### Document history (from the CSRC page)

- 08/24/23: FIPS 203 (Draft)
- 08/13/24: FIPS 203 (Final)

### Known open item

The page carries a planning note dated **11/17/2025**: "We've identified an issue that will be
corrected in a future update/revision of this publication." An errata spreadsheet is listed
under Documentation. A revision is therefore anticipated; the byte figures in
`engine/recommender.py` should be re-checked against it before a final release.

## What could NOT be verified from this page

The publication landing page states the algorithm families and their relative ordering but does
**not** publish the encapsulation-key, ciphertext or decapsulation-key sizes in bytes. Those
figures live inside the PDF. **This file therefore does not assert them.**

The byte values currently in `engine/recommender.py` (`ML_KEM_SIZES`) are therefore *unverified
against the primary source* and are flagged as such in `research/sources/INDEX.md`. They are
consistent with the widely reported round-3 submission sizes, but "widely reported" is not a
citation.

**Action before release:** extract Table 1 of FIPS 203 from the PDF and reconcile.

## What this means for our tool

- `engine/cbom.py` QUANTUM_CATEGORY maps `ML-KEM-512 -> 1`, `-768 -> 3`, `-1024 -> 5`. The
  three-set ladder is confirmed by the source. The category NUMBERS are not stated on this
  page and remain sourced from SP 800-57 equivalence.
- `engine/recommender.py` recommends **ML-KEM-768** for general key establishment. The source
  says the three sets trade security against performance in one direction only — increasing
  security, decreasing performance — which supports presenting 768 as the middle choice
  rather than claiming it is universally best.
- The parameter-set names in `PQC_FAMILIES` are `ML[-_]?KEM`, which matches all three exactly.
