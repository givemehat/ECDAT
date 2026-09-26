# Competitive Intelligence — SIH26164

Evidence base for `ANALYSIS.md`, which drives the upgrades in `engine/purpose.py`,
`engine/fspolicy.py`, the comment-blanking pass in `engine/scanner.py`, and
`tests/test_competitive_upgrades.py`.

## Contents

| Path | What it is |
|---|---|
| `ANALYSIS.md` | **Start here.** Single-repo analysis, take/adapt/reject decisions, strategic position |
| `scrape_github.py` | 24 GitHub Search API queries → `raw/*.json` |
| `filter.py` | Relevance-scores the 349 scraped repos → `shortlist.csv` (119) |
| `fetch_readmes.py` | README + metadata for the 17 most relevant → `raw_readme/`, `repos.json` |
| `profile.py` | Compact per-repo profile → `profiles.txt` |
| `inventory.csv` | All 349 repos: stars, licence, language, topics |
| `shortlist.csv` | The 119 relevant ones, with a relevance score |
| `raw/` | Raw API responses, committed so every claim is checkable offline |
| `raw_readme/` | The 17 fetched READMEs, verbatim |

## Reproducing

```bash
python scrape_github.py      # ~75s; unauthenticated rate limit may reject some queries
python filter.py
python fetch_readmes.py      # ~40s
python profile.py > profiles.txt
```

The scrape is **unauthenticated** and therefore rate-limited. In the run recorded here, 6 of 24
search queries returned HTTP 403; all were in the `in:description` slice. Re-running may reject
different queries — `raw/_per_query.json` records exactly which succeeded, including the
`total_count` for each, so a partial run is never mistaken for a complete one.

## Headline finding

**Two other teams are already building SIH26164.** `sgtsujith141-wq/cryptodrishti` (Team Zero-Day)
is 27 commits in with 7 sensors and 664 tests, and `saitharunpotluri-creator/ECDAT` is a 3-commit
Next.js + Semgrep prototype. This changed the plan: we stopped competing on sensor count and
started competing on measured accuracy, scanner safety, and traceability. See `ANALYSIS.md` §6.

## What we adopted, and the test that pins it

| Idea | Source | Pinned by |
|---|---|---|
| Adversarial decoy suite | Quantum-Safe-Scan | `tests/test_competitive_upgrades.py::test_decoy_*` |
| Comment blanking before rule matching | found *by* the decoy suite | `::test_decoy_java_yields_no_findings` |
| Assurance taxonomy (capability/declared/used/observed) | cryptodrishti C1 | `::test_evidence_class_maps_to_assurance` |
| Purpose resolution with UNRESOLVED | cryptodrishti C2 | `::test_unresolved_purpose_refuses_to_name_a_pqc_target` |
| Filesystem containment + credential-store refusal | cryptodrishti C5 | `tests/test_fspolicy.py` |

## A note on what the decoy suite actually found

The first run of the decoy tests failed, and the failures were worth more than the tests:

* `Decoy.java` reported an RSA finding from `KeyPairGenerator.getInstance("RSA")` **inside a
  Javadoc block**. The scanner had no comment stripping at all. Fixed — see `_strip_comments`.
* `decoy_source.py` reported SHA-256 and MD5 from `hashlib.sha256(...)` — and that was **correct**.
  Those are real invocations. The fixture was mislabelled as a decoy, so the test was rewritten to
  assert specifically about the prose region, with a converse test that the real calls are still
  found. Over-broad suppression would have looked like a clean scan while silently losing
  detections, which is the worse failure.

Both are recorded here because the process is the point: the measurement found a defect that no
other test in the suite was looking for.
