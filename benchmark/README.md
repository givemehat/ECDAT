# External accuracy benchmark

Measures `engine.scanner.ECDATScanner` for **quantum-vulnerable cryptographic use** against
**externally sourced** corpora pinned by commit SHA, scored against committed line-level
ground truth.

## One command

```
python benchmark/run_benchmark.py
```

That clones any missing corpus, verifies every pinned SHA, verifies every label against the
corpus, runs the scanner, and rewrites `RESULTS.md` and `results.json`.

```
python benchmark/run_benchmark.py --fetch      # hard-reset corpora to the pinned commits first
python benchmark/run_benchmark.py --no-write   # print only
python benchmark/run_benchmark.py --only paramiko
```

## Layout

| path | what it is |
|---|---|
| `run_benchmark.py` | the harness. The only thing you need to run. |
| `annotate.py` | the **labeller**. Produces `labels/*.json`. Not used at measurement time. |
| `pqtaxonomy.py` | the definition of "quantum-vulnerable", kept separate from the detector. |
| `labels/*.json` | the committed ground truth. Frozen data. See `labels/README.md`. |
| `labels/README.md` | the labelling criterion, in full, with its known weaknesses. |
| `RESULTS.md` | human-readable results, with raw counts beside every ratio. |
| `results.json` | the same numbers, machine-readable. |
| `corpora/` | third-party clones. **Git-ignored**; re-fetched at a pinned SHA. |

## Corpora

| corpus | pinned commit | what it is |
|---|---|---|
| `cryptoapi_bench` | `e6b6b50fef6970151300c1ac2de62e188ba6de19` | CryptoAPI-Bench (Afrose et al., IEEE SecDev 2019). 203 Java files. Published, peer-reviewed, third-party -- but *constructed* micro-programmes, not production code. |
| `paramiko` | `142f593e40ad767c5e3556cbace66dc84589620c` | paramiko, the Python SSH library. Real production code, so it is the corpus that actually speaks to real-world accuracy. |
| `xcrypto_ssh_algorithms` | `7a4a4d6beae2222add4437a0910bd48414e19211` | golang.org/x/crypto, Go's official crypto library, scoped to **three files** of the `ssh/` package (`cipher.go`, `mac.go`, `mlkem.go`) — the algorithm tables and the hybrid ML-KEM-768 KEX. Real production code. The other 28 non-test files in that package are cloned but **not** annotated and **not** scanned, so the figure is a three-file slice, not a package result. |

### `scan_files`, and why a file list exists

Most corpora are measured by walking a directory. `xcrypto_ssh_algorithms` is declared with
`scan_files` instead, because its honest unit is a hand-picked set of files that have been read
in full. Widening the scope to the unannotated remainder would not make recall *worse* — it would
make it **unknowable**, and a number derived from labels nobody wrote is not evidence. The list
is opt-in per corpus and `scan_subdir` behaviour is unchanged for the other two.

## The caveat that matters most

**No** corpus labels *quantum vulnerability*. CryptoAPI-Bench labels *API misuse*; paramiko and
x/crypto ship no labels at all. The ground truth used here is therefore hand-annotated by the
author
of this harness, with the criterion stated in `labels/README.md` and every label carrying its
verbatim source line. `RESULTS.md` says so in its first paragraph, and reports two label
variants (L1 and the stricter L2) so the effect of the labelling choices on the score is
visible rather than buried.
