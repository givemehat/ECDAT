# Java gap analysis — why recall is 0.219 on `cryptoapi_bench`

**Scope.** This is a measurement of *our own* misses on an external, public, third-party
corpus. No rule, regular expression, or file layout was taken from any other project. Every
number below was produced by a script I actually ran, and the scripts are named so you can
re-run them.

**Corpus.** `benchmark/corpora/cryptoapi_bench/`, git-cloned, pinned at commit
`e6b6b50fef6970151300c1ac2de62e188ba6de19` (verified with `git rev-parse`). 203 `.java`
files under `src/main/java`. Published as: Afrose, Rahaman, Yao, *"CryptoAPI-Bench: A
Comprehensive Benchmark on Java Cryptographic API Misuses"*, IEEE SecDev 2019, pp. 49–61.

**Reproduction.**

```
python research/scratch/gap_v2.py     # scoring, miss dump, categorisation
python research/scratch/gap_probe.py  # counterfactual probes, root-cause evidence
```

Outputs land beside them as `gap_v2_out.txt`, `gap_probe_out.txt`, and
`gap_v2_L1_misses.json` (the full machine-readable miss list: file, line, primitive,
break model, exact source text, category). No file under `engine/`, `tests/` or
`benchmark/` was modified; `git status --porcelain engine tests benchmark` is empty.

> Note: a prior untracked draft of this document existed at this path. It was replaced by
> this independently-measured version and preserved at
> `research/scratch/PRIOR_DRAFT_java-gap-analysis.md.bak`. One figure in that draft was
> wrong and is corrected here: it reported 21 `IvParameterSpec` occurrences, of which 11
> are `new IvParameterSpec(...)` construction sites and 10 are `import` lines (§5).

---

## 1. What the harness actually rewards

Read first, because it fixes everything else.

`benchmark/run_benchmark.py` is line-level and location-level, not finding-level:

* `positives_for()` (line 118) builds a **set of `(file, line)` tuples**. A label is
  positive if `decision == "positive"`, or — for variant L2 only — if the reason string
  contains the marker `"variant L2"`.
* `score()` (line 133) walks the findings; if a finding's `(file, line)` is in that set the
  location is a hit, otherwise **every** finding there is a false positive. `tp = len(hit)`,
  `fn = len(positives) - tp`.
* `ECDATScanner(enable_ml=False).scan_directory(...)` is the system under test, and the
  scanner is passed the **absolute** path, so `f["_loc"]` is `relpath(file, corpus_root)` —
  which is what the label `file` field holds. There is no path-normalisation slack.
* `describe()` (line 151) is what lets the harness tell a *miss* from a *mislabel*; I reuse
  the same idea in §6.

So a true positive requires: **the correct file, the correct 1-based line number, and *any*
finding emitted there.** The algorithm name in the finding is not scored. That matters for
§6.

**Confirmed baseline, reproduced by my own script (not read from `results.json`):**

| variant | TP | FP | FN | labelled positives | recall |
|---|---|---|---|---|---|
| L1 | 46 | 0 | 164 | 210 | **46/210 = 0.2190** |
| L2 | 46 | 0 | 277 | 323 | 46/323 = 0.1424 |

This matches the committed `benchmark/results.json` exactly, so the harness is deterministic
and my re-implementation is equivalent.

**Label format** (`benchmark/labels/cryptoapi_bench_pq.json`): 529 label objects, each
`{decision, primitive, break_model, reason, file, line, code}`. `code` is the **verbatim
stripped source line**, and `run_benchmark.py::verify_labels` re-reads all 529 from the
pinned corpus and aborts on any mismatch. So labels cannot have drifted. 210 positive, 319
negative-audited. I did not simply trust the `code` field for reporting — I re-read every
source line from the corpus myself in `srcline()` and print that.


---

## 2. Headline: 164 misses, in 7 categories

`gap_v2.py` re-reads every missed location from the corpus and buckets it by the API family
the *source line* actually uses. First match wins, in the priority order below. The
bucketing is a property of the corpus text, not of the label's prose reason.

| # | category | count | share of 164 | label primitives involved |
|---|---|---|---|---|
| 1 | `String x = "<algo>"` (algorithm literal bound to a name) | **45** | 27.4% | AES 9, DES 8, IDEA 4, Blowfish 4, RC2 4, SHA-1 4, MD5 4, MD4 4, MD2 4 |
| 2 | `KeyGenerator.getInstance(<algo>)` | **41** | 25.0% | AES 28, Blowfish 3, RC2 3, IDEA 3, DES 2, RC4 2 |
| 3 | `Cipher.getInstance(<algo>)` | **34** | 20.7% | RSA 11, AES 5, DES 4, Blowfish 4, RC2 4, IDEA 4, RC4 2 |
| 4 | `new SecretKeySpec(<bytes>, "<algo>")` | **17** | 10.4% | AES 17 |
| 5 | `MessageDigest.getInstance(<algo>)` | **16** | 9.8% | MD4 5, MD2 5, SHA-1 3, MD5 3 |
| 6 | algorithm literal passed to a constructor | **8** | 4.9% | DES, Blowfish, RC2, IDEA, SHA-1, MD5, MD4, MD2 (1 each) |
| 7 | `Mac.getInstance("Hmac…")` | **3** | 1.8% | HMAC 3 |
| | **SUM** | **164** | 100% | |

There are only **seven** categories, not dozens: 164/164 assigned, no `"anything else"`
bucket. That is itself a finding — see §4.

### Real examples, copied from the corpus

**1. `String x = "<algo>"` — 45 sites**

```
src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:20   String crypto = "DES/ECB/PKCS5Padding";
src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase1.java:21   String keyAlgo = "DES";
src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase10.java:11  public static final String DEFAULT_CRYPTO = "IDEA";
src/main/java/org/cryptoapi/bench/brokencrypto/BrokenCryptoABICase11.java:23  String key = "DES";
```

**2. `KeyGenerator.getInstance(<algo>)` — 41 sites (32 literal argument, 9 variable)**

```
.../brokencrypto/BrokenCryptoABPSCase1.java:12   KeyGenerator keyGen = KeyGenerator.getInstance("AES");
.../brokencrypto/BrokenCryptoBBCase1.java:13      KeyGenerator keyGen = KeyGenerator.getInstance("DES");
.../brokencrypto/BrokenCryptoABICase1.java:12     KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgo);
.../brokencrypto/BrokenCryptoABICase12.java:15    KeyGenerator keyGen = KeyGenerator.getInstance(crypto);
```

**3. `Cipher.getInstance(<algo>)` — 34 sites (20 literal argument, 14 variable)**

```
.../brokencrypto/BrokenCryptoABPSCase1.java:14   Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
.../brokencrypto/BrokenCryptoABPSCase2.java:13   Cipher cipher = Cipher.getInstance("Blowfish");
.../brokencrypto/BrokenCryptoABICase1.java:14     Cipher cipher = Cipher.getInstance(crypto);
.../brokencrypto/BrokenCryptoABICase11.java:18    Cipher cipher = Cipher.getInstance(crypto);
```

**4. `new SecretKeySpec(...)` — 17 sites, every one of them AES**

```
.../credentialinstring/CredentialInStringABICase1.java:18   SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
.../credentialinstring/CredentialInStringABHCase1.java:15   SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
.../predictablecryptographickey/PredictableCryptographicKeyABSCase1.java:55  SecretKeySpec keySpec = new SecretKeySpec(keyBytes,algo);
```

**5. `MessageDigest.getInstance(<algo>)` — 16 sites (4 literal argument, 12 variable)**

```
.../brokenhash/BrokenHashABPSCase3.java:9    MessageDigest md = MessageDigest.getInstance("MD4");
.../brokenhash/BrokenHashABPSCase4.java:9    MessageDigest md = MessageDigest.getInstance("MD2");
.../brokenhash/BrokenHashABICase1.java:13    MessageDigest md = MessageDigest.getInstance(crypto);
.../brokenhash/BrokenHashABICase10.java:18   MessageDigest md = MessageDigest.getInstance(crypto);
```

**6. literal passed to a constructor — 8 sites**

```
.../brokencrypto/BrokenCryptoABSCase1.java:11   crypto = new Crypto2("DES/ECB/PKCS5Padding");
.../brokencrypto/BrokenCryptoABSCase2.java:11   crypto = new Crypto3("Blowfish");
.../brokencrypto/BrokenCryptoABSCase4.java:11   crypto = new Crypto5("RC2");
.../brokencrypto/BrokenCryptoABSCase5.java:11   crypto = new Crypto6("IDEA");
```

**7. `Mac.getInstance` — 3 sites**

```
.../brokenmac/BrokenMacBBCase1.java:16      Mac mac = Mac.getInstance("HmacMD5");
.../brokenmac/BrokenMacBBCase2.java:16      Mac mac = Mac.getInstance("HmacSHA1");
.../brokenmac/BrokenMacCorrected.java:16    Mac mac = Mac.getInstance("HmacSHA256");
```

---

## 3. Cumulative effect, if each category were closed

Adding categories in descending size, against the fixed denominator of 210 L1 positives
(the 46 existing TPs are held constant). This is **arithmetic on the miss set, not an
experiment** — I added no rule, and precision is unmeasured for any of these:

| added | category | sites | recall after |
|---|---|---|---|
| — | current state | — | 46/210 = 0.2190 |
| top-1 | `String x = "<algo>"` | +45 | 91/210 = 0.4333 |
| top-2 | `KeyGenerator.getInstance` | +41 | 132/210 = 0.6286 |
| top-3 | `Cipher.getInstance` | +34 | 166/210 = 0.7905 |

---

## 4. Root cause, with a counterfactual

Three questions a reader should ask: (a) are the files even being read, (b) is the label set
wrong, (c) does the rule table lack the patterns.

**(a) Files are read. Coverage is clean.** `files_seen=203, files_scanned=203,
files_skipped=0, scan_errors=[]`. Every file is examined. The gap is not a walk failure.

**(b) The labels are not wrong.** They are byte-verified against the corpus on every harness
run, and my own independent re-read reproduced all 164 source lines. I also independently
re-classified every literal with `benchmark/pqtaxonomy.classify` and it agrees with the
committed label on all 164 (`'MD2'->('MD2','grover')`, `'IDEA'->('IDEA','grover')`,
`'AES/ECB/PKCS5Padding'->('AES','grover')`, etc.).

**(c) The rule table lacks the patterns.** This is the direct measurement. I fed 31
*canonical, textbook-correct* Java JCA lines to the real compiled rule table
(`engine.scanner._COMPILED_RULES`) and recorded which rules fire:

```
=== A. COUNTERFACTUAL: canonical Java line -> rules that fire ===
Cipher cipher = Cipher.getInstance("AES");                       *** NONE ***
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");      ['ECD-SRC-AES-001']
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");      ['ECD-SRC-AES-001']
Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");      *** NONE ***
Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");   *** NONE ***
Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding"); *** NONE ***
Cipher cipher = Cipher.getInstance("RC2/ECB/PKCS5Padding");      *** NONE ***
Cipher cipher = Cipher.getInstance("RC4");                       ['ECD-CFG-LEGACY-001']
Cipher cipher = Cipher.getInstance("IDEA/ECB/PKCS5Padding");     *** NONE ***
KeyGenerator keyGen = KeyGenerator.getInstance("AES");           *** NONE ***
KeyGenerator keyGen = KeyGenerator.getInstance("DES");           *** NONE ***
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");      *** NONE ***
MessageDigest md = MessageDigest.getInstance("MD2");             *** NONE ***
MessageDigest md = MessageDigest.getInstance("MD4");             *** NONE ***
Mac mac = Mac.getInstance("HmacSHA256");                         *** NONE ***
Mac mac = Mac.getInstance("HmacMD5");                            *** NONE ***
String crypto = "AES/CBC/PKCS5Padding";                          *** NONE ***
String DEFAULT_CRYPTO = "DES/ECB/PKCS5Padding";                  *** NONE ***

lines with 0 rules firing: 20 of 31
```

`20 of 31`. These are not obscure lines. `KeyGenerator.getInstance("AES")` and
`new SecretKeySpec(keyBytes, "AES")` are the two most idiomatic lines in the JCA.

**The structural reason** (`=== D.` in the probe output). The table has **36 rules**;
**10** mention a JCA class name. And every one of those 10 is a hard-coded, *enumerated*
literal paired with a *single* JCA class — they are Python/OpenSSL rules with one Java
alternative bolted on:

| rule | JCA alternative it contains |
|---|---|
| `ECD-SRC-RSA-003` | `KeyPairGenerator\.getInstance\(\s*["']RSA["']\s*\)` |
| `ECD-SRC-ECDH-001` | `KeyAgreement\.getInstance\(\s*["']ECDH` |
| `ECD-SRC-ECDSA-001` | `Signature\.getInstance\(\s*["'](SHA\d+withECDSA\|ECDSA)` |
| `ECD-SRC-ECC-001` | `KeyPairGenerator\.getInstance\(\s*["']EC["']\s*\)` |
| `ECD-SRC-DSA-001` | `KeyPairGenerator\.getInstance\(\s*["']DSA` |
| `ECD-SRC-DH-001` | `KeyAgreement\.getInstance\(\s*["']DH` |
| `ECD-SRC-AES-001` | `Cipher\.getInstance\(\s*["']AES/(?:GCM\|CBC\|CTR\|ECB)` |
| `ECD-SRC-SHA2-001` | `MessageDigest\.getInstance\(\s*["']SHA-?256` |
| `ECD-SRC-SHA1-001` | `MessageDigest\.getInstance\(\s*["']SHA-?1["']` |
| `ECD-SRC-MD5-001` | `MessageDigest\.getInstance\(\s*["']MD5["']` |

Read down the `Cipher` column: AES is enumerated, nothing else is. Read across
`KeyGenerator`, `Mac`, `SecretKeySpec`, `SecretKeyFactory`: **absent entirely.** The table
was written around Python's `cryptography`/`hashlib` and OpenSSL/SSH wire vocabulary, and
Java got one enumerated literal per already-existing rule. This is exactly why the misses
collapse into 7 buckets — they are the 7 shapes those 10 rules do not enumerate.

**The asymmetry is visible in the recall table** (`=== G.`, recomputed independently in a
second, separate code path):

| primitive | TP | labelled | recall |
|---|---|---|---|
| SHA-256 | 5 | 5 | **1.000** |
| RC4 | 8 | 12 | 0.667 |
| RSA | 6 | 17 | 0.353 |
| AES | 23 | 82 | 0.280 |
| SHA-1 | 2 | 10 | 0.200 |
| MD5 | 2 | 10 | 0.200 |
| DES | 0 | 15 | **0.000** |
| IDEA | 0 | 12 | **0.000** |
| Blowfish | 0 | 12 | **0.000** |
| RC2 | 0 | 12 | **0.000** |
| MD4 | 0 | 10 | **0.000** |
| MD2 | 0 | 10 | **0.000** |
| HMAC | 0 | 3 | **0.000** |
| **TOTAL** | **46** | **210** | **0.2190** |

Perfect recall on SHA-256, and exactly zero on seven primitives. Zero is not a tuning
result; it is the signature of an absent enumeration. Note that RC4 scores 0.667 *by
accident* — it is caught by `ECD-CFG-LEGACY-001`, a config rule whose regex is
`\b(3DES|DES-CBC3|RC4|NULL-SHA|EXPORT)\b`, i.e. RC4 is a member of a deprecation list, not
a recognised cipher.

### Recoverability

Splitting the 164 by whether the missed line *itself* carries a QV algorithm literal that
our own `classify()` calls quantum-affected:

| | count |
|---|---|
| miss line carries the QV algorithm literal itself | **127** (77.4%) |
| needs cross-line dataflow (the algorithm is in a variable) | **37** (22.6%) |

So **127 of 164 — over three quarters — need no dataflow at all.** They are single lines
carrying a literal that a one-regex-per-JCA-factory rule would catch. That is the strongest
single statement in this document: this is a *table-completeness* problem, not an

---

## 5. Categories in the brief that turned out **not** to apply

I checked each shape the brief named against the whole corpus and against the label
decision, rather than assuming. Reporting these as gaps would have inflated the number.

| shape | corpus sites | labelled positive | verdict |
|---|---|---|---|
| `Cipher.getInstance` without explicit `Provider` | **0** | — | **Inapplicable.** I grepped for any 2-arg `getInstance` across all 203 files: `total 2-arg getInstance sites: 0`. JCA's `getInstance(String, Provider)` overload is never used here. |
| `IvParameterSpec` | 21 (11 `new`, 10 `import`) | 0 | **Inapplicable.** `annotate.py` line 122 excludes it explicitly: "IV / PBKDF parameter object; names no primitive". Outside the denominator. |
| `GCMParameterSpec` | **0** | 0 | **Inapplicable.** The string `GCM` does not occur anywhere in the corpus. |
| `PBEKeySpec` | 11 | 0 | **Inapplicable.** Negative — PBKDF parameter object, not a primitive. |
| `PBEParameterSpec` | 20 | 0 | **Inapplicable.** Same. |
| `PBEWith<hash>And<cipher>` strings | **0** | 0 | **Inapplicable.** Zero occurrences. |
| ECB mode as a *mode* finding | 18 lines mention `ECB` | 14 | **Partly a red herring.** All 14 positive `ECB` lines are positive because of the *primitive* in the string (`DES/ECB/…`, `AES/ECB/…`), not because ECB is a mode. They are already counted in categories 1 and 3. 12 of 14 are misses; **2 are hits** — `EcbInSymmCryptoABPSCase1.java:13` and `EcbInSymmCryptoBBCase1.java:14`, both `Cipher.getInstance("AES/ECB/PKCS5Padding")`, caught by the `AES/(?:GCM\|CBC\|CTR\|ECB)` alternation. |
| `Signature.getInstance` | **0** | 0 | **Inapplicable here.** Zero occurrences. (Caveat: `ECD-SRC-ECDSA-001` *does* contain a `Signature.getInstance` alternative, so I cannot claim "no Signature rule" — only that this corpus never calls it, so its absence costs nothing.) |
| `KeyAgreement.getInstance` | **0** | 0 | **Inapplicable here.** Zero occurrences; same caveat as above. |
| `SecretKeyFactory.getInstance` | **0** | 0 | **Inapplicable.** Zero occurrences. |
| `KeyPairGenerator.getInstance` | 6 | **6** | **Not a miss.** All 6 are `getInstance("RSA")` and all 6 are already hits via `ECD-SRC-RSA-003`. |
| `KeyStore.getInstance` | 10 | 0 | **Inapplicable.** Labelled negative — "KeyStore container format (JKS), not a cryptographic primitive" (`annotate.py` line 125). |
| `cipher.init` / `dec.init` | 71 | 0 | **L2-only.** All 71 labelled negative in L1: "operates on a primitive chosen elsewhere; names no primitive". See §7. |
| `SecureRandom` | 123 | 0 | **Inapplicable.** A PRNG, excluded at `annotate.py` line 120. |

One honesty caveat on the "inapplicable" rows: `IvParameterSpec`/`PBEKeySpec`/
`PBEParameterSpec`/`SecureRandom` lines are *unlabelled*, not labelled-negative — they fall
outside the annotator's candidate regex entirely, so they sit outside the denominator and
cannot be misses. Only `KeyStore`, `cipher.init` and the ECB/P3 lines are explicitly
labelled negative.

---

## 6. Are any misses actually mislabels? (the question that changes the fix)

**No. Zero of the 164 misses are mislabels.** This is structural, not luck: `score()` counts
a location as a hit only if a finding exists there, so *by construction* a "miss" cannot also
carry a finding. I verified it rather than assuming it — for each of the 164 I looked up
`hits_by_loc[(file, line)]`; all 164 are empty.

So the bug is a **total miss, uniformly**: we emit nothing on those lines. Not a wrong
algorithm, not a wrong line, not a duplicate.

**But the converse question has a real answer, and it matters.** Of the 46 TPs, **15 are
named differently from the label** — and the harness scores them as TPs anyway, because only
`(file, line)` is compared:

| label says | we emit | rule | count |
|---|---|---|---|
| RC4 | `LEGACY-CIPHER` | `ECD-CFG-LEGACY-001` | 8 |
| SHA-256 | `SHA256` | `ECD-SRC-SHA2-001` | 5 |
| SHA-1 | `SHA1` | `ECD-SRC-SHA1-001` | 2 |

```
.../brokencrypto/BrokenCryptoBBCase3.java:14  label=RC4  we emit LEGACY-CIPHER  (Cipher.getInstance("RC4"))
.../brokenhash/BrokenHashBBCase1.java:9       label=SHA-1 we emit SHA1          (MessageDigest.getInstance("SHA1"))
.../brokenhash/BrokenHashCorrected.java:10    label=SHA-256 we emit SHA256      (MessageDigest.getInstance("SHA-256"))

---

## 7. Summary

* **164 misses.** Top 3 categories = 120 misses = **73.2%** of the gap: algorithm-literal
  bindings (45), `KeyGenerator.getInstance` (41), `Cipher.getInstance` (34).
* **Root cause: rule-table completeness, not coverage, not labels.** 203/203 files scanned,
  0 errors, 0 skipped; all 164 labels byte-verified. But **20 of 31 canonical Java JCA
  lines fire no rule at all**, and the table has 10 JCA-aware rules out of 36 — each
  enumerating one hard-coded literal against one JCA class. `KeyGenerator`, `Mac`,
  `SecretKeySpec` and `SecretKeyFactory` have no JCA rule at all.
* **127 of 164 (77.4%) need no dataflow** — the literal is on the missed line. A JCA factory
  rule that enumerates the Grover set against
  `Cipher|KeyGenerator|MessageDigest|Mac|SecretKeySpec` would address the large majority of
  the gap.
* **All 164 are total misses; 0 are mislabels.** But 15 of the 46 TPs are *named*
  differently, and 8 of those (`RC4 → LEGACY-CIPHER`) mis-type a real finding.
* **Six of the shapes named in the brief do not exist in this corpus** (2-arg
  `getInstance`: 0 sites; `GCMParameterSpec`: 0; `Signature.getInstance`: 0;
  `KeyAgreement.getInstance`: 0; `SecretKeyFactory.getInstance`: 0; `PBEWith…`: 0;
  `KeyPairGenerator`: 6 sites, all already caught). `IvParameterSpec`/`PBEKeySpec`/
  `PBEParameterSpec` exist but are labelled negative or unlabelled, so they sit outside the
  denominator.
* **L2 is worse: 0.1424** (46/323). The 113 L2-only positives are operation lines — 71
  `cipher.init`/`dec.init` sites (all labelled negative in L1) plus `.doFinal`, `.update`,
  `generateKey`. These are not line-numbering artefacts; the scanner simply has no
  operation-line rules, which is a deliberate design choice rather than an oversight. Any
  recall claim should quote L1 = 0.2190 and note L2 = 0.1424 beside it.

### Caveats I want on the record

* The ground truth is **ours**, annotated by the harness author — one annotator, no
  inter-annotator agreement figure. It is byte-verified against the corpus but it is still
  one person's judgement. I did not weaken it: every label I re-derived from the corpus
  text via `classify()` matched.
* CryptoAPI-Bench is a **constructed** benchmark of 203 small micro-programmes, not
  production Java. The `String x = "<algo>"` category (45 sites, 27% of the gap) is an
  artefact of that style; real code is less likely to bind the algorithm to a local
  immediately above its use. Do not read the category mix as a statement about production
  Java.
* The §3 cumulative table is **arithmetic on the miss set**, not an experiment. I added no
  rule. Precision is unmeasured for every hypothetical rule — a `Cipher.getInstance`
  pattern that fires on every call would gain recall and lose precision, and I did not
  measure that trade-off.
* My category boundaries are a judgement call. A different but equally defensible grouping
  (for instance folding the ctor-literal sites into category 1, giving 6 categories) changes
  the ranking within the top 3 but not the total, the sum-to-164 check, or the root cause.
* `_strip_comments` runs before rules, so a JCA call inside a comment would not be found.
  I found no such case among the 164, but I did not exhaustively verify comment-only calls
  across the corpus.
* The `delta` analysis in §6 compares each miss to the nearest finding in the *same file*;
  it is a diagnostic for off-by-N errors, not a claim that closing a category would
  automatically produce a finding at that offset.

```

`SHA256` vs `SHA-256` is cosmetic. The 8 `RC4 → LEGACY-CIPHER` cases are a real fidelity
defect: `LEGACY-CIPHER` is a `primitive="protocol"`, `artefact_class="config"` finding, so
those 8 lines enter the CBOM as a protocol concern rather than as an RC4 stream cipher and
would be recommended the wrong replacement. It is worth 8/210 ≈ 3.8 recall points of
*apparent* performance that is not real fidelity.

**Not an off-by-one problem either.** Distance from each miss to the nearest finding in the
same file: `delta=+2` ×21, `+4` ×7, `−4` ×2, `−3` ×1, `±5,6,7,8,12,13,14,17,22,24,25` ×1
each, and **119 misses in a file where we produced no finding at all.** `delta=0` appears
zero times, confirming §6's first claim. And 162 of 203 files produce zero findings; 69 of
the 110 files containing a labelled positive produce nothing. File-level recall is
**41/110 = 0.3727** versus line-level 0.2190 — the line-level number is genuinely the
stricter one, and quoting the file-level figure would flatter us by 15 points.

architecture problem.

| top-4 | `new SecretKeySpec` | +17 | 183/210 = 0.8714 |
| top-5 | `MessageDigest.getInstance` | +16 | 199/210 = 0.9476 |
| top-6 | ctor literal | +8 | 207/210 = 0.9857 |
| top-7 | `Mac.getInstance` | +3 | 210/210 = 1.0000 |

The top **three** categories are 120 of 164 misses — **73.2%** of the gap.
