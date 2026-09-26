# HAND-160 — defects found by property, differential and fuzz testing

`pip show hypothesis` reported *not found* on a clean checkout; it was installed (6.168.1) and
used with `derandomize=True`, so the example sequence is a pure function of the test files and
every failure below is reproducible. The fuzzer deliberately uses `random.Random(seed)` with
fixed seeds instead, because a fuzz case must be replayable from its seed alone.

New files: `tests/test_properties.py`, `tests/test_differential.py`, `tests/test_fuzz.py`.
**No file under `engine/` was modified.**

**13 tests are RED.** Every one of them is a real defect in the engine, not a test artefact.
No assertion was weakened and nothing was marked `xfail`.

---

## BUG 1 — a truncated container image crashes the whole scan (HIGH)

`engine/scanner.py:448`. `tarfile.open()` is wrapped in
`except (tarfile.TarError, OSError, EOFError)`, but `opened.getmembers()` on the next line is
**not**. In stream mode (`"r:"`) the archive is parsed lazily, so a truncated file opens
successfully and only raises when the members are read. The `tarfile.ReadError` escapes
`scan_directory` and kills the CLI.

The module docstring promises the opposite: *"Failures are recorded in `self.errors` and the
coverage manifest, so a caller can distinguish 'no crypto here' from 'could not look here'."*

```python
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode="w") as t:
    i = tarfile.TarInfo("app.py"); d = b"rsa.newkeys(2048)\n"; i.size = len(d)
    t.addfile(i, io.BytesIO(d))
open("hdr.tar", "wb").write(buf.getvalue()[:512])      # one bare header block

ECDATScanner(enable_ml=False).scan_directory("hdr.tar")
# tarfile.ReadError: unexpected end of data
#   engine/scanner.py:448 in _scan_container_image -> for member in opened.getmembers()
#   engine/scanner.py:512 in scan_directory       -> return self._scan_path(directory_path)
#   cli.py:34            in run_headless_scan      -> findings = scanner.scan_directory(...)
```

Blast radius: **one corrupt `.tar` in a repository destroys every other finding in the tree**,
because `os.walk` never gets to finish. A partially-written `docker save` or an interrupted
upload is the most likely way this input occurs in practice.

Tests: `tests/test_fuzz.py::test_a_truncated_container_image_is_recorded_and_not_raised`,
`…::test_a_truncated_container_image_does_not_abort_a_whole_tree_scan`,
`…::test_fuzzed_single_files_never_crash_never_hang_and_stay_consistent[163]`.

---

## BUG 2 — scanning a single file skips de-duplication and coverage finalisation (HIGH)

`engine/scanner.py:511-512`. `scan_directory` returns `self._scan_path(directory_path)` as soon
as the argument is a file — **before** the de-duplication block (line 543) and before
`coverage["scanners_run"]` is populated (line 550). Both are documented entry points, so the
same bytes on disk give two different answers.

```python
open("k.py", "wb").write(b"a = rsa.newkeys(2048); b = rsa.newkeys(4096);\n")

scanner = ECDATScanner(enable_ml=False)
scanner.scan_directory("k.py")
# 2 findings: [('RSA', 1, 2048), ('RSA', 1, 4096)]
# scanner.coverage_manifest()["scanners_run"] == []      <-- 2 findings, "no scanner ran"

[f for f in ECDATScanner(enable_ml=False).scan_directory(".") if f["file"].endswith("k.py")]
# 1 finding: [('RSA', 1, 2048)]
```

Two consequences, both user-visible:

1. The same artefact is reported twice (once per key size) when the file is scanned directly,
   inflating the finding count and the CBOM component list.
2. **`coverage_manifest()["scanners_run"]` is empty while findings are returned.** The coverage
   manifest is the tool's own honesty mechanism — the CLI prints it and the CBOM embeds it — so
   for a single-file scan it states the opposite of the truth.

Tests: `tests/test_differential.py::test_scanning_one_file_directly_must_equal_scanning_its_directory`,
`…::test_duplicate_matches_on_one_line_are_collapsed_on_both_entry_points`,
`…::test_the_coverage_manifest_is_identical_whichever_entry_point_is_used`,
`…::test_a_container_image_is_reported_as_scanned_by_the_container_scanner_either_way`.

---

## BUG 3 — `dependencyType` is not a valid CycloneDX 1.7 property (HIGH)

`engine/cbom.py:284`. The vendored schema's `definitions.dependency` has
`"additionalProperties": false` and permits only `ref`, `dependsOn` and `provides`. Emitting
`dependencyType` makes the document **unusable by any consumer that validates it** — which is
the entire point of publishing a CBOM.

```python
generate_cbom([{"name": "RSA", "primitive": "pke", "key_length": 2048}])
# dependencies: [{"ref": "ECDAT-Scanned-Artefact",
#                 "dependsOn": ["crypto-asset-0"],
#                 "dependencyType": "uses"}]
# jsonschema: Additional properties are not allowed ('dependencyType' was unexpected)
```

Reached whenever a finding has no `file` key — ambient/global crypto, a policy-wide setting, or
an inventory re-imported from another tool. The existing `tests/test_cbom_schema.py` never
reaches it because it only feeds scanner output, which always carries a `file`.

(The CycloneDX `implements`-vs-`uses` distinction the design note mentions is expressed through
`compositions` and component `type`, not through a field on `dependencies`.)

Test: `tests/test_properties.py::test_cbom_matches_the_published_schema_for_findings_without_provenance`.

---

## BUG 4 — cipher `mode` is not mapped into the schema's closed enum (MEDIUM)

`engine/cbom.py:128` lowercases the mode and emits it verbatim. CycloneDX's `mode` is a closed
enum of eight values plus `other` and `unknown` — the schema provides those two precisely so an
unrecognised mode can be represented.

| input `mode` | CBOM emits | result |
|---|---|---|
| `GCM`, `CBC`, `CTR`, `OFB`, `CFB`, `ECB`, `CCM` | `gcm`, `cbc`, … | valid |
| `XTS` | `xts` | **invalid** |
| `GCM-SIV` | `gcm-siv` | **invalid** |
| `EAX` | `eax` | **invalid** |
| `OCB` | `ocb` | **invalid** |
| `SIV` | `siv` | **invalid** |

All five failures are real, widely deployed AEAD/cipher modes. The scanner does not currently
populate `mode`, so this is reachable only from an external caller — but `generate_cbom` is a
public function and `mode` is a documented finding key.

Test: `tests/test_properties.py::test_cbom_matches_the_published_schema_for_every_cipher_mode`.

---

## BUG 5 — `int(key_length)` crashes report generation (MEDIUM)

`engine/cbom.py:133`.

```python
generate_cbom([{"name": "RSA", "primitive": "pke", "key_length": "2048 bits",
                "file": "a.py", "line": 1}])
# ValueError: invalid literal for int() with base 10: '2048 bits'
```

A `key_length` of `"2048 bits"`, `"unknown"` or `"0x800"` — all reachable from a config file, a
spreadsheet import or a JSON inventory — takes the **entire report** down rather than omitting
the one field. Note `""` is already handled (falsy) and numeric *strings* work.

Test: `tests/test_properties.py::test_cbom_is_total_for_arbitrary_key_length`.

---

## BUG 6 — an unhashable algorithm name crashes report generation (MEDIUM)

`engine/cbom.py:265` — `OID_BY_NAME.get(f.get("name", ""))`.

```python
generate_cbom([{"name": ["RSA"], "primitive": "pke", "file": "a.py", "line": 1}])
# TypeError: cannot use 'list' as a dict key (unhashable type: 'list')
```

`list` and `dict` are both JSON-representable, so a finding round-tripped through a JSON
inventory can legitimately carry one there.

Test: `tests/test_properties.py::test_cbom_is_total_for_any_json_representable_algorithm_name`.

---

## BUG 7 — `component.name` and `component.version` are emitted uncoerced (MEDIUM)

`engine/cbom.py:261` and `engine/cbom.py:290`.

```python
generate_cbom([{"name": None, "primitive": "pke", "file": "a.py", "line": 1}])
# jsonschema: components/0/name: None is not of type 'string'

generate_cbom([{"name": "RSA", ...}], subject_version=1)
# jsonschema: metadata/component/version: 1 is not of type 'string'
```

Note the asymmetry: the *library* branch (line 222) does supply a literal `"unknown"` default, so
`type: "library"` with a missing name is fine, while `type: "algorithm"` with `name: None`
produces an invalid document.

Test: `tests/test_properties.py::test_cbom_is_wellformed_for_any_subject_name`.

---

## BUG 8 — `NO_ACTION` is shared mutable module state (HIGH, latent)

`engine/recommender.py:294` and `:322` do `return NO_ACTION` — the module-level dict, not a
copy. Every caller receives the *same* object.

```python
a = get_pqc_recommendation({"name": "AES", "primitive": "ae", "key_length": 256})
b = get_pqc_recommendation({"name": "AES", "primitive": "ae", "key_length": 256})
a is b            # True

a["algorithm"] = "POISONED"
get_pqc_recommendation({"name": "SHA256", "primitive": "hash"})["algorithm"]
# 'POISONED'    <-- a later, unrelated call now reports a false algorithm
```

Nothing in the current tree mutates the result, so this is latent — but `app.py:70` and
`cli.py:54` both assign it straight onto the finding dict, and the moment the GUI or a reporter
annotates a record (a row id, a ticket number) every subsequent recommendation in the process is
silently corrupted. `NO_ACTION` also holds mutable `notes` and `standard_basis` lists, so a bare
`append` is enough to trigger it.

Test: `tests/test_properties.py::test_recommendation_records_are_not_shared_module_state`.

---

## BUG 9 — `X + Y == Z` is reported vulnerable because of IEEE-754 rounding (HIGH)

`engine/mosca.py:262` — `is_vulnerable = bool(subject and total > z_years)` on raw floats.
`X + Y == Z` is a mathematical statement about the numbers the operator typed, but
`1.1 + 2.2` is `3.3000000000000003` in binary floating point, which compares strictly greater
than `3.3`.

| X | Y | Z | `X+Y` in float | mathematically equal? | reported | tier |
|---|---|---|---|---|---|---|
| 1.1 | 2.2 | 3.3 | `3.3000000000000003` | yes | **vulnerable** | **HIGH** |
| 0.1 | 0.2 | 0.3 | `0.30000000000000004` | yes | **vulnerable** | **HIGH** |
| 0.7 | 0.6 | 1.3 | `1.2999999999999998` | yes | not vulnerable | MEDIUM |
| 2.5 | 3.5 | 6.0 | `6.0` | yes | not vulnerable | MEDIUM |

The last two rows show the error is not a consistent bias: it flips the verdict in whichever
direction the rounding happens to fall, and only for values that are not dyadic.

The audit trail contradicts itself in the same breath — the report prints `x_y=3.3` against
`z=3.3`, two visibly equal numbers, and asserts `is_vulnerable=True`. Anyone auditing a HIGH
verdict from that line cannot tell whether the tool is wrong or the arithmetic is. The verdict
also flips a whole tier (MEDIUM → HIGH), across the whole estate at once.

Tests: `tests/test_properties.py::test_exact_decimal_boundary_x_plus_y_equal_to_z_is_not_vulnerable`.
The dyadic control `…::test_exact_boundary_x_plus_y_equal_to_z_is_not_vulnerable` **passes**,
which confirms the strict-inequality logic itself is correct and only the float comparison is
at fault. `…::test_epsilon_past_the_boundary_is_vulnerable` also passes, so the fix must not
overshoot into the opposite error.

---

## BUG 10 — out-of-scope files are in no coverage counter at all (MEDIUM)

`engine/scanner.py:571`. `_scan_path` returns `[]` for an unrecognised extension without calling
either `_note_scanned()` or `_note_error()`, so the file appears in `files_seen` and nowhere
else. The manifest's `never_in_scope` list names *categories of cryptography*, not file types,
so nothing explains the gap.

```python
for n in ("a.py", "b.c", "c.conf", "d.so", "e.txt", "f.md", "g.zip", "h.dat", "i.rst"):
    open(n, "wb").write(b"rsa.newkeys(2048)\n")
scanner.scan_directory(".")
# files_seen=9  files_scanned=4  files_skipped=0   ->  5 files unaccounted for
```

The five unaccounted files each contain a live `rsa.newkeys(2048)`. A reader doing
`files_seen - files_scanned - files_skipped` to work out how much was quietly ignored gets a
number the manifest never explains — which is the one job the manifest exists to do.

Test: `tests/test_fuzz.py::test_every_file_seen_is_either_scanned_or_recorded_as_skipped`.

---

## Properties that PASSED

These found nothing, which is itself a result worth recording — it marks what is now covered:

* **Scanner determinism**: identical output across three consecutive scans, and independence
  from unrelated files in the same directory.
* **Scanner totality**: 300+ hypothesis-generated arbitrary texts — NUL, control characters,
  4-byte code points, unterminated comments, 300 KB single lines, every supported extension.
* **Line-number sanity** (`1 <= line <=` the file's real line count), plus the targeted
  comment-blanking offset test across every combination of block comment, docstring, `#` and
  `//` prefixes, for both C and Python, with the true line number asserted exactly.
* **Recommender totality over the full 35 840-combination
  name × primitive × uses × evidence_class cross-product** — including `None`, `""`, empty
  lists, tuples, floats, `True`, unknown primitives and injection-shaped strings — every one
  returning a complete, well-formed record with a non-empty `rule_trace`, and none raising.
  Also total over 15 arbitrary values in each of 16 extra finding keys.
* **Recommender purity**: deep-compare of the caller's dict before and after, over generated
  findings with nested values.
* **Mosca monotonicity** in X, in Y and in Z, with a paired *reverse* boundary check so that a
  "never vulnerable" implementation cannot pass the strictness test for the wrong reason.
* **`resolve_within` containment** under generated traversal sequences, drive-letter paths, UNC
  shares, NUL bytes and prefix lookalikes — paired with a positive control, so "always return
  None" cannot pass.
* **`.py` / `.c` / `.java` / `.go` agreement** on algorithm names *and* line numbers for
  comment-free snippets, with the one documented `#`-comment divergence pinned as its own test
  rather than left to hide a real routing bug.
* **`_normalise_primitive` alias convergence** for every alias class, plus case and whitespace
  insensitivity, plus "an explicit primitive always beats the name fallback".
* **CBOM schema conformance** for findings that carry provenance, for any coverage manifest,
  and for any subject name — and structural determinism across runs.
* **Fuzzing**: 8 fixed seeds × 45 cases (mutated, truncated, binary, container, oversized,
  undecodable) with a per-case wall-clock budget, plus whole-tree walks with awkward filenames.
  No hangs, no timeouts, and no unhandled exception other than BUG 1.

## Deliberately not asserted

Two behaviours are documented design decisions rather than defects, and are pinned by tests
that assert the *documented* behaviour so they cannot drift silently:

* `#` opens a comment in Python and in config formats but not in C
  (`test_hash_comments_are_stripped_in_python_but_not_in_c_by_design`).
* `protocol` and `cryptographic-library` are not CycloneDX algorithms and are modelled as
  `assetType=protocol` and `type=library` components respectively
  (`test_non_algorithm_primitives_are_modelled_as_such_in_the_cbom`).



