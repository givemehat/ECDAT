"""IndraMesh external-accuracy benchmark -- ONE COMMAND reproduces every number.

    python benchmark/run_benchmark.py              # measure (auto-fetches corpora if absent)
    python benchmark/run_benchmark.py --fetch      # force a fresh clone at the pinned SHAs
    python benchmark/run_benchmark.py --no-write   # print only, do not touch results files

WHAT IS MEASURED
----------------
IndraMeshScanner(enable_ml=False) is run over each corpus exactly as an operator would run it
(`scan_directory`), and its findings are matched against a committed, hand-annotated,
line-level ground truth (`benchmark/labels/*.json`).

A finding is a TRUE POSITIVE iff its (file, line) is a labelled positive location.
  precision = TP / (TP + FP)      recall = TP / (TP + FN)      F1 = 2PR / (P + R)
Every ratio is reported next to its numerator and denominator so the arithmetic is checkable.

TWO LABEL SETS ARE REPORTED
---------------------------
L1 (primary)  a line is positive iff it NAMES, or binds a name to, a quantum-vulnerable
              primitive in a position that determines the algorithm.
L2 (variant)  L1 PLUS every line that merely OPERATES on such a primitive (`cipher.init`,
              `md.update`, `cipher.encryptor()`, `.digest()`). L2 is a STRICTER ground truth
              and therefore a LOWER-BOUND on recall. Both are reported; neither is hidden.

HONESTY RULES ENFORCED IN CODE
------------------------------
* The corpus commit SHA is verified with `git rev-parse`; a mismatch aborts.
* Every label's verbatim `code` is re-read from the corpus and compared; a mismatch aborts.
  Labels are frozen data and are never silently re-derived.
* Scan errors and the coverage manifest are reported, so "no finding" and "not examined"
  can never be confused.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from annotate import CORPORA  # noqa: E402
from engine.scanner import IndraMeshScanner  # noqa: E402

LABEL_DIR = os.path.join(HERE, "labels")
CORPUS_DIR = os.path.join(HERE, "corpora")
RESULTS_JSON = os.path.join(HERE, "results.json")
RESULTS_MD = os.path.join(HERE, "RESULTS.md")

L2_MARKER = "variant L2"


class IntegrityError(Exception):
    """Raised when the corpus or the labels do not match what was committed."""


def git(*args, cwd):
    return subprocess.run(("git",) + args, cwd=cwd, capture_output=True, text=True,
                          check=False).stdout.strip()


def ensure_corpus(name, spec, force=False):
    root = os.path.join(CORPUS_DIR, name)
    if force and os.path.isdir(root):
        subprocess.run(("git", "fetch", "--all", "--tags"), cwd=root,
                       capture_output=True, text=True, check=False)
        subprocess.run(("git", "checkout", "--force", spec["pinned"]), cwd=root,
                       capture_output=True, text=True, check=False)
    if not os.path.isdir(root):
        os.makedirs(CORPUS_DIR, exist_ok=True)
        print("[fetch] cloning %s -> %s" % (spec["url"], root))
        r = subprocess.run(("git", "clone", "--quiet", spec["url"], root),
                           capture_output=True, text=True, check=False)
        if r.returncode != 0:
            raise IntegrityError("git clone failed for %s: %s" % (name, r.stderr.strip()))
    head = git("rev-parse", "HEAD", cwd=root)
    if head != spec["pinned"]:
        raise IntegrityError(
            "corpus %s is at %s but the benchmark is pinned to %s. Refusing to measure a "
            "corpus the labels were not written against." % (name, head, spec["pinned"]))
    return root, head


def load_labels(name):
    path = os.path.join(LABEL_DIR, "%s_pq.json" % name)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def verify_labels(name, spec, root, labels):
    """Every committed label must still match the corpus byte-for-byte. Drift => abort."""
    drift = []
    for lab in labels["labels"]:
        full = os.path.join(root, lab["file"].replace("/", os.sep))
        try:
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().split("\n")
        except OSError as exc:
            drift.append((lab["file"], lab["line"], "unreadable: %s" % exc))
            continue
        if lab["line"] < 1 or lab["line"] > len(lines):
            drift.append((lab["file"], lab["line"], "line out of range"))
            continue
        actual = lines[lab["line"] - 1].strip()
        if actual != lab["code"]:
            drift.append((lab["file"], lab["line"],
                          "label says %r, corpus has %r" % (lab["code"], actual)))
    if drift:
        raise IntegrityError(
            "%d label(s) no longer match the pinned corpus of %s, e.g. %s. The labels are "
            "frozen data; re-run `python benchmark/annotate.py` ONLY if the corpus was "
            "deliberately re-pinned, and review every changed line before committing."
            % (len(drift), name, drift[0]))
    return len(labels["labels"])


def positives_for(labels, variant):
    """Return the positive-location set for label variant 'L1' or 'L2'."""
    out = set()
    for lab in labels["labels"]:
        if lab["decision"] == "positive":
            out.add((lab["file"], lab["line"]))
        elif variant == "L2" and L2_MARKER in lab["reason"]:
            out.add((lab["file"], lab["line"]))
    return out


def _ratio(num, den):
    return None if not den else round(num / den, 4)


def score(findings, positives, label_index):
    """Line-level scoring. Returns counts plus explicit FP/FN lists."""
    hit, fp_locs = set(), {}
    for f in findings:
        loc = f["_loc"]
        if loc in positives:
            hit.add(loc)
        else:
            fp_locs.setdefault(loc, []).append(f)

    tp = len(hit)
    fp = len(fp_locs)
    fn = len(positives) - tp
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = None if not (precision and recall) else _ratio(2 * precision * recall,
                                                        precision + recall)

    def describe(loc, group):
        lab = label_index.get(loc)
        return {
            "file": loc[0], "line": loc[1],
            "labelled_primitive": (lab or {}).get("primitive"),
            "labelled_code": (lab or {}).get("code"),
            "labelled_break_model": (lab or {}).get("break_model"),
            "labelled_reason": (lab or {}).get("reason"),
            "indramesh_names": sorted({str(g.get("name")) for g in group}),
            "indramesh_rule_ids": sorted({str(g.get("rule_id")) for g in group}),
            "indramesh_match": [g.get("match") for g in group][:4],
        }

    return {
        "counts": {"TP": tp, "FP": fp, "FN": fn,
                   "labelled_positives": len(positives), "findings_total": len(findings)},
        "precision": precision,
        "precision_fraction": "%d/%d" % (tp, tp + fp) if (tp + fp) else "0/0",
        "recall": recall,
        "recall_fraction": "%d/%d" % (tp, tp + fn),
        "f1": f1,
        "f1_note": "F1 is computed from the ROUNDED precision/recall, so it may differ in the "
                   "4th decimal from an F1 computed from the raw counts.",
        "false_positives": [describe(loc, g) for loc, g in sorted(fp_locs.items())],
        "false_negatives": [describe(loc, [label_index[loc]]) for loc in sorted(positives - hit)],
    }


def file_level_score(findings, positives):
    """Secondary, coarser view: did the tool flag the right FILES at all?"""
    pos_files = {f for f, _ in positives}
    hit_files = {f["_loc"][0] for f in findings if f["_loc"][0] in pos_files}
    fp_files = {f["_loc"][0] for f in findings if f["_loc"][0] not in pos_files}
    tp = len(hit_files)
    return {
        "counts": {"TP": tp, "FP": len(fp_files), "FN": len(pos_files) - tp,
                   "labelled_positive_files": len(pos_files)},
        "precision": _ratio(tp, tp + len(fp_files)),
        "precision_fraction": "%d/%d" % (tp, tp + len(fp_files)),
        "recall": _ratio(tp, len(pos_files)),
        "recall_fraction": "%d/%d" % (tp, len(pos_files)),
        "false_positive_files": sorted(fp_files),
        "false_negative_files": sorted(pos_files - hit_files),
    }


def primitive_breakdown(positives, label_index, hit):
    rows = {}
    for loc in positives:
        lab = label_index[loc]
        key = "%s (%s)" % (lab["primitive"], lab["break_model"])
        r = rows.setdefault(key, {"labelled": 0, "detected": 0})
        r["labelled"] += 1
        if loc in hit:
            r["detected"] += 1
    for key, r in rows.items():
        r["recall"] = _ratio(r["detected"], r["labelled"])
    return dict(sorted(rows.items()))


def evaluate(name, spec, force_fetch):
    root, head = ensure_corpus(name, spec, force=force_fetch)
    labels = load_labels(name)
    n_checked = verify_labels(name, spec, root, labels)

    scanner = IndraMeshScanner(enable_ml=False)
    # A corpus is normally measured by walking a directory. `scan_files` exists for the case
    # where the honest unit of measurement is a HAND-PICKED SET OF FILES rather than a whole
    # subtree -- which is not a convenience. It is the only way to publish a number from a
    # subset of a package that has been fully read, without silently widening the scope to
    # files nobody annotated. It is deliberately opt-in per corpus: if a spec has `scan_files`,
    # exactly those files are scanned and nothing else, so the scope in the label file and the
    # scope measured cannot drift apart.
    if spec.get("scan_files"):
        findings = []
        for rel in spec["scan_files"]:
            path = os.path.join(root, rel.replace("/", os.sep))
            if not os.path.isfile(path):
                raise IntegrityError(
                    "corpus %s declares scan_files entry %r which is not present at the pinned "
                    "commit" % (name, rel))
            findings.extend(scanner._scan_path(path))
    else:
        scan_root = os.path.join(root, spec["scan_subdir"].replace("/", os.sep))
        findings = scanner.scan_directory(scan_root)

    for f in findings:
        f["_loc"] = (os.path.relpath(f.get("file", ""), root).replace("\\", "/"),
                     f.get("line"))
    label_index = {(l["file"], l["line"]): l for l in labels["labels"]}

    out = {
        "corpus": name,
        "corpus_kind": spec["kind"],
        "corpus_url": spec["url"],
        "corpus_pinned_commit": head,
        "citation": spec["citation"],
        "corpus_notes": spec["notes"],
        "scan_root_relative": (spec.get("scan_files") and
                               "explicit file list: %s" % ", ".join(spec["scan_files"])) or
                              spec["scan_subdir"],
        "ground_truth": {
            "label_file": "benchmark/labels/%s_pq.json" % name,
            "label_kind": labels["label_kind"],
            "labels_verified_against_corpus": n_checked,
            "annotation": labels["annotation"],
        },
        "coverage": scanner.coverage_manifest(findings),
        "scan_errors": scanner.errors,
        "findings_by_rule": {},
        "variants": {},
    }
    for r, n in sorted({}.fromkeys([]).items()):
        pass
    agg = {}
    for f in findings:
        k = "%s | %s" % (f.get("name"), f.get("rule_id"))
        agg[k] = agg.get(k, 0) + 1
    out["findings_by_rule"] = dict(sorted(agg.items(), key=lambda kv: -kv[1]))

    for variant in ("L1", "L2"):
        pos = positives_for(labels, variant)
        res = score(findings, pos, label_index)
        res["file_level"] = file_level_score(findings, pos)
        res["by_primitive"] = primitive_breakdown(
            pos, label_index, {f["_loc"] for f in findings} & pos)
        out["variants"][variant] = res
    return out


def render_markdown(results):
    L = []
    A = L.append
    A("# IndraMesh external-accuracy benchmark results")
    A("")
    A("Reproduce everything in this file with one command:")
    A("")
    A("```")
    A("python benchmark/run_benchmark.py")
    A("```")
    A("")
    A("## Which corpus is this, and is it external or hand-labelled?")
    A("")
    A("**Both corpora are EXTERNAL and were fetched from the network. The line-level ground")
    A("truth is hand-annotated by the author of this harness, not supplied by the corpus")
    A("authors, because neither published corpus labels *quantum vulnerability* -- they label")
    A("*API misuse*. That distinction is the single most important caveat in this document and")
    A("is repeated in every table below.**")
    A("")
    A("| corpus | external? | pinned commit | what it is |")
    A("|---|---|---|---|")
    for r in results:
        A("| `%s` | yes (git clone) | `%s` | %s |"
          % (r["corpus"], r["corpus_pinned_commit"][:12], r["corpus_notes"]))
    A("")
    A("### Why the ground truth had to be hand-made")
    A("")
    A("CryptoAPI-Bench ships `CryptoAPI-Bench_details.xlsx` with 182 rows of *misuse* labels")
    A("(28 categories: `Constant Seed`, `Usage of ECB`, `RSA keysize 1024 bits`, `DES used`,")
    A("`PBE iteration < 1000`, ...). IndraMesh is a **quantum**-vulnerability detector. Those are")
    A("different properties, so scoring IndraMesh against the published labels would be a category")
    A("error, and we do not report such a number as an accuracy figure. Instead each corpus")
    A("carries a hand-annotated label set whose unit is one `(file, line)` location and whose")
    A("criterion is stated in full below and in `benchmark/labels/README.md`.")
    A("")
    A("## Labelling criterion (identical for both corpora)")
    A("")
    A("A `(file, line)` location is **POSITIVE** iff it *names*, or *binds a name to*, a")
    A("quantum-vulnerable cryptographic primitive in a position that determines the algorithm:")
    A("")
    A("- `P1` a factory call that selects the algorithm, e.g. `Cipher.getInstance` with an AES literal, `KeyGenerator.getInstance(keyAlgo)` where `keyAlgo` holds DES, `hashlib.sha256`, `rsa.generate_private_key(...)`;")
    A("- `P1b` naming a quantum-vulnerable primitive identifier in executable code,")
    A("  including type annotations and `isinstance` checks, e.g. `X25519PrivateKey.generate()`;")
    A("- `P2` a key-spec / hash-constant binding -- `new SecretKeySpec(bytes, \"AES\")`,")
    A("  `hashes.SHA256`;")
    A("- `P3` a *taint source* -- a literal that determines the algorithm further down, e.g.")
    A("  `public static final String DEFAULT_CRYPTO = \"IDEA\";`, `from hashlib import sha1`;")
    A("- `P4` an SSH/OpenSSL algorithm identifier naming a quantum-vulnerable primitive, e.g.")
    A("  `\"ecdh-sha2-nistp256\"`, `\"ssh-ed25519\"`, `\"aes256-ctr\"`, `\"hmac-sha2-256\"`.")
    A("")
    A("A location that merely **operates** on a primitive chosen elsewhere -- `cipher.init`,")
    A("`md.update`, `cipher.encryptor()`, `.digest()`, `compute_hmac(...)` -- is **NEGATIVE in**")
    A("**L1** and **POSITIVE in L2**. Comments, PRNGs (`SecureRandom`, `random`), IVs and salts,")
    A("PBKDF parameter objects, key-store container formats (`JKS`) and key/block-size plumbing")
    A("are negative in both, each with a recorded reason.")
    A("")
    A("This criterion **favours IndraMesh**: every excluded operation line is a location the tool")
    A("did not report and would otherwise have counted as a false negative. That is exactly why")
    A("L2 is reported next to L1 rather than buried.")
    A("")
    A("Break models follow NIST/`engine/mosca.py`: `shor` = broken outright (RSA, DSA, DH, ECDH,")
    A("ECDSA, EdDSA, ElGamal, X25519); `grover` = quadratic speed-up only, not retroactive (AES,")
    A("DES, 3DES, Blowfish, RC2, RC4, IDEA, ChaCha20, MD2/4/5, SHA-1/2, HMAC).")
    A("")
    A("## Headline numbers (line level)")
    A("")
    A("`precision = TP / (TP + FP)`, `recall = TP / (TP + FN)`. Every ratio is shown with the")
    A("counts it came from; no ratio is reported without them.")
    A("")
    A("| corpus | labels | TP | FP | FN | precision | recall | F1 |")
    A("|---|---|---|---|---|---|---|---|")
    for r in results:
        for v in ("L1", "L2"):
            s = r["variants"][v]
            c = s["counts"]
            A("| `%s` | %s | %d | %d | %d | %s = %d/%d | %s = %d/%d | %s |"
              % (r["corpus"], v, c["TP"], c["FP"], c["FN"],
                 s["precision"], c["TP"], c["TP"] + c["FP"],
                 s["recall"], c["TP"], c["TP"] + c["FN"], s["f1"]))
    A("")
    A("### File-level view (secondary)")
    A("")
    A("| corpus | labels | TP | FP | FN | precision | recall |")
    A("|---|---|---|---|---|---|---|")
    for r in results:
        for v in ("L1", "L2"):
            f = r["variants"][v]["file_level"]
            c = f["counts"]
            A("| `%s` | %s | %d | %d | %d | %s | %s |"
              % (r["corpus"], v, c["TP"], c["FP"], c["FN"], f["precision"], f["recall"]))
    A("")
    A("### Recall by primitive (L1)")
    A("")
    A("| corpus | primitive (break model) | labelled | detected | recall |")
    A("|---|---|---|---|---|")
    for r in results:
        for key, row in r["variants"]["L1"]["by_primitive"].items():
            A("| `%s` | %s | %d | %d | %s |"
              % (r["corpus"], key, row["labelled"], row["detected"], row["recall"]))
    A("")
    A("## Coverage and scan honesty")
    A("")
    A("`files_skipped` and `errors` are reported so that \"the tool found nothing here\" can")
    A("never be confused with \"the tool could not look here\".")
    A("")
    A("| corpus | files seen | files scanned | files skipped | scan errors |")
    A("|---|---|---|---|---|")
    for r in results:
        cov = r["coverage"]
        A("| `%s` | %d | %d | %d | %d |"
          % (r["corpus"], cov["files_seen"], cov["files_scanned"],
             cov["files_skipped"], len(r["scan_errors"])))
    A("")
    for r in results:
        A("Findings emitted for `%s`, by rule:" % r["corpus"])
        A("")
        A("| rule | findings |")
        A("|---|---|")
        for k, n in r["findings_by_rule"].items():
            A("| %s | %d |" % (k, n))
    for r in results:
        for v in ("L1", "L2"):
            s = r["variants"][v]
            A("## Explicit false positives -- `%s`, %s (%d)"
              % (r["corpus"], v, len(s["false_positives"])))
            A("")
            A("A false positive is a finding at a `(file, line)` that the labels record as NOT")
            A("a quantum-vulnerable cryptographic use. The exclusion reason is quoted verbatim")
            A("from the label file, so each row can be checked against the source.")
            A("")
            if not s["false_positives"]:
                A("None.")
                A("")
                continue
            A("| file:line | why the labels exclude it | IndraMesh called it | rule |")
            A("|---|---|---|---|")
            for fp in s["false_positives"]:
                A("| `%s:%d` | %s | %s | %s |"
                  % (fp["file"], fp["line"],
                     (fp["labelled_reason"] or "line was not a labelling candidate"),
                     ", ".join(fp["indramesh_names"]), ", ".join(fp["indramesh_rule_ids"])))
            A("")
    for r in results:
        for v in ("L1", "L2"):
            s = r["variants"][v]
            A("## Explicit false negatives -- `%s`, %s (%d)"
              % (r["corpus"], v, len(s["false_negatives"])))
            A("")
            A("A false negative is a labelled quantum-vulnerable location IndraMesh did not report.")
            A("")
            if not s["false_negatives"]:
                A("None.")
                A("")
                continue
            A("| file:line | primitive (break model) | the quantum-vulnerable code |")
            A("|---|---|---|")
            for fn in s["false_negatives"]:
                A("| `%s:%d` | %s (%s) | `%s` |"
                  % (fn["file"], fn["line"], fn["labelled_primitive"],
                     fn["labelled_break_model"],
                     (fn["labelled_code"] or "").replace("|", "\\|")))
            A("")
    return L


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--fetch", action="store_true",
                    help="re-clone / hard-reset each corpus to its pinned commit first")
    ap.add_argument("--no-write", action="store_true", help="print, do not write results files")
    ap.add_argument("--only", default=None, help="measure a single corpus by name")
    args = ap.parse_args()

    results = []
    for name, spec in CORPORA.items():
        if args.only and args.only != name:
            continue
        try:
            res = evaluate(name, spec, args.fetch)
        except IntegrityError as exc:
            print("INTEGRITY FAILURE: %s" % exc, file=sys.stderr)
            return 2
        results.append(res)

    if not results:
        print("no corpora selected", file=sys.stderr)
        return 2

    for r in results:
        for v in ("L1", "L2"):
            s = r["variants"][v]
            c = s["counts"]
            print("%-16s %s  TP=%-4d FP=%-4d FN=%-4d  precision=%-6s (%s)  recall=%-6s (%s)  F1=%s"
                  % (r["corpus"], v, c["TP"], c["FP"], c["FN"],
                     s["precision"], s["precision_fraction"], s["recall"],
                     s["recall_fraction"], s["f1"]))
        cov = r["coverage"]
        print("%-16s coverage: files_seen=%d files_scanned=%d files_skipped=%d errors=%d"
              % (r["corpus"], cov["files_seen"], cov["files_scanned"],
                 cov["files_skipped"], len(r["scan_errors"])))

    if not args.no_write:
        payload = {
            "harness": "benchmark/run_benchmark.py",
            "scanner": "engine.scanner.IndraMeshScanner(enable_ml=False)",
            "matching_rule": "a finding is a true positive iff its (file, line) is a labelled "
                             "positive location; distinct locations are counted, so a second "
                             "finding on an already-matched positive line is neither a TP nor "
                             "an FP",
            "corpora": results,
        }
        with open(RESULTS_JSON, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, default=str)
            fh.write("\n")
        md = render_markdown(results)
        md += LIMITATIONS
        with open(RESULTS_MD, "w", encoding="utf-8") as fh:
            fh.write("\n".join(md))
            fh.write("\n")
        print("\nwrote %s and %s" % (RESULTS_JSON, RESULTS_MD))
    return 0


LIMITATIONS = [
    "",
    "## Limitations, stated plainly",
    "",
    "1. **The ground truth is ours, not the corpus authors'.** It was annotated by the author",
    "   of this harness. Every label records its verbatim source line, and the harness re-reads",
    "   each one from the pinned corpus and aborts on mismatch, so the label set is auditable",
    "   and tamper-evident -- but it is still one annotator's judgement, with no second",
    "   annotator and no inter-annotator agreement figure. We do not claim otherwise.",
    "2. **CryptoAPI-Bench is a constructed benchmark.** Its 203 files are small, deliberately",
    "   written Java micro-programmes, not production code. It is genuinely third-party and",
    "   peer-reviewed, but it is not evidence about messy real-world code. `paramiko` is",
    "   included precisely because it is real production code.",
    "3. **The L1 criterion favours the tool.** Operation lines (`cipher.init`, `.digest()`) are",
    "   excluded from L1 and included in L2. L2 is the lower bound on recall; read it before",
    "   quoting a recall number.",
    "4. **IndraMesh was run with `enable_ml=False`.** The optional PyTorch classifier is therefore",
    "   absent from these numbers, and `dl_confidence` is not populated. This is deliberate: the",
    "   benchmark must be hermetic and reproducible on a machine with no model file.",
    "5. **Regex-rule coverage is the whole story here.** Every number above is a measurement of",
    "   the hand-written rule table plus primitive naming. Nothing in this benchmark validates",
    "   the CBOM, the Mosca arithmetic, or the recommender.",
    "6. **Line-level matching is strict.** A finding one line away from a labelled positive is a",
    "   false positive AND that positive is a false negative. The file-level table is given as",
    "   a coarser cross-check for exactly that reason.",
    "",
]


if __name__ == "__main__":
    sys.exit(main())
