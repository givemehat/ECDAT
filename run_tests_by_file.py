# Run the whole suite ONE TEST FILE AT A TIME, reporting each separately.
#
# Why not just `pytest -q`: a single summary line hides which area is weak, and a failure in one
# area can cascade into others. Per-file reporting makes the shape of the suite visible and turns
# "408 passed" into "here is where we are strong and here is where we are thin" -- which is the
# only useful form of that number.
#
#   python run_tests_by_file.py            # every test file
#   python run_tests_by_file.py mosca      # only files matching 'mosca'
#   python run_tests_by_file.py --verbose  # show the per-test tail on failure
import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = os.path.join(HERE, "tests")

# Per-file expectations worth stating, because a bare count hides whether a module is actually
# defended. A file below its floor is a warning even when it passes.
FLOORS = {
    "test_mosca.py": 8,
    "test_scanner.py": 12,
    "test_cbom.py": 8,
    "test_recommender.py": 8,
    "test_cbom_schema.py": 8,
    "test_purpose.py": 6,
    "test_fspolicy.py": 10,
    "test_properties.py": 15,
    "test_differential.py": 8,
    "test_fuzz.py": 6,
    "test_mutation_kills.py": 10,
    "test_dependencies.py": 20,
    "test_verify_migration.py": 20,
    "test_competitive_upgrades.py": 10,
    "test_gui_helpers.py": 8,
    # Deliberately high floors on the two files that are genuinely thin. An "integration" file
    # with 4 tests and a schema file with 4 are the weakest points in the suite, and the honest
    # move is to make this tool say so on every run until they are fixed.
    "test_integration.py": 10,
    "test_ml.py": 8,
}

COLLECT = re.compile(r"(\d+)\s+(passed|failed|error|errors|skipped|xfailed|xpassed)\b")


def run_one(path, verbose):
    """Run one test file. Returns (name, passed, failed, skipped, seconds, failure_text).

    Runs with the REPOSITORY ROOT as cwd, not tests/. Several test modules rely on the root
    being importable and do not bootstrap sys.path themselves; running from tests/ makes
    `import engine` fail and every such file reports a spurious collection error.
    """
    started = time.time()
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", os.path.join("tests", os.path.basename(path)),
         "-q", "--no-header", "-p", "no:cacheprovider"],
        cwd=HERE, capture_output=True, text=True, timeout=1800)
    out = proc.stdout or ""
    tail = out[-2500:] if verbose else ""
    counts = {k: 0 for k in ("passed", "failed", "skipped", "error")}
    for n, word in COLLECT.findall(out):
        key = "error" if word.startswith("error") else word
        counts[key] = counts.get(key, 0) + int(n)
    if proc.returncode not in (0, 1):
        # Non-standard exit: collection error or crash. Surface it rather than reporting 0/0.
        return (os.path.basename(path), 0, 1, 0, time.time() - started,
                out[-1500:] or proc.stderr[-1500:])
    return (os.path.basename(path), counts["passed"], counts["failed"] + counts["error"],
            counts["skipped"], time.time() - started, tail)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pattern", nargs="?", default="", help="only files whose name matches this")
    ap.add_argument("--verbose", action="store_true", help="show failure output")
    args = ap.parse_args()

    if not os.path.isdir(TESTS):
        print("run this from the repository root", file=sys.stderr)
        return 2

    files = sorted(f for f in os.listdir(TESTS)
                   if f.startswith("test_") and f.endswith(".py")
                   and args.pattern.lower() in f.lower())
    if not files:
        print(f"no test files matched {args.pattern!r}", file=sys.stderr)
        return 2

    print(f"Running {len(files)} test file(s) individually\n")
    print(f"{'file':<38} {'pass':>5} {'fail':>5} {'skip':>5} {'sec':>6}  status")
    print("-" * 78)

    rows, thin = [], []
    for name in files:
        row = run_one(os.path.join(TESTS, name), args.verbose)
        rows.append(row)
        status = "OK" if row[2] == 0 else "FAIL"
        floor = FLOORS.get(name)
        if floor and row[1] < floor and row[2] == 0:
            status = f"OK (thin: <{floor})"
            thin.append((name, row[1], floor))
        print(f"{row[0]:<38} {row[1]:>5} {row[2]:>5} {row[3]:>5} {row[4]:>6.1f}  {status}")
        if row[2] and args.verbose and row[5]:
            print("    " + row[5].replace("\n", "\n    ")[:2000])

    tp = sum(r[1] for r in rows)
    tf = sum(r[2] for r in rows)
    ts = sum(r[3] for r in rows)
    print("-" * 78)
    print(f"{'TOTAL':<38} {tp:>5} {tf:>5} {ts:>5} {sum(r[4] for r in rows):>6.1f}")
    if thin:
        print("\nThin coverage (passing, but fewer tests than the floor):")
        for name, got, floor in thin:
            print(f"  - {name}: {got} tests, floor {floor}. A module this thin is the "
                  f"easiest place for a regression to hide.")
    if tf:
        print(f"\n{tf} FAILING. Re-run the failing file alone to see why.")
    return 1 if tf else 0


if __name__ == "__main__":
    sys.exit(main())
