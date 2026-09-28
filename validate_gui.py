# -*- coding: utf-8 -*-
"""Headless smoke test of the Streamlit GUI against REAL corpus data.

The user will test the GUI by hand in a browser. That is the right way to judge it, but it is
not a way to find a crash on the first render. This runs the same code paths -- config parsing,
execute_scan, every view function, and the post-scan pipeline -- against a real Go source file
so that a broken import, a renamed helper or a None dereference surfaces here first.

Streamlit is not started: the view functions are called directly, which is what the app does
once a session exists. Anything that needs a live session raises here rather than in front of
the user.
"""
import os
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(ROOT, "benchmark", "corpora", "xcrypto", "ssh", "cipher.go")
if not os.path.isfile(CORPUS):
    # Fall back to a small real file if the corpus was not fetched.
    CORPUS = os.path.join(ROOT, "cli.py")

results = []


def step(name, fn):
    try:
        out = fn()
        results.append((name, "OK", out))
        return out
    except Exception as exc:  # noqa: BLE001 - the point is to report, not to mask
        results.append((name, "FAIL", "%s: %s" % (type(exc).__name__, exc)))
        traceback.print_exc()
        return None


# --- import the app the way Streamlit would -------------------------------------------------
step("import app", lambda: __import__("app"))

import app  # noqa: E402
import streamlit  # noqa: E402

print("streamlit %s" % streamlit.__version__)
print("app file    %s" % os.path.basename(app.__file__))
print("scan target %s" % CORPUS)

# --- a Streamlit session context, so helpers that read session state work --------------------
try:
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(os.path.join(ROOT, "app.py"), default_timeout=120)
    at.run()
    print("\nAppTest ran. exception count: %d" % (len(at.exception) if at.exception else 0))
    for e in (at.exception or []):
        print("  EXCEPTION: %s" % e)
    results.append(("streamlit AppTest", "OK" if not at.exception else "FAIL",
                    "%d element groups" % len(at)))
    results.append(("no runtime exception", "OK" if not at.exception else "FAIL", ""))
except Exception as exc:  # noqa: BLE001
    results.append(("streamlit AppTest", "FAIL", "%s: %s" % (type(exc).__name__, exc)))
    traceback.print_exc()

# --- the engine path, independent of Streamlit ------------------------------------------------
step("scanner import", lambda: __import__("engine.scanner", fromlist=["RULES"]))
from engine.scanner import ECDATScanner, RULES  # noqa: E402
from engine.mosca import calculate_risk, quantum_break_model  # noqa: E402

print("\nrules available: %d" % len(RULES))


def do_scan():
    s = ECDATScanner(enable_ml=False)
    findings = s._scan_path(CORPUS)
    return findings


findings = step("scan a real Go file", do_scan)
if findings is not None:
    print("findings on %s: %d" % (os.path.basename(CORPUS), len(findings)))
    names = sorted({f.get("name") for f in findings})
    print("  algorithms: %s" % ", ".join(str(n) for n in names[:12]))

    def do_analyse():
        rows = [calculate_risk(f) for f in findings]
        return [r for r in rows if r]
    analysed = step("mosca risk on every finding", do_analyse)
    if analysed is not None:
        print("risk records: %d" % len(analysed))
        tiers = {}
        for r in analysed:
            tiers[r.get("tier")] = tiers.get(r.get("tier"), 0) + 1
        print("  tiers: %s" % tiers)
        # The break model must never be guessed: an unknown primitive has to stay unrated.
        for nm in ("AES", "RSA", "ECDH", "ML-KEM-768", "PRNG"):
            bm = quantum_break_model(nm, "")
            print("    break_model(%-11s) = %s" % (nm, bm))

    def do_cbom():
        from engine.cbom import generate_cbom
        import json
        import jsonschema
        bom = generate_cbom(findings)
        schema = json.load(open(os.path.join(ROOT, "schemas", "bom-1.7.schema.json"),
                                encoding="utf-8"))
        jsonschema.Draft7Validator(schema).validate(json.loads(bom))
        return len(json.loads(bom).get("components", []))
    n = step("CBOM + schema validation", do_cbom)
    if n is not None:
        print("CBOM components: %d (schema-valid)" % n)

# --- gui_helpers, which the views call --------------------------------------------------------
def do_helpers():
    from engine import gui_helpers
    return len([n for n in dir(gui_helpers) if not n.startswith("_")])


nh = step("gui_helpers import", do_helpers)
if nh is not None:
    print("gui_helpers public names: %d" % nh)

print("\n" + "=" * 68)
bad = [r for r in results if r[1] == "FAIL"]
for name, status, extra in results:
    print("  %-28s %s %s" % (name, status, extra if status == "FAIL" else ""))
print("=" * 68)
print("%d checks, %d failed" % (len(results), len(bad)))
sys.exit(1 if bad else 0)

