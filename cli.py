"""ECDAT headless scanner for CI/CD pipelines and the command line.

    python cli.py ./target --format cbom --z 10 --policy india-dst-nqm
    python cli.py ./image.tar --format text
    python cli.py . --format cbom --no-ml --out reports/

Exit codes:  0 = no finding at or above --fail-on   1 = threshold exceeded   2 = scan error
"""
import argparse
import json
import os
import sys

from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk, DEFAULT_Z, POLICY_DEADLINES, Z_PRESETS
from engine.recommender import get_pqc_recommendation
from engine.cbom import generate_cbom

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _z_presets_help():
    return ", ".join("{}={}".format(name, preset["years"]) for name, preset in Z_PRESETS.items())


def run_headless_scan(target_dir, output_format="text", z_time=DEFAULT_Z,
                      policy="india_dst_nqm", enable_ml=True, out_dir=".",
                      fail_on="CRITICAL", subject_name=None):
    print(f"[*] ECDAT scan starting on: {target_dir}")
    print(f"    Z={z_time}y  policy={policy}"
          f"  policy deadline={POLICY_DEADLINES.get(policy, {}).get('year', 'n/a')}")

    scanner = ECDATScanner(enable_ml=enable_ml)
    findings = scanner.scan_directory(target_dir)
    coverage = scanner.coverage_manifest(findings)

    print(f"[*] Files scanned: {coverage['files_scanned']}  skipped: {coverage['files_skipped']}")
    print(f"    ML engine: {coverage['ml_reason']}")
    # The raw total alone is misleading: it mixes proven call sites with capabilities nothing
    # calls. Both numbers are shown so the reader can tell which is which.
    print(f"[*] Findings: {coverage['findings_total']} total, "
          f"{coverage['proven_use']} with proven use (used/observed), "
          f"{coverage['unresolved_purpose']} with unresolved purpose")
    print(f"    Assurance: {json.dumps(coverage['assurance_histogram'])}")
    if coverage["errors"]:
        print(f"[!] {len(coverage['errors'])} file(s) could not be read -- these are NOT clean:")
        for err in coverage["errors"][:10]:
            print(f"      - {err['file']}: {err['reason']}")
        if len(coverage["errors"]) > 10:
            print(f"      ... and {len(coverage['errors']) - 10} more")

    for f in findings:
        f["risk"] = calculate_risk(f, z_collapse_time=z_time, policy=policy)
        f["recommendation"] = get_pqc_recommendation(f)

    counts = {t: sum(1 for f in findings if f["risk"]["tier"] == t) for t in SEVERITY_ORDER}
    print(f"[*] {len(findings)} artefact(s): "
          + "  ".join(f"{t}={counts[t]}" for t in SEVERITY_ORDER))

    if output_format == "cbom":
        os.makedirs(out_dir, exist_ok=True)
        cbom_path = os.path.join(out_dir, "ecdat_report.json")
        with open(cbom_path, "w", encoding="utf-8") as fh:
            fh.write(generate_cbom(findings, enriched=True,
                                    subject_name=subject_name or os.path.basename(target_dir.rstrip("/\\")),
                                    coverage=coverage))
        recs_path = os.path.join(out_dir, "ecdat_recommendations.json")
        with open(recs_path, "w", encoding="utf-8") as fh:
            json.dump([{"target": f["file"], "line": f.get("line"), "artefact": f["name"],
                        "primitive": f["primitive"], "risk": f["risk"],
                        "recommendation": f["recommendation"]} for f in findings], fh, indent=2)
        cov_path = os.path.join(out_dir, "ecdat_coverage.json")
        with open(cov_path, "w", encoding="utf-8") as fh:
            json.dump(coverage, fh, indent=2)
        print(f"[+] CBOM          -> {cbom_path}")
        print(f"[+] Recommendations-> {recs_path}")
        print(f"[+] Coverage      -> {cov_path}")
    else:
        for f in findings:
            r = f["risk"]
            flag = " [HNDL EXPOSED]" if r["hndl_exposed"] else ""
            print(f"  - {f['name']:<12} {r['tier']:<9} X+Y={r['x_y']:>6} vs Z={r['z']:<5}"
                  f" margin={r['margin']:>6}{flag}  {f['file']}:{f.get('line')}")
            print(f"      {f['recommendation']['algorithm']}")

    print("\n[-- NOT IN SCOPE (require a different sensor or an attestation) --]")
    for gap in coverage["never_in_scope"]:
        print(f"    - {gap}")

    threshold = SEVERITY_ORDER.index(fail_on)
    breaches = [f for f in findings if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    if breaches:
        print(f"\n[!] {len(breaches)} finding(s) at or above {fail_on}. Failing build.")
        return 1
    print(f"\n[+] No findings at or above {fail_on}.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="ECDAT headless cryptographic scanner")
    parser.add_argument("target", help="Directory, file or container-image tar to scan")
    parser.add_argument("--format", choices=["text", "cbom"], default="text")
    parser.add_argument("--z", type=float, default=DEFAULT_Z,
                        help="Years until a CRQC. Presets: " + _z_presets_help())
    parser.add_argument("--policy", default="india_dst_nqm", choices=sorted(POLICY_DEADLINES))
    parser.add_argument("--out", default=".", help="Output directory for artefacts")
    parser.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    parser.add_argument("--no-ml", action="store_true",
                        help="Disable the PyTorch transformer (regex-only mode; no torch needed)")
    parser.add_argument("--subject", default=None, help="Subject name recorded in the CBOM metadata")
    args = parser.parse_args(argv)

    if not os.path.exists(args.target):
        print(f"[!] Target not found: {args.target}")
        return 2
    return run_headless_scan(args.target, args.format, args.z, args.policy,
                             not args.no_ml, args.out, args.fail_on, args.subject)


if __name__ == "__main__":
    sys.exit(main())
