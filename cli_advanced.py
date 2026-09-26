"""
ECDAT advanced entry point: the two NEW sensors that cli.py does not wire in.

    python cli_advanced.py deps       ./target
    python cli_advanced.py verify-migration ./build/app.so --format json
    python cli_advanced.py all        ./target --z 10

SEPARATION, AND WHY
------------------------------------------------------------------------------------------------
`cli.py` is not modified: other work is in flight against it, and a sensor that only exists
behind a new entry point cannot break an existing pipeline. This file is additive. It imports
`engine.scanner` so the combined mode reports source AND dependency findings in one pass, and
so both sets share the Mosca/recommender treatment -- but the dependency findings carry
`evidence_class="dependency"`, which resolves to ASSURANCE_CAPABILITY and a different
recommendation, so the two never get conflated in the output.

Exit codes
    deps              0 = scanned, 1 = findings at/above --fail-on, 2 = a manifest was unreadable
    verify-migration  0 = verified, 1 = not verified, 2 = inconclusive
    all               0 = nothing breached, 1 = threshold breached, 2 = scan error
"""
import argparse
import json
import os
import sys

from engine.cbom import generate_cbom
from engine.dependencies import DependencyScanner
from engine.mosca import DEFAULT_Z, calculate_risk
from engine.recommender import get_pqc_recommendation
from engine.scanner import ECDATScanner
from engine.verify_migration import PQC_ALGORITHMS, MigrationVerifier
# Re-exported so a caller can write `from cli_advanced import EXIT_VERIFIED` rather than
# reaching into the engine module for a CLI contract constant.
from engine.verify_migration import (EXIT_INCONCLUSIVE, EXIT_NOT_VERIFIED,  # noqa: F401
                                     EXIT_VERIFIED)

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def run_deps(target, output_format="text", fail_on="CRITICAL", ecosystems=None, out_dir="."):
    """Dependency-manifest scan. Emits capability-tier findings, never breach language."""
    scanner = DependencyScanner(ecosystems=ecosystems)
    findings = scanner.scan(target)
    coverage = scanner.coverage_manifest(findings)

    for finding in findings:
        finding["risk"] = calculate_risk(finding)
        finding["recommendation"] = get_pqc_recommendation(finding)

    print(f"[*] Dependency manifests seen: {coverage['manifests_seen']}  "
          f"parsed: {coverage['manifests_parsed']}  "
          f"unreadable: {coverage['manifests_unreadable']}")
    print(f"    Dependencies examined: {coverage['dependencies_examined']}  "
          f"recognised as crypto providers: {coverage['libraries_recognised']} "
          f"(map holds {coverage['libraries_in_map']})")
    print(f"    Ecosystems: {', '.join(coverage['ecosystems']) or 'none'}")
    if coverage["errors"]:
        # Named, not summarised away. This is the cryptodeps pattern and the whole point of the
        # `errors` channel: an unreadable manifest is NOT a clean manifest.
        print(f"[!] {len(coverage['errors'])} file(s) NOT read -- these are NOT clean:")
        for err in coverage["errors"][:15]:
            print(f"      - {err['file']}: {err['reason']}")
        if len(coverage["errors"]) > 15:
            print(f"      ... and {len(coverage['errors']) - 15} more")

    pqc = [f for f in findings if f.get("provides_pqc")]
    print(f"[*] {len(findings)} crypto provider(s) reachable; {len(pqc)} provide "
          f"standardised post-quantum algorithms.")
    print("    ASSURANCE: capability. A dependency makes an algorithm REACHABLE; no finding "
          "here proves a call site.")

    if output_format == "json":
        payload = {"findings": findings, "coverage": coverage}
        print(json.dumps(payload, indent=2))
    else:
        for finding in findings:
            print(f"  - {finding['name']:<28} {finding['provides_pqc'] and 'PQC' or '   '} "
                  f"{', '.join(finding['provides'][:6])}"
                  f"{' ...' if len(finding['provides']) > 6 else ''}")
            print(f"      {finding['file']}:{finding.get('line')}")
            if finding.get("capability_gate"):
                print(f"      gate: {finding['capability_gate']}")

    print("\n[-- NOT IN SCOPE for a dependency manifest --]")
    for gap in coverage["never_in_scope"]:
        print(f"    - {gap}")

    threshold = SEVERITY_ORDER.index(fail_on)
    breaches = [f for f in findings
                if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "ecdat_dependencies.json"), "w", encoding="utf-8") as fh:
        json.dump({"findings": findings, "coverage": coverage}, fh, indent=2)
    print(f"[+] dependency report -> {os.path.join(out_dir, 'ecdat_dependencies.json')}")

    if coverage["errors"] and not coverage["manifests_parsed"]:
        # Every manifest we found was unreadable, so "no findings" would be indistinguishable
        # from "no cryptography". Exit 2 says the scan did not happen.
        print("\n[!] No manifest could be read at all. The result is not a clean bill of health.")
        return 2
    if breaches:
        print(f"\n[!] {len(breaches)} provider(s) at or above {fail_on}.")
        return 1
    print(f"\n[+] No provider at or above {fail_on}.")
    return 0
def run_verify_migration(target, output_format="text", out_dir="."):
    """Post-migration verification. The exit code IS the verdict, so this is CI-usable as-is:
    `verify-migration && deploy` refuses to deploy on an unverified or unreadable artefact."""
    verifier = MigrationVerifier()
    report = verifier.verify(target)

    print(f"[*] Artefacts examined: {report['files_examined']}")
    print("[*] Per-algorithm status (FIPS 203/204/205/206):")
    for algo in PQC_ALGORITHMS:
        data = report["algorithms"][algo]
        markers = ", ".join(sorted({m["marker"] for m in data["matches"]})) or "-"
        print(f"      {algo:<9} {data['status']:<20} {markers}")
        for reason in data["reasons"][:2]:
            print(f"                 why: {reason}")

    if report["hybrids"]:
        print("[*] Hybrid constructions found:")
        for hybrid in report["hybrids"]:
            kind = "HYBRID" if hybrid["is_hybrid"] else "pure PQ"
            codepoint = (f"IANA {hybrid['iana_codepoint']}"
                         if hybrid["iana_codepoint"] else "no IANA codepoint")
            print(f"      {hybrid['name']} ({kind})  {codepoint}  {hybrid['specification']}")
            print(f"                 classical half: {hybrid['classical_half']}   "
                  f"PQC half: {hybrid['pqc_half']}")
        print(f"      semantics: {report['hybrids'][0]['semantics']}")
    if report["deprecated_variants"]:
        print("[!] DEPRECATED pre-standardisation markers -- these are NOT the FIPS algorithms:")
        for hit in report["deprecated_variants"]:
            print(f"      - {hit['marker']}  ({hit['file']}:{hit['line']})")
            print(f"        {hit['reason']}")
    if report["other_pqc_drafts"]:
        print("[!] Other post-quantum DRAFT names (not one of the four FIPS algorithms):")
        for hit in report["other_pqc_drafts"]:
            print(f"      - {hit['marker']}  ({hit['file']}:{hit['line']})")
    if report["errors"]:
        print(f"[!] {len(report['errors'])} artefact(s) NOT read -- not a clean result:")
        for err in report["errors"][:15]:
            print(f"      - {err['file']}: {err['reason']}")

    print(f"\n[*] VERDICT: {report['verdict'].upper()}  (exit {report['exit_code']})")
    print(f"    {report['verdict_reason']}")
    print(f"    Evidence: {report['evidence_note']}")
    print("\n[-- WHAT THIS DOES NOT PROVE --]")
    for item in report["not_proven"]:
        print(f"    - {item}")

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "ecdat_migration_verification.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    if output_format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(f"\n[+] verification report -> {path}")
    return report["exit_code"]
def run_all(target, z_time=DEFAULT_Z, policy="india_dst_nqm", enable_ml=True,
            fail_on="CRITICAL", out_dir="."):
    """Source + binary + dependency findings in one pass, then migration verification.

    The two finding sets are concatenated, never merged: a dependency finding keeps
    `evidence_class="dependency"` so `calculate_risk` and `get_pqc_recommendation` treat it as a
    capability, while a source finding keeps `discovered`. The CBOM then records the assurance
    level per component, which is the only way a reader can tell them apart downstream.
    """
    source_scanner = ECDATScanner(enable_ml=enable_ml)
    source_findings = source_scanner.scan_directory(target)
    source_coverage = source_scanner.coverage_manifest(source_findings)

    dep_scanner = DependencyScanner()
    dep_findings = dep_scanner.scan(target)
    dep_coverage = dep_scanner.coverage_manifest(dep_findings)

    findings = list(source_findings) + list(dep_findings)
    for finding in findings:
        finding["risk"] = calculate_risk(finding, z_collapse_time=z_time, policy=policy)
        finding["recommendation"] = get_pqc_recommendation(finding)

    capabilities = [f for f in findings if f.get("evidence_class") == "dependency"]
    proven = [f for f in findings if f.get("evidence_class") in ("discovered", "observed",
                                                                "negotiated")]
    print(f"[*] Findings: {len(findings)} total  |  {len(proven)} with proven use  |  "
          f"{len(capabilities)} capability (dependency)")
    print(f"    source findings: {len(source_findings)}   dependency findings: {len(dep_findings)}")

    os.makedirs(out_dir, exist_ok=True)
    cbom_path = os.path.join(out_dir, "ecdat_cbom_advanced.json")
    coverage = {
        "source_scanner": source_coverage,
        "dependency_scanner": dep_coverage,
        "findings_total": len(findings),
        "proven_use": len(proven),
        "capability_only": len(capabilities),
    }
    with open(cbom_path, "w", encoding="utf-8") as fh:
        fh.write(generate_cbom(findings, enriched=True,
                               subject_name=os.path.basename(target.rstrip("/\\")),
                               coverage=coverage))
    print(f"[+] CBOM -> {cbom_path}")

    run_verify_migration(target, out_dir=out_dir)

    threshold = SEVERITY_ORDER.index(fail_on)
    breaches = [f for f in findings
                if SEVERITY_ORDER.index(f["risk"]["tier"]) >= threshold]
    if breaches:
        print(f"\n[!] {len(breaches)} finding(s) at or above {fail_on}. Failing build.")
        return 1
    print(f"\n[+] No finding at or above {fail_on}.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="ECDAT advanced sensors: dependency manifests and PQC migration verification")
    sub = parser.add_subparsers(dest="command", required=True)

    deps = sub.add_parser("deps", help="Scan dependency manifests for crypto capabilities")
    deps.add_argument("target")
    deps.add_argument("--format", choices=["text", "json"], default="text")
    deps.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    deps.add_argument("--ecosystem", action="append", default=None,
                      help="Restrict to one ecosystem (repeatable): pip, pyproject, npm, gomod, "
                           "maven, cargo, gem, composer, dotnet")
    deps.add_argument("--out", default=".")

    verify = sub.add_parser("verify-migration",
                            help="Verify that a PQC migration actually landed in an artefact")
    verify.add_argument("target")
    verify.add_argument("--format", choices=["text", "json"], default="text")
    verify.add_argument("--out", default=".")

    combined = sub.add_parser("all", help="Source + dependency scan, then migration verification")
    combined.add_argument("target")
    combined.add_argument("--z", type=float, default=DEFAULT_Z)
    combined.add_argument("--policy", default="india_dst_nqm")
    combined.add_argument("--fail-on", default="CRITICAL", choices=SEVERITY_ORDER)
    combined.add_argument("--no-ml", action="store_true")
    combined.add_argument("--out", default=".")

    args = parser.parse_args(argv)
    if not os.path.exists(args.target):
        print(f"[!] Target not found: {args.target}")
        return 2
    if args.command == "deps":
        return run_deps(args.target, args.format, args.fail_on, args.ecosystem, args.out)
    if args.command == "verify-migration":
        return run_verify_migration(args.target, args.format, args.out)
    return run_all(args.target, args.z, args.policy, not args.no_ml, args.fail_on, args.out)


if __name__ == "__main__":
    sys.exit(main())