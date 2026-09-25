import argparse
import sys
import json
from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk
from engine.cbom import generate_cbom

def run_headless_scan(target_dir, output_format, z_time=8):
    print(f"[*] ECDAT DevSecOps CI/CD Scanner starting on directory: {target_dir}")
    scanner = ECDATScanner()
    
    findings = scanner.scan_directory(target_dir)
    if not findings:
        print("[+] No cryptographic assets found. Scan clean.")
        sys.exit(0)
        
    enriched_findings = []
    critical_risks = 0
    from engine.recommender import get_pqc_recommendation
    for f in findings:
        f['risk'] = calculate_risk(f, z_collapse_time=z_time)
        f['recommendation'] = get_pqc_recommendation(f)
        if f['risk']['tier'] == 'CRITICAL':
            critical_risks += 1
        enriched_findings.append(f)
        
    if output_format == 'cbom':
        print("\n[*] Generating CBOM...")
        cbom = generate_cbom(enriched_findings, enriched=True)
        with open('ecdat_report.json', 'w') as out:
            out.write(cbom)
        print("[+] CBOM saved to ecdat_report.json")
    else:
        print(f"\n[*] Scan Complete. Found {len(enriched_findings)} assets.")
        for f in enriched_findings:
            print(f"  - {f['name']} in {f['file']} [Risk: {f['risk']['tier']}]")
            
    # Fail the CI/CD pipeline if critical quantum risks are found
    if critical_risks > 0:
        print(f"\n[!] ALERT: {critical_risks} CRITICAL quantum vulnerabilities found! Failing build.")
        sys.exit(1)
    else:
        print("\n[+] Build passed. No critical quantum risks detected.")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECDAT Headless Scanner for CI/CD")
    parser.add_argument("target", help="Target directory to scan")
    parser.add_argument("--format", choices=['text', 'cbom'], default='text', help="Output format")
    args = parser.parse_args()
    
    run_headless_scan(args.target, args.format)
