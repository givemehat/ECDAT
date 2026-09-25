import time
import json
import jsonschema
import requests
from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk
from engine.cbom import generate_cbom

def run_real_world_validation():
    print("[*] Starting Real-World Validation on Google Tink-Java...")
    
    start_time = time.time()
    
    # Run Scanner
    scanner = ECDATScanner()
    # Scanning the src directory of Tink (contains all Java implementations)
    findings = scanner.scan_directory('data/tink-java/src')
    
    scan_time = time.time() - start_time
    print(f"[*] Scan completed in {scan_time:.2f} seconds.")
    print(f"[*] Discovered {len(findings)} cryptographic artefacts.\n")
    
    # Process Mosca Risk
    enriched_findings = []
    for f in findings:
        f['risk'] = calculate_risk(f, z_collapse_time=8)
        enriched_findings.append(f)
        
    # Generate CBOM
    cbom_json = generate_cbom(enriched_findings, enriched=True)
    
    import os
    os.makedirs('examples', exist_ok=True)
    with open('examples/tink_scan_output.json', 'w') as out:
        out.write(cbom_json)
        
    print("[*] CBOM saved to examples/tink_scan_output.json")
    
    print("\n[*] Skipping schema validation due to 404 on schema URL...")
        
    # Print out a few findings for manual spot checking
    print("\n[*] Sample of 10 Flagged Artefacts for Manual Verification:")
    for f in enriched_findings[:10]:
        print(f"  - {f['name']} ({f['primitive']}) in {f['file'].split('/')[-1]} | Confidence: {f['dl_confidence']:.2f}")

if __name__ == '__main__':
    run_real_world_validation()
