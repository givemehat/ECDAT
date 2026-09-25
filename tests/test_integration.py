import pytest
import os
import json
from engine.scanner import ECDATScanner
from engine.mosca import calculate_risk
from engine.cbom import generate_cbom

def test_full_pipeline_integration(tmpdir):
    # 1. Create a mock vulnerable directory
    test_dir = tmpdir.mkdir("dummy_code")
    vuln_file = test_dir.join("vuln.py")
    vuln_file.write("import os\nkey = rsa.newkeys(2048)\n")
    
    # 2. Run Scanner (Scanner inherently uses ML Inference)
    scanner = ECDATScanner()
    findings = scanner.scan_directory(str(test_dir))
    
    # Ensure it found something
    assert len(findings) > 0
    assert any(f['name'] == 'RSA' for f in findings)
    
    # 3. Enrich with Mosca
    enriched = []
    for f in findings:
        risk = calculate_risk(f, z_collapse_time=8)
        f['risk'] = risk
        enriched.append(f)
        
    # Verify risk applied properly
    assert 'tier' in enriched[0]['risk']
    assert enriched[0]['risk']['x'] > 0
    
    # 4. Generate CBOM
    cbom_json = generate_cbom(enriched, enriched=True)
    
    # 5. Validate CBOM Structure
    cbom = json.loads(cbom_json)
    assert cbom['bomFormat'] == 'CycloneDX'
    assert cbom['specVersion'] == '1.6'
    assert 'components' in cbom
    
    # Check components
    components = cbom['components']
    assert len(components) > 0
    assert 'cryptoProperties' in components[0]
