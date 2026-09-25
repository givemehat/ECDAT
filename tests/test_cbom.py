import json
from engine.cbom import generate_cbom

def test_cbom_empty_findings():
    cbom_json = generate_cbom([])
    cbom = json.loads(cbom_json)
    assert cbom['bomFormat'] == 'CycloneDX'
    assert len(cbom['components']) == 0

def test_cbom_with_all_optional_fields():
    findings = [{
        'name': 'ECC',
        'primitive': 'public-key',
        'key_length': 256,
        'curve': 'secp256r1',
        'mode': 'ECDH',
        'risk': {'tier': 'HIGH', 'threat': 'Shor'},
        'recommendation': {'algorithm': 'ML-KEM'}
    }]
    cbom_json = generate_cbom(findings, enriched=True)
    cbom = json.loads(cbom_json)
    
    comp = cbom['components'][0]
    props = {p['name']: p['value'] for p in comp['properties']}
    
    assert props['keyLength'] == '256'
    assert props['curve'] == 'secp256r1'
    assert props['mode'] == 'ECDH'
    assert props['moscaRiskTier'] == 'HIGH'
    assert props['quantumThreat'] == 'Shor'
    assert props['pqcRecommendation'] == 'ML-KEM'
