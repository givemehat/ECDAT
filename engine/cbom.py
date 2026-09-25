import json

def generate_cbom(findings, enriched=False):
    """
    Generates a CycloneDX 1.6 CBOM from findings.
    If enriched=True, includes Mosca Risk and Recommendations as properties.
    """
    components = []
    
    for idx, f in enumerate(findings):
        comp = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{idx}",
            "name": f.get('name', 'Unknown'),
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": f.get('primitive', 'unknown')
                }
            },
            "properties": []
        }
        
        if 'key_length' in f and f['key_length']:
            comp['properties'].append({"name": "keyLength", "value": str(f['key_length'])})
        if 'curve' in f:
            comp['properties'].append({"name": "curve", "value": f['curve']})
        if 'mode' in f:
            comp['properties'].append({"name": "mode", "value": f['mode']})
            
        if enriched and 'risk' in f:
            comp['properties'].append({"name": "moscaRiskTier", "value": f['risk']['tier']})
            comp['properties'].append({"name": "quantumThreat", "value": f['risk']['threat']})
        
        if enriched and 'recommendation' in f:
            comp['properties'].append({"name": "pqcRecommendation", "value": f['recommendation']['algorithm']})
            
        components.append(comp)
        
    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "ECDAT-Scanned-Artefact"
            }
        },
        "components": components
    }
    
    return json.dumps(cbom, indent=2)
