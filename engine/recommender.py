def get_recommendation(finding, risk_assessment):
    """
    Provides context-aware Post-Quantum Cryptography recommendations.
    """
    name = finding.get('name', '')
    tier = risk_assessment.get('tier', 'LOW')
    
    recommendation = {
        'action': 'Maintain',
        'algorithm': 'Current',
        'tradeoff_latency': '+0ms',
        'tradeoff_size': '+0KB'
    }
    
    if name == 'RSA' or name == 'ECC':
        if tier in ['CRITICAL', 'HIGH']:
            recommendation['action'] = 'Migrate to Hybrid PQC'
            recommendation['algorithm'] = 'ML-KEM-768 (Kyber) + X25519'
            recommendation['tradeoff_latency'] = '+1.5ms'
            recommendation['tradeoff_size'] = '+1.08KB (Ciphertext)'
            
    elif name == 'AES':
        recommendation['action'] = 'Upgrade Key Size'
        recommendation['algorithm'] = 'AES-256 (for Grover mitigation)'
        recommendation['tradeoff_latency'] = '+0.2ms'
        recommendation['tradeoff_size'] = '+0KB'
        
    return recommendation
