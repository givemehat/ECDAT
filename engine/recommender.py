def get_pqc_recommendation(finding):
    """
    Takes a cryptographic finding (with embedded risk profile) and returns 
    a specific Post-Quantum Cryptography (PQC) recommendation based on NIST standards.
    """
    name = finding.get('name', 'Unknown').upper()
    primitive = finding.get('primitive', 'unknown').lower()
    
    # Base response for unhandled/unknown algorithms
    rec = {
        'algorithm': 'Manual Review Needed',
        'action': 'Investigate',
        'justification': 'Artefact type not strictly recognized. Evaluate against NIST PQC standards based on use-case.',
        'tradeoff_latency': 'N/A',
        'tradeoff_size': 'N/A'
    }
    
    if name == 'RSA':
        if 'signature' in primitive or finding.get('mode') == 'signing':
            rec['algorithm'] = 'ML-DSA (Dilithium) or SLH-DSA'
            rec['action'] = 'Migrate to PQC Digital Signatures'
            rec['justification'] = 'ML-DSA is the primary NIST standard for general-purpose signatures. It has a larger signature size than RSA/ECDSA but performs well for TLS handshakes. SLH-DSA is a fallback for highly conservative systems.'
            rec['tradeoff_latency'] = '+0.8ms'
            rec['tradeoff_size'] = '+2.42KB (Signature)'
        else:
            # Default to Key Exchange / Encapsulation for RSA
            rec['algorithm'] = 'Hybrid ML-KEM (Kyber768) + X25519'
            rec['action'] = 'Migrate to Hybrid KEM'
            rec['justification'] = 'ML-KEM is the NIST standard for Key Encapsulation. Using a hybrid mode (with X25519) ensures FIPS compliance while maintaining protection against both classical and quantum threats.'
            rec['tradeoff_latency'] = '+1.5ms'
            rec['tradeoff_size'] = '+1.08KB (Ciphertext)'
            
    elif name == 'ECC':
        rec['algorithm'] = 'ML-DSA (Dilithium)'
        rec['action'] = 'Migrate to PQC Digital Signatures'
        rec['justification'] = 'Replaces ECDSA/EdDSA. ML-DSA has larger signature sizes than ECC, so network payload sizes should be evaluated, but validation speed is excellent.'
        rec['tradeoff_latency'] = '+0.8ms'
        rec['tradeoff_size'] = '+2.42KB (Signature)'
            
    elif name == 'AES' or 'symmetric' in primitive:
        key_len = finding.get('key_length', 128)
        if key_len and int(key_len) >= 256:
            rec['algorithm'] = 'AES-256 (Maintain)'
            rec['action'] = 'No immediate action required'
            rec['justification'] = 'AES-256 is already considered quantum-resistant against Grover\'s algorithm.'
            rec['tradeoff_latency'] = '0ms'
            rec['tradeoff_size'] = '0KB'
        else:
            rec['algorithm'] = 'AES-256'
            rec['action'] = 'Upgrade Key Size'
            rec['justification'] = 'Grover\'s algorithm effectively halves symmetric key strength. AES-128 is vulnerable; upgrading to AES-256 provides adequate quantum resistance.'
            rec['tradeoff_latency'] = '+0.1ms'
            rec['tradeoff_size'] = '0KB'
            
    elif name == 'SHA256' or name == 'SHA' or 'hash' in primitive:
        rec['algorithm'] = 'SHA-384 or SHA-512'
        rec['action'] = 'Upgrade Hash Function'
        rec['justification'] = 'Quantum algorithms reduce collision resistance. Upgrading to SHA-384 or SHA-512 ensures long-term cryptographic integrity.'
        rec['tradeoff_latency'] = '+0.05ms'
        rec['tradeoff_size'] = '0KB'

    return rec
