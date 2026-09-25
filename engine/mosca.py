def calculate_risk(finding, x_shelf_life, y_migration_time, z_collapse_time=8):
    """
    Applies Mosca's Theorem (X + Y > Z) to calculate quantum risk tier.
    X: Data Security Lifetime (years)
    Y: Migration Time (years)
    Z: Time until CRQC (Cryptographically Relevant Quantum Computer)
    """
    score = x_shelf_life + y_migration_time
    is_vulnerable = score > z_collapse_time
    
    name = finding.get('name', '')
    
    # Shor's Algorithm Vulnerability (Public Key)
    shors_vuln = ['RSA', 'ECC', 'DSA', 'DH']
    # Grover's Algorithm Vulnerability (Symmetric/Hash)
    grovers_vuln = ['AES', 'SHA']
    
    is_shors = any(name.startswith(v) for v in shors_vuln)
    is_grovers = any(name.startswith(v) for v in grovers_vuln)
    
    if is_shors:
        if is_vulnerable:
            tier = 'CRITICAL'
        else:
            tier = 'HIGH'
        threat = "Shor's Algorithm (Full Break)"
    elif is_grovers:
        tier = 'MEDIUM' if is_vulnerable else 'LOW'
        threat = "Grover's Algorithm (Key Space Reduction)"
    else:
        tier = 'LOW'
        threat = "Unknown/Low"
        
    return {
        'x': x_shelf_life,
        'y': y_migration_time,
        'z': z_collapse_time,
        'x_y': score,
        'is_vulnerable': is_vulnerable,
        'threat': threat,
        'tier': tier
    }
