import math

def calculate_risk(finding, user_x=None, user_y=None, z_collapse_time=8):
    """
    Applies an Advanced Mosca's Theorem (X + Y > Z).
    Now dynamically calculates Y (Migration Time) based on AST complexity (ast_depth)
    and X (Data Shelf Life) based on neural network confidence if not explicitly provided.
    """
    ast_depth = max(0.0, finding.get('ast_depth', 1.0))
    dl_confidence = max(0.0, min(1.0, finding.get('dl_confidence', 0.5)))
    
    if user_x is not None and user_x < 0:
        raise ValueError("Data Shelf Life (X) cannot be negative.")
    if user_y is not None and user_y < 0:
        raise ValueError("Migration Time (Y) cannot be negative.")
    
    # Advanced: If Y is not provided, estimate it using AST Depth. 
    # Deeper AST = More complex code = Harder to migrate = Higher Y
    # Base migration time is 1 year. Every 10 AST depth units adds 0.5 years.
    y_migration_time = user_y if user_y is not None else 1.0 + (ast_depth / 10.0) * 0.5
    
    # Advanced: If X is not provided, we use the Neural Network confidence as a proxy
    # for criticality. Highly confident detections usually correlate with core cryptographic
    # operations, which have longer data shelf life requirements (5-10 years).
    x_shelf_life = user_x if user_x is not None else 3.0 + (dl_confidence * 5.0)
    
    score = x_shelf_life + y_migration_time
    is_vulnerable = score > z_collapse_time
    
    name = finding.get('name', '')
    
    # Threat Vectors
    is_shors = any(v in name for v in ['RSA', 'ECC', 'DSA', 'DH'])
    is_grovers = any(v in name for v in ['AES', 'SHA'])
    
    # Probabilistic Risk Multiplier based on DL Confidence
    risk_multiplier = dl_confidence
    
    if is_shors:
        if is_vulnerable and risk_multiplier > 0.8:
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
        'x': round(x_shelf_life, 2),
        'y': round(y_migration_time, 2),
        'z': z_collapse_time,
        'x_y': round(score, 2),
        'is_vulnerable': is_vulnerable,
        'threat': threat,
        'tier': tier,
        'dl_confidence': round(dl_confidence, 4),
        'ast_depth': round(ast_depth, 2)
    }
