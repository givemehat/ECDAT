import pytest
from engine.mosca import calculate_risk

def test_mosca_critical_rsa():
    # Simulated finding for an RSA key with high DL confidence
    finding = {
        'name': 'RSA',
        'dl_confidence': 0.95,
        'ast_depth': 20.0
    }
    
    # Calculate risk with Z=8 (Quantum computers arrive in 8 years)
    risk = calculate_risk(finding, z_collapse_time=8)
    
    # Assertions
    assert risk['tier'] == 'CRITICAL'
    assert risk['threat'] == "Shor's Algorithm (Full Break)"
    assert risk['is_vulnerable'] == True
    assert risk['y'] == 2.0  # Migration time: 1.0 + (20.0 / 10.0) * 0.5 = 2.0
    assert risk['x'] == 7.75 # Shelf life: 3.0 + (0.95 * 5.0) = 7.75
    assert risk['x_y'] == 9.75 # Total: 7.75 + 2.0 = 9.75 (which is > 8)

def test_mosca_low_aes():
    # Simulated finding for an AES key with lower confidence/depth
    finding = {
        'name': 'AES_GCM',
        'dl_confidence': 0.60,
        'ast_depth': 5.0
    }
    
    risk = calculate_risk(finding, z_collapse_time=10)
    
    # X = 3.0 + (0.6 * 5.0) = 6.0
    # Y = 1.0 + (5.0 / 10.0) * 0.5 = 1.25
    # Total = 7.25. (7.25 is NOT > 10)
    assert risk['is_vulnerable'] == False
    assert risk['tier'] == 'LOW'
    assert risk['threat'] == "Grover's Algorithm (Key Space Reduction)"
