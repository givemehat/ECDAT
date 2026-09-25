import pytest
from engine.mosca import calculate_risk

def test_mosca_critical_rsa():
    finding = {'name': 'RSA', 'dl_confidence': 0.95, 'ast_depth': 20.0}
    risk = calculate_risk(finding, z_collapse_time=8)
    assert risk['tier'] == 'CRITICAL'
    assert risk['is_vulnerable'] == True

def test_mosca_low_aes():
    finding = {'name': 'AES_GCM', 'dl_confidence': 0.60, 'ast_depth': 5.0}
    risk = calculate_risk(finding, z_collapse_time=10)
    assert risk['is_vulnerable'] == False
    assert risk['tier'] == 'LOW'

def test_mosca_boundary_exact():
    # If X+Y == Z, the strict ">" means not vulnerable. Let's verify.
    finding = {'name': 'RSA'}
    risk = calculate_risk(finding, user_x=4.0, user_y=4.0, z_collapse_time=8.0)
    assert risk['x_y'] == 8.0
    assert risk['is_vulnerable'] == False
    assert risk['tier'] == 'HIGH' # Not CRITICAL because not strictly > Z

def test_mosca_boundary_slightly_less():
    finding = {'name': 'RSA'}
    risk = calculate_risk(finding, user_x=4.0, user_y=3.9, z_collapse_time=8.0)
    assert risk['is_vulnerable'] == False
    assert risk['tier'] == 'HIGH'

def test_mosca_invalid_inputs():
    finding = {'name': 'RSA'}
    with pytest.raises(ValueError, match="negative"):
        calculate_risk(finding, user_x=-1.0, user_y=5.0)
    with pytest.raises(ValueError, match="negative"):
        calculate_risk(finding, user_x=5.0, user_y=-2.0)

def test_mosca_large_values_overflow():
    finding = {'name': 'ECC', 'dl_confidence': 0.95}
    # Test sane handling of huge numbers
    risk = calculate_risk(finding, user_x=1e6, user_y=1e6, z_collapse_time=8)
    assert risk['is_vulnerable'] == True
    assert risk['tier'] == 'CRITICAL'
    assert risk['x_y'] == 2e6

def test_mosca_borderline_confidence():
    # Confidence exactly at 0.51 (which is just above a median)
    # Threshold for CRITICAL is vulnerable + confidence > 0.8.
    finding = {'name': 'RSA', 'dl_confidence': 0.79, 'ast_depth': 100.0} # huge depth = huge Y
    risk = calculate_risk(finding, z_collapse_time=8)
    assert risk['is_vulnerable'] == True
    # It is vulnerable, but confidence is 0.79 (<= 0.8), so it should fall back to HIGH
    assert risk['tier'] == 'HIGH'
    
def test_mosca_unknown_threat():
    finding = {'name': 'RandomCustomCipher', 'dl_confidence': 0.99, 'ast_depth': 10.0}
    risk = calculate_risk(finding, z_collapse_time=1)
    assert risk['tier'] == 'LOW'
    assert risk['threat'] == 'Unknown/Low'
