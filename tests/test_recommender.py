import pytest
from engine.recommender import get_pqc_recommendation

def test_recommend_rsa_kem():
    finding = {'name': 'RSA', 'primitive': 'public-key-encryption'}
    rec = get_pqc_recommendation(finding)
    assert 'ML-KEM' in rec['algorithm']
    assert 'Hybrid' in rec['action']

def test_recommend_rsa_signature():
    finding = {'name': 'RSA', 'primitive': 'digital-signature'}
    rec = get_pqc_recommendation(finding)
    assert 'ML-DSA' in rec['algorithm']
    assert 'Digital Signatures' in rec['action']

def test_recommend_ecc():
    finding = {'name': 'ECC'}
    rec = get_pqc_recommendation(finding)
    assert 'ML-DSA' in rec['algorithm']
    assert 'larger signature sizes' in rec['justification']

def test_recommend_aes_128():
    finding = {'name': 'AES', 'key_length': 128}
    rec = get_pqc_recommendation(finding)
    assert 'AES-256' in rec['algorithm']
    assert 'Upgrade' in rec['action']

def test_recommend_aes_256():
    finding = {'name': 'AES', 'key_length': 256}
    rec = get_pqc_recommendation(finding)
    assert 'Maintain' in rec['algorithm']
    assert 'No immediate action' in rec['action']

def test_recommend_hash():
    finding = {'name': 'SHA256'}
    rec = get_pqc_recommendation(finding)
    assert 'SHA-384' in rec['algorithm']

def test_recommend_unknown():
    finding = {'name': 'CustomCipher'}
    rec = get_pqc_recommendation(finding)
    assert 'Manual Review' in rec['algorithm']
