import pytest
from unittest.mock import patch, MagicMock
import torch
from engine.ml.inference import AdvancedCryptoInference

@pytest.fixture
def mocked_engine():
    # Mock the loading process so we don't need real weights
    with patch('torch.load') as mock_load, patch('engine.ml.inference.TransformerCryptoDetector') as mock_model_class:
        mock_load.return_value = {
            'vocab': {'a': 1, 'b': 2, '<UNK>': 3},
            'labels': ['AES', 'RSA', 'SHA'],
            'model_state_dict': {}
        }
        mock_model_instance = MagicMock()
        # Mock forward pass to return some logits
        mock_model_instance.return_value = torch.tensor([[2.0, 0.5, 0.1]]) 
        mock_model_class.return_value = mock_model_instance
        
        engine = AdvancedCryptoInference(model_path='dummy_path.pth')
        return engine

def test_ml_inference_loading_mocked(mocked_engine):
    assert mocked_engine.loaded == True

def test_ml_inference_adversarial_empty(mocked_engine):
    pred, conf, depth = mocked_engine.predict("")
    assert pred in ['AES', 'RSA', 'SHA']
    assert 0.0 <= conf <= 1.0
    assert depth == 0.0

def test_ml_inference_adversarial_huge(mocked_engine):
    huge_string = "A" * 50000
    pred, conf, depth = mocked_engine.predict(huge_string)
    assert pred in ['AES', 'RSA', 'SHA']
    assert 0.0 <= conf <= 1.0
    assert depth >= 0.0

def test_ml_inference_adversarial_garbage(mocked_engine):
    garbage = "@#(*$&(@*#$&"
    pred, conf, depth = mocked_engine.predict(garbage)
    assert pred in ['AES', 'RSA', 'SHA']
    assert 0.0 <= conf <= 1.0

def test_ml_inference_adversarial_binary(mocked_engine):
    binary_str = b'\xff\x00\xff'.decode('utf-8', errors='ignore')
    pred, conf, depth = mocked_engine.predict(binary_str)
    assert pred in ['AES', 'RSA', 'SHA']
    assert 0.0 <= conf <= 1.0

@pytest.mark.slow
def test_ml_inference_real_model():
    engine = AdvancedCryptoInference(model_path='models/transformer_crypto_model.pth')
    if not engine.loaded:
        pytest.skip("Real model not available")
    
    snippet = "import java.security.KeyPairGenerator; \n KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\");"
    pred, conf, depth = engine.predict(snippet)
    
    assert pred in ['AES', 'RSA', 'SHA']
    assert 0.0 <= conf <= 1.0
    assert depth >= 0.0
