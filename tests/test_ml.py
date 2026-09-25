import pytest
from engine.ml.inference import AdvancedCryptoInference

def test_ml_inference_loading():
    engine = AdvancedCryptoInference(model_path='models/transformer_crypto_model.pth')
    assert engine.loaded == True
    
def test_ml_inference_prediction():
    engine = AdvancedCryptoInference(model_path='models/transformer_crypto_model.pth')
    
    # Provide a simple RSA-like snippet
    snippet = "import java.security.KeyPairGenerator; \n KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); kpg.initialize(2048);"
    pred, conf, depth = engine.predict(snippet)
    
    # Assertions
    assert pred in ['RSA', 'AES', 'SHA'] # Based on whatever the dummy dataset trained
    assert isinstance(conf, float)
    assert conf >= 0.0 and conf <= 1.0
    assert depth >= 0.0
