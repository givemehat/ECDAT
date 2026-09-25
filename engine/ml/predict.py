import joblib
import os

def load_ml_model(model_path='models/crypto_classifier.joblib'):
    """
    Loads the trained NLP model for cryptographic pattern detection.
    """
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

def predict_snippet(model, code_snippet):
    """
    Predicts the cryptographic family of a given code snippet using the ML model.
    """
    if model:
        prediction = model.predict([code_snippet])[0]
        return prediction
    return "Model not found"

if __name__ == "__main__":
    print("Testing ML Inference...")
    model = load_ml_model('../../models/crypto_classifier.joblib')
    
    test_snippets = [
        "key = rsa.generate_private_key(65537, 2048)",
        "cipher = AESGCM(key)",
        "print('Hello World!')",
        "hashlib.sha256(b'hello').hexdigest()"
    ]
    
    for snippet in test_snippets:
        pred = predict_snippet(model, snippet)
        print(f"Snippet: {snippet} \n-> Prediction: {pred}\n")
