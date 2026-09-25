import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

def train_and_save_model():
    print("Loading dataset...")
    df = pd.read_csv('data/crypto_snippets.csv')
    df = df.dropna()
    
    X = df['code']
    y = df['label']
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Create a simple NLP pipeline: TF-IDF -> Random Forest
    print("Training ML Pipeline (TF-IDF + Random Forest)...")
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 3), analyzer='char_wb')), # Character n-grams work well for code
        ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
    ])
    
    # Train
    pipeline.fit(X_train, y_train)
    
    # Test
    print("Testing Model...")
    predictions = pipeline.predict(X_test)
    print("\nClassification Report:\n")
    print(classification_report(y_test, predictions))
    
    # Save the model
    os.makedirs('models', exist_ok=True)
    model_path = 'models/crypto_classifier.joblib'
    joblib.dump(pipeline, model_path)
    print(f"Model saved successfully to {model_path}!")

if __name__ == "__main__":
    train_and_save_model()
