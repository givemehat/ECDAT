import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, random_split
from multimodal_dataset import CryptoMultiModalDataset
from model import MultiModalCryptoDetector
import os

def train_multimodal_model():
    print("Loading Multi-Modal Dataset...")
    dataset_path = 'data/real_crypto_snippets.csv'
    dataset = CryptoMultiModalDataset(dataset_path)
    
    # Check if dataset has enough samples
    if len(dataset) < 10:
        print("Not enough data in dataset.")
        return
        
    print(f"Dataset Size: {len(dataset)} snippets.")
    print(f"Vocabulary Size: {dataset.vocab_size}")
    print(f"Classes: {dataset.labels}")
    
    # Train/Test Split (80/20)
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_dataset, test_dataset = random_split(dataset, [train_size, test_size])
    
    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=8, shuffle=False)
    
    # Initialize Model
    model = MultiModalCryptoDetector(
        vocab_size=dataset.vocab_size,
        num_classes=len(dataset.labels)
    )
    
    # Setup Device (MPS for Mac, else CPU)
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"Training on device: {device}")
    model.to(device)
    
    # Loss and Optimizer
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    
    epochs = 10
    print("Starting Multi-Modal Training...")
    
    for epoch in range(epochs):
        model.train()
        running_loss = 0.0
        
        for seq, stat, labels in train_loader:
            seq, stat, labels = seq.to(device), stat.to(device), labels.to(device)
            
            # Forward pass
            outputs = model(seq, stat)
            loss = criterion(outputs, labels)
            
            # Backward and optimize
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            
            running_loss += loss.item()
            
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {running_loss/len(train_loader):.4f}")
        
    # Evaluation
    model.eval()
    correct = 0
    total = 0
    with torch.no_grad():
        for seq, stat, labels in test_loader:
            seq, stat, labels = seq.to(device), stat.to(device), labels.to(device)
            outputs = model(seq, stat)
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            
    accuracy = 100 * correct / total
    print(f"\nMulti-Modal Model Evaluation Accuracy on Test Set: {accuracy:.2f}%")
    
    # Save Model Weights
    os.makedirs('models', exist_ok=True)
    model_path = 'models/multimodal_crypto_model.pth'
    torch.save({
        'model_state_dict': model.state_dict(),
        'vocab': dataset.vocab,
        'labels': dataset.labels
    }, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    # Ensure working directory is correct
    if not os.path.exists('data/real_crypto_snippets.csv'):
        # Fallback if run from ml/ folder
        os.chdir('../../')
    train_multimodal_model()
