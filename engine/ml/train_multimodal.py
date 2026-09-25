import torch
import torch.nn as nn
import torch.optim as optim
from torch.optim.lr_scheduler import CosineAnnealingLR
from torch.utils.data import DataLoader, random_split
from multimodal_dataset import CryptoMultiModalDataset
from model import TransformerCryptoDetector
import os

def train_transformer_model():
    print("Loading Advanced Multi-Modal Dataset with AST Parsing...")
    dataset_path = 'data/real_crypto_snippets.csv'
    dataset = CryptoMultiModalDataset(dataset_path)
    
    if len(dataset) < 10:
        print("Not enough data in dataset.")
        return
        
    print(f"Dataset Size: {len(dataset)} snippets.")
    print(f"Vocabulary Size: {dataset.vocab_size}")
    print(f"Classes: {dataset.labels}")
    
    train_size = int(0.8 * len(dataset))
    test_size = len(dataset) - train_size
    train_dataset, test_dataset = random_split(dataset, [train_size, test_size])
    
    train_loader = DataLoader(train_dataset, batch_size=8, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=8, shuffle=False)
    
    # Initialize the new Transformer Model
    model = TransformerCryptoDetector(
        vocab_size=dataset.vocab_size,
        num_classes=len(dataset.labels),
        embed_dim=128,
        nhead=8,
        num_layers=3,
        static_dim=12 # 8 baseline + 4 AST features
    )
    
    device = torch.device("mps" if torch.backends.mps.is_available() else "cpu")
    print(f"Training on device: {device}")
    model.to(device)
    
    # Loss, Optimizer, and LR Scheduler
    criterion = nn.CrossEntropyLoss()
    optimizer = optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-4)
    epochs = 15
    scheduler = CosineAnnealingLR(optimizer, T_max=epochs)
    
    print("Starting Advanced Transformer Training...")
    
    for epoch in range(epochs):
        model.train()
        running_loss = 0.0
        
        for seq, stat, labels in train_loader:
            seq, stat, labels = seq.to(device), stat.to(device), labels.to(device)
            
            outputs = model(seq, stat)
            loss = criterion(outputs, labels)
            
            optimizer.zero_grad()
            loss.backward()
            
            # Gradient clipping to prevent exploding gradients in Transformers
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            
            optimizer.step()
            running_loss += loss.item()
            
        scheduler.step()
        print(f"Epoch [{epoch+1}/{epochs}], Loss: {running_loss/len(train_loader):.4f}, LR: {scheduler.get_last_lr()[0]:.6f}")
        
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
    print(f"\nAdvanced Transformer Evaluation Accuracy on Test Set: {accuracy:.2f}%")
    
    os.makedirs('models', exist_ok=True)
    model_path = 'models/transformer_crypto_model.pth'
    torch.save({
        'model_state_dict': model.state_dict(),
        'vocab': dataset.vocab,
        'labels': dataset.labels
    }, model_path)
    print(f"Model saved to {model_path}")

if __name__ == "__main__":
    if not os.path.exists('data/real_crypto_snippets.csv'):
        os.chdir('../../')
    train_transformer_model()
