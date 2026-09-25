import torch
import torch.nn as nn

class MultiModalCryptoDetector(nn.Module):
    def __init__(self, vocab_size, num_classes, embed_dim=64, hidden_dim=128, static_dim=8):
        super(MultiModalCryptoDetector, self).__init__()
        
        # Branch 1: Semantic (Sequence of Tokens)
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, batch_first=True, bidirectional=True)
        
        # Branch 2: Structural (Static Features)
        self.static_fc = nn.Sequential(
            nn.Linear(static_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU()
        )
        
        # Fusion Layer
        # LSTM output is hidden_dim * 2 (because bidirectional) = 256
        # Static FC output is 16
        # Total concatenated dimension = 256 + 16 = 272
        
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim * 2 + 16, 64),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(64, num_classes)
        )
        
    def forward(self, seq, static_feats):
        # Process Modality 1 (Semantic)
        embedded = self.embedding(seq) # (batch, seq_len, embed_dim)
        lstm_out, (h_n, c_n) = self.lstm(embedded)
        # Take the output of the last time step from both directions
        # h_n shape: (num_layers * num_directions, batch, hidden_size)
        semantic_features = torch.cat((h_n[-2,:,:], h_n[-1,:,:]), dim=1) # (batch, hidden_dim * 2)
        
        # Process Modality 2 (Structural)
        struct_features = self.static_fc(static_feats) # (batch, 16)
        
        # Multi-Modal Fusion
        fused = torch.cat((semantic_features, struct_features), dim=1) # (batch, 272)
        
        # Classification
        logits = self.classifier(fused)
        return logits
