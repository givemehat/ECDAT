import torch
import torch.nn as nn
import math

class PositionalEncoding(nn.Module):
    def __init__(self, d_model, dropout=0.1, max_len=5000):
        super(PositionalEncoding, self).__init__()
        self.dropout = nn.Dropout(p=dropout)

        position = torch.arange(max_len).unsqueeze(1)
        div_term = torch.exp(torch.arange(0, d_model, 2) * (-math.log(10000.0) / d_model))
        pe = torch.zeros(max_len, 1, d_model)
        pe[:, 0, 0::2] = torch.sin(position * div_term)
        pe[:, 0, 1::2] = torch.cos(position * div_term)
        self.register_buffer('pe', pe)

    def forward(self, x):
        # x shape: (seq_len, batch_size, embedding_dim)
        x = x + self.pe[:x.size(0)]
        return self.dropout(x)

class TransformerCryptoDetector(nn.Module):
    def __init__(self, vocab_size, num_classes, embed_dim=128, nhead=8, num_layers=3, static_dim=12):
        super(TransformerCryptoDetector, self).__init__()
        
        self.embed_dim = embed_dim
        # Branch 1: Semantic Transformer
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.pos_encoder = PositionalEncoding(embed_dim)
        
        encoder_layers = nn.TransformerEncoderLayer(d_model=embed_dim, nhead=nhead, dim_feedforward=256, dropout=0.2, batch_first=True)
        self.transformer_encoder = nn.TransformerEncoder(encoder_layers, num_layers=num_layers)
        
        # Branch 2: Structural (AST / Static Features)
        self.static_fc = nn.Sequential(
            nn.Linear(static_dim, 64),
            nn.ReLU(),
            nn.LayerNorm(64),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU()
        )
        
        # Attention-based Fusion
        # Query from static features, Key/Value from semantic features
        self.fusion_attention = nn.MultiheadAttention(embed_dim=embed_dim, num_heads=4, batch_first=True)
        self.static_proj = nn.Linear(32, embed_dim) # Project static up to embed_dim for attention query
        
        # Final Classification Head
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim * 2, 128),
            nn.GELU(),
            nn.Dropout(0.4),
            nn.Linear(128, 64),
            nn.GELU(),
            nn.Linear(64, num_classes)
        )
        
    def forward(self, seq, static_feats):
        # --- Modality 1: Transformer on Semantic Tokens ---
        # seq shape: (batch_size, seq_len)
        embedded = self.embedding(seq) * math.sqrt(self.embed_dim) # (batch, seq_len, embed_dim)
        embedded = embedded.transpose(0, 1) # (seq_len, batch, embed_dim) for pos_encoder
        embedded = self.pos_encoder(embedded)
        embedded = embedded.transpose(0, 1) # (batch, seq_len, embed_dim) for batch_first=True
        
        # padding mask for transformer (True where padding is 0)
        padding_mask = (seq == 0)
        
        transformer_out = self.transformer_encoder(embedded, src_key_padding_mask=padding_mask)
        # Average pooling over sequence length, ignoring padding
        mask = (~padding_mask).unsqueeze(-1).float()
        semantic_features = (transformer_out * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        # semantic_features shape: (batch_size, embed_dim)
        
        # --- Modality 2: FFNN on AST Structural Features ---
        struct_features = self.static_fc(static_feats) # (batch_size, 32)
        struct_query = self.static_proj(struct_features).unsqueeze(1) # (batch_size, 1, embed_dim)
        
        # --- Multi-Modal Attention Fusion ---
        # Let the structural features attend to the semantic sequence
        attn_out, _ = self.fusion_attention(query=struct_query, key=transformer_out, value=transformer_out, key_padding_mask=padding_mask)
        attn_out = attn_out.squeeze(1) # (batch_size, embed_dim)
        
        # Concatenate average pooled semantic features with attention-fused features
        fused = torch.cat((semantic_features, attn_out), dim=1) # (batch_size, embed_dim * 2)
        
        # --- Classification ---
        logits = self.classifier(fused)
        return logits
