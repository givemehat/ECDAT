import torch
from torch.utils.data import Dataset
import pandas as pd
import numpy as np

class CryptoMultiModalDataset(Dataset):
    def __init__(self, csv_file, vocab=None, max_seq_len=100):
        self.df = pd.read_csv(csv_file).dropna()
        
        # Filter rare classes (same logic as before to be safe)
        class_counts = self.df['label'].value_counts()
        valid_classes = class_counts[class_counts >= 3].index
        self.df = self.df[self.df['label'].isin(valid_classes)]
        self.df.reset_index(drop=True, inplace=True)
        
        self.max_seq_len = max_seq_len
        self.labels = self.df['label'].unique().tolist()
        self.label_to_idx = {l: i for i, l in enumerate(self.labels)}
        
        # Build simple character vocabulary if not provided
        if vocab is None:
            chars = set()
            for code in self.df['code']:
                chars.update(list(code))
            self.vocab = {c: i+1 for i, c in enumerate(sorted(chars))} # 0 is padding
            self.vocab['<UNK>'] = len(self.vocab) + 1
        else:
            self.vocab = vocab
            
        self.vocab_size = len(self.vocab) + 1
        
    def __len__(self):
        return len(self.df)
        
    def _extract_static_features(self, code):
        """
        Modality 2: Structural / Static handcrafted features
        Simulates static analysis of AST by searching for known structural patterns.
        """
        features = [
            1.0 if 'import ' in code else 0.0,
            1.0 if 'new ' in code else 0.0,
            1.0 if 'getInstance' in code else 0.0,
            1.0 if 'generate' in code else 0.0,
            1.0 if 'SecretKey' in code else 0.0,
            code.count('(') / 10.0,
            code.count('"') / 10.0,
            len(code) / 500.0
        ]
        return torch.tensor(features, dtype=torch.float)
        
    def _tokenize(self, code):
        """
        Modality 1: Semantic sequence of the code
        """
        tokens = [self.vocab.get(c, self.vocab['<UNK>']) for c in list(code)]
        if len(tokens) > self.max_seq_len:
            tokens = tokens[:self.max_seq_len]
        else:
            tokens += [0] * (self.max_seq_len - len(tokens)) # Padding
        return torch.tensor(tokens, dtype=torch.long)
        
    def __getitem__(self, idx):
        code = str(self.df.iloc[idx]['code'])
        label_str = self.df.iloc[idx]['label']
        
        seq_features = self._tokenize(code)
        static_features = self._extract_static_features(code)
        label = torch.tensor(self.label_to_idx[label_str], dtype=torch.long)
        
        return seq_features, static_features, label
