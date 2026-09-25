import torch
import javalang
from .model import TransformerCryptoDetector

class AdvancedCryptoInference:
    def __init__(self, model_path='models/transformer_crypto_model.pth'):
        # Forcing CPU for inference to avoid MPS fallback issues with TransformerEncoder
        self.device = torch.device("cpu")
        

            
        try:
            checkpoint = torch.load(model_path, map_location=self.device)
            self.vocab = checkpoint['vocab']
            self.labels = checkpoint['labels']
            
            self.model = TransformerCryptoDetector(
                vocab_size=len(self.vocab) + 1,
                num_classes=len(self.labels),
                embed_dim=128,
                nhead=8,
                num_layers=3,
                static_dim=12
            )
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()
            self.loaded = True
        except Exception as e:
            print(f"Warning: Could not load Deep Learning model: {e}")
            self.loaded = False

    def extract_features(self, code, max_seq_len=200):
        if not isinstance(code, str) or not code.strip():
            # Return dummy zero tensors for empty/invalid inputs
            return torch.zeros((1, max_seq_len), dtype=torch.long).to(self.device), torch.zeros((1, 12), dtype=torch.float).to(self.device), 0.0
            
        # Semantic Tokens
        tokens = [self.vocab.get(c, self.vocab.get('<UNK>', 0)) for c in list(code)]
        if len(tokens) > max_seq_len:
            tokens = tokens[:max_seq_len]
        else:
            tokens += [0] * (max_seq_len - len(tokens))
        seq_tensor = torch.tensor([tokens], dtype=torch.long).to(self.device)
        
        # AST Structural Features
        features = [
            1.0 if 'import ' in code else 0.0,
            1.0 if 'new ' in code else 0.0,
            1.0 if 'getInstance' in code else 0.0,
            1.0 if 'generate' in code else 0.0,
            1.0 if 'SecretKey' in code else 0.0,
            code.count('(') / 10.0,
            code.count('"') / 10.0,
            len(code) / 500.0,
            0.0, 0.0, 0.0, 0.0
        ]
        
        try:
            java_code = f"class Wrapper {{ void method() {{ {code} }} }}" if "class " not in code else code
            tree = javalang.parse.parse(java_code)
            
            methods_count = len(list(tree.filter(javalang.tree.MethodDeclaration)))
            local_vars_count = len(list(tree.filter(javalang.tree.LocalVariableDeclaration)))
            try_catches_count = len(list(tree.filter(javalang.tree.TryStatement)))
            
            depths = [len(path) for path, node in tree]
            max_depth = max(depths) if depths else 0
            
            features[8] = max_depth / 20.0
            features[9] = methods_count / 5.0
            features[10] = local_vars_count / 10.0
            features[11] = try_catches_count / 5.0
        except Exception:
            pass
            
        stat_tensor = torch.tensor([features], dtype=torch.float).to(self.device)
        return seq_tensor, stat_tensor, features[8] # return max_depth for risk calc

    def predict(self, code_snippet):
        if not self.loaded:
            return None, 0.0, 0.0
            
        seq, stat, ast_depth = self.extract_features(code_snippet)
        
        with torch.no_grad():
            outputs = self.model(seq, stat)
            probabilities = torch.softmax(outputs, dim=1)
            confidence, predicted = torch.max(probabilities, 1)
            
        predicted_label = self.labels[predicted.item()]
        return predicted_label, confidence.item(), ast_depth * 20.0 # scale depth back up
