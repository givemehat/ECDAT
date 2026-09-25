import os
import re
import subprocess
from engine.ml.inference import AdvancedCryptoInference

class ECDATScanner:
    def __init__(self):
        print("Initializing Deep Learning Engine...")
        self.ml_engine = AdvancedCryptoInference()

    def scan_directory(self, directory_path):
        """
        Recursively scans a directory for source files and binaries.
        Uses Hybrid Analysis: RegEx patterns + Multi-Modal Transformer Neural Network.
        """
        findings = []
        
        crypto_patterns = {
            'RSA': re.compile(r'rsa\.newkeys\(\s*(\d+)\s*\)|RSA\.generate\(\s*(\d+)\s*\)|KeyPairGenerator\.getInstance\("RSA"\)|EVP_PKEY_RSA'),
            'ECC': re.compile(r'ec\.generate_private_key\(\s*ec\.(SECP\d+R1)\(\)\s*\)|KeyPairGenerator\.getInstance\("EC"\)|EVP_PKEY_EC'),
            'AES_GCM': re.compile(r'AESGCM\(|algorithms\.AES\(|Cipher\.getInstance\("AES/GCM|EVP_aes_\d+_gcm'),
            'SHA256': re.compile(r'hashes\.SHA256\(\)|MessageDigest\.getInstance\("SHA-256"\)|EVP_sha256')
        }

        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # 1. HYBRID SOURCE CODE SCANNING (RegEx + Deep Learning)
                if file.endswith(('.py', '.java', '.c', '.cpp', '.h')):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # Neural Network Inference (Semantic + AST)
                            dl_pred, dl_conf, ast_depth = self.ml_engine.predict(content)
                            
                            found_by_regex = False
                            
                            # Check RSA
                            for match in crypto_patterns['RSA'].finditer(content):
                                found_by_regex = True
                                key_size = match.group(1) or match.group(2) if len(match.groups()) >= 2 else None
                                findings.append({
                                    'file': file_path,
                                    'type': 'algorithm',
                                    'primitive': 'public-key-encryption',
                                    'name': 'RSA',
                                    'key_length': int(key_size) if key_size else None,
                                    'dl_confidence': dl_conf if dl_pred == 'RSA' else 0.8,
                                    'ast_depth': ast_depth
                                })
                                
                            # Check AES
                            if crypto_patterns['AES_GCM'].search(content):
                                found_by_regex = True
                                findings.append({
                                    'file': file_path,
                                    'type': 'algorithm',
                                    'primitive': 'symmetric-encryption',
                                    'name': 'AES',
                                    'mode': 'GCM',
                                    'dl_confidence': dl_conf if dl_pred == 'AES' else 0.8,
                                    'ast_depth': ast_depth
                                })
                                
                            # Deep Learning Fallback (If RegEx misses it but Transformer is highly confident)
                            if not found_by_regex and dl_pred and dl_conf > 0.90:
                                findings.append({
                                    'file': file_path,
                                    'type': 'algorithm',
                                    'primitive': 'neural-detected',
                                    'name': dl_pred,
                                    'dl_confidence': dl_conf,
                                    'ast_depth': ast_depth
                                })
                                
                    except Exception as e:
                        pass
                        
                # 2. COMPILED BINARY SCANNING
                elif file.endswith(('.so', '.dll', '.bin', '.elf')):
                    try:
                        result = subprocess.run(['strings', file_path], capture_output=True, text=True)
                        if result.returncode == 0:
                            content = result.stdout
                            if 'libcrypto' in content or 'OpenSSL' in content:
                                findings.append({
                                    'file': file_path,
                                    'type': 'library',
                                    'name': 'OpenSSL/libcrypto',
                                    'primitive': 'cryptographic-library',
                                    'dl_confidence': 1.0,
                                    'ast_depth': 0
                                })
                    except Exception:
                        pass
                        
        # Deduplicate
        unique_findings = []
        seen = set()
        for f in findings:
            f_tuple = (f['file'], f['name'])
            if f_tuple not in seen:
                seen.add(f_tuple)
                unique_findings.append(f)
                
        return unique_findings
