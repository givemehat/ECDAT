import os
import re

def scan_directory(directory_path):
    """
    Recursively scans a directory for python source files and identifies cryptographic primitives.
    (Prototype uses regex/AST-lite for Hackathon demo purposes).
    """
    findings = []
    
    # Patterns for common crypto usage
    crypto_patterns = {
        'RSA': re.compile(r'rsa\.newkeys\(\s*(\d+)\s*\)|RSA\.generate\(\s*(\d+)\s*\)'),
        'ECC': re.compile(r'ec\.generate_private_key\(\s*ec\.(SECP\d+R1)\(\)\s*\)'),
        'AES_GCM': re.compile(r'AESGCM\(|algorithms\.AES\('),
        'SHA256': re.compile(r'hashes\.SHA256\(\)')
    }

    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Check RSA
                        for match in crypto_patterns['RSA'].finditer(content):
                            key_size = match.group(1) or match.group(2)
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'primitive': 'public-key-encryption',
                                'name': 'RSA',
                                'key_length': int(key_size) if key_size else None
                            })
                            
                        # Check ECC
                        for match in crypto_patterns['ECC'].finditer(content):
                            curve = match.group(1)
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'primitive': 'public-key-encryption',
                                'name': 'ECC',
                                'curve': curve
                            })
                            
                        # Check AES
                        if crypto_patterns['AES_GCM'].search(content):
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'primitive': 'symmetric-encryption',
                                'name': 'AES',
                                'mode': 'GCM'
                            })
                            
                        # Check SHA256
                        if crypto_patterns['SHA256'].search(content):
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'primitive': 'hash',
                                'name': 'SHA-256'
                            })
                            
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    
    return findings
