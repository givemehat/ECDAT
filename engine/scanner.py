import os
import re
import subprocess

def scan_directory(directory_path):
    """
    Recursively scans a directory for source files and binaries to identify cryptographic primitives.
    Expanded for SIH Demo: Supports Python, Java, C/C++, and basic binary scanning (via strings).
    """
    findings = []
    
    # Patterns for common crypto usage across languages
    crypto_patterns = {
        'RSA': re.compile(r'rsa\.newkeys\(\s*(\d+)\s*\)|RSA\.generate\(\s*(\d+)\s*\)|KeyPairGenerator\.getInstance\("RSA"\)|EVP_PKEY_RSA'),
        'ECC': re.compile(r'ec\.generate_private_key\(\s*ec\.(SECP\d+R1)\(\)\s*\)|KeyPairGenerator\.getInstance\("EC"\)|EVP_PKEY_EC'),
        'AES_GCM': re.compile(r'AESGCM\(|algorithms\.AES\(|Cipher\.getInstance\("AES/GCM|EVP_aes_\d+_gcm'),
        'SHA256': re.compile(r'hashes\.SHA256\(\)|MessageDigest\.getInstance\("SHA-256"\)|EVP_sha256')
    }

    for root, _, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            
            # 1. SOURCE CODE SCANNING
            if file.endswith(('.py', '.java', '.c', '.cpp', '.h')):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Check RSA
                        for match in crypto_patterns['RSA'].finditer(content):
                            key_size = match.group(1) or match.group(2) if len(match.groups()) >= 2 else None
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'primitive': 'public-key-encryption',
                                'name': 'RSA',
                                'key_length': int(key_size) if key_size else None
                            })
                            
                        # Check ECC
                        for match in crypto_patterns['ECC'].finditer(content):
                            curve = match.group(1) if len(match.groups()) >= 1 else None
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
                    pass
                    
            # 2. COMPILED BINARY SCANNING (Mock implementation via 'strings')
            elif file.endswith(('.so', '.dll', '.bin', '.elf')):
                try:
                    # Run strings command to extract readable text from binary
                    result = subprocess.run(['strings', file_path], capture_output=True, text=True)
                    if result.returncode == 0:
                        content = result.stdout
                        if 'libcrypto' in content or 'OpenSSL' in content:
                            findings.append({
                                'file': file_path,
                                'type': 'library',
                                'name': 'OpenSSL/libcrypto',
                                'primitive': 'cryptographic-library'
                            })
                        if 'AES' in content:
                            findings.append({
                                'file': file_path,
                                'type': 'algorithm',
                                'name': 'AES (Binary Artefact)',
                                'primitive': 'symmetric-encryption'
                            })
                except Exception as e:
                    pass
                    
    # Deduplicate findings (simplistic deduplication for demo)
    unique_findings = []
    seen = set()
    for f in findings:
        f_tuple = (f['file'], f['name'])
        if f_tuple not in seen:
            seen.add(f_tuple)
            unique_findings.append(f)
            
    return unique_findings
