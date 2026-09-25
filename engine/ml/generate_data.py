import pandas as pd

# Creating a synthetic dataset of code snippets to train the ML Model.
# We want the model to classify snippets into: 'RSA', 'AES', 'ECC', 'SHA', 'None'

data = [
    # RSA Snippets
    {"code": "key = rsa.newkeys(2048)", "label": "RSA"},
    {"code": "RSA.generate(2048)", "label": "RSA"},
    {"code": "KeyPairGenerator kpg = KeyPairGenerator.getInstance(\"RSA\"); kpg.initialize(2048);", "label": "RSA"},
    {"code": "EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);", "label": "RSA"},
    {"code": "from cryptography.hazmat.primitives.asymmetric import rsa; private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)", "label": "RSA"},
    
    # AES Snippets
    {"code": "cipher = AESGCM(key)", "label": "AES"},
    {"code": "Cipher c = Cipher.getInstance(\"AES/GCM/NoPadding\");", "label": "AES"},
    {"code": "EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);", "label": "AES"},
    {"code": "algorithm = algorithms.AES(key)", "label": "AES"},
    {"code": "crypto.createCipheriv('aes-256-gcm', key, iv);", "label": "AES"},

    # ECC Snippets
    {"code": "ec.generate_private_key(ec.SECP256R1())", "label": "ECC"},
    {"code": "KeyPairGenerator.getInstance(\"EC\");", "label": "ECC"},
    {"code": "EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);", "label": "ECC"},
    {"code": "crypto.createECDH('secp256k1');", "label": "ECC"},
    {"code": "ECGenParameterSpec ecSpec = new ECGenParameterSpec(\"secp256r1\");", "label": "ECC"},

    # SHA Snippets
    {"code": "digest = hashes.Hash(hashes.SHA256())", "label": "SHA"},
    {"code": "MessageDigest.getInstance(\"SHA-256\");", "label": "SHA"},
    {"code": "EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);", "label": "SHA"},
    {"code": "crypto.createHash('sha256').update(data).digest('hex');", "label": "SHA"},
    {"code": "hashlib.sha256(b\"hello\").hexdigest()", "label": "SHA"},

    # Non-Crypto Snippets
    {"code": "print('hello world')", "label": "None"},
    {"code": "for i in range(10): print(i)", "label": "None"},
    {"code": "public static void main(String[] args) {}", "label": "None"},
    {"code": "SELECT * FROM users WHERE id = 1;", "label": "None"},
    {"code": "def calculate_sum(a, b): return a + b", "label": "None"},
    {"code": "import os; os.listdir('.')", "label": "None"},
    {"code": "fetch('https://api.example.com/data')", "label": "None"}
]

df = pd.DataFrame(data)
# Add some variations to increase dataset size slightly
expanded_data = []
for _ in range(5):
    for row in data:
        expanded_data.append(row)

df = pd.DataFrame(expanded_data)
df.to_csv('data/crypto_snippets.csv', index=False)
print("Synthetic dataset created at data/crypto_snippets.csv")
