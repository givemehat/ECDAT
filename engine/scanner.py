"""
ECDAT scanning engine.

What changed on 2026-09-25 and why: the previous revision (1) defined regexes for RSA/ECC/
AES-GCM/SHA256 but only ever tested RSA and AES_GCM, so ECC was silently undetectable; (2)
hard-imported torch at module load even though the ML model is only a supplemental signal, so
a fresh clone crashed on `import`; (3) wrapped every file read in `except Exception: pass`, so
an unreadable file was indistinguishable from a clean scan; (4) had no container support at
all, although the brief explicitly requires container images. Each of those is now fixed.
"""
import gzip
import io
import os
import re
import tarfile

from engine.fspolicy import check_root, is_credential_store, resolve_within
from engine.purpose import (PURPOSE_UNRESOLVED, assurance_histogram, proven_use_count,
                            resolve_purpose, unresolved_purpose_count)

SOURCE_EXTENSIONS = (".py", ".java", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".go", ".rs", ".js",
                     ".ts", ".php", ".php5", ".phtml", ".rb", ".rake")
CONFIG_EXTENSIONS = (".cnf", ".conf", ".cfg", ".ini", ".properties", ".yaml", ".yml", ".json", ".xml", ".toml")
BINARY_EXTENSIONS = (".so", ".dll", ".dylib", ".bin", ".elf", ".exe", ".a", ".o", ".jar", ".war")
CONTAINER_EXTENSIONS = (".tar", ".tar.gz", ".tgz")
CONFIG_FILENAMES = ("openssl.cnf", "openssl.conf", "java.security", "nginx.conf", "httpd.conf",
                    "ssh_config", "sshd_config", "web.xml")

# ---------------------------------------------------------------------------------------------
# Detection rules. Data, not code, so the set is auditable and extensible.
#   key_group -> 1-based regex group holding a key size, or None
#   key_map   -> translate a matched group value into a numeric key size
#   uses      -> how the primitive is typically exercised (drives the recommendation branch)
#   evidence  -> 'discovered' (found in code) or 'configured' (found in configuration)
# ---------------------------------------------------------------------------------------------
RULES = [
    dict(id="ECD-SRC-RSA-001", name="RSA", primitive="pke", artefact_class="source",
         uses="at-rest", key_group=1, evidence="discovered",
         regex=r"rsa\.newkeys\(\s*(\d+)|"
               r"rsa\.generate_private_key\([^)]*key_size\s*=\s*(\d+)|"
               r"rsa\.generate_private_key\(\s*[\"']?\d+[\"']?\s*,\s*(\d+)"),
    dict(id="ECD-SRC-RSA-002", name="RSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"RSASSA-PSS|rsa\.PSS\(|PKCS1_v1_5|pkcs1_15|padding\.PSS|SHA\d+withRSA"),
    dict(id="ECD-SRC-RSA-003", name="RSA", primitive="pke", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"KeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']\s*\)|EVP_PKEY_RSA|RSA_generate_key_ex"),
    # ---- Java (javax.crypto) -------------------------------------------------------------------
    # Added 2026-09-27 against MEASURED misses on the CryptoAPI-Bench corpus, where recall was
    # 0.219 (46/210) with FP=0. Under-detection, not over-detection, was the whole problem: six
    # rules fired across 203 files, and every one required the algorithm name to be an inline
    # string literal INSIDE the call.
    #
    # The dominant shape in real Java is the opposite:
    #     String crypto = "DES/ECB/PKCS5Padding";
    #     Cipher.getInstance(crypto);
    # i.e. the algorithm is a CONSTANT assigned earlier. No regex on the call site can see it, so
    # the rules below key on the constant DECLARATION as well as on literal arguments.
    dict(id="ECD-SRC-JAVA-LEGACY-001", name="DES", primitive="block-cipher", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"[\"']DES(?:ede)?(?:/[A-Za-z0-9-]+)*[\"']"
                r"|[\"'](?:Blowfish|RC2|RC4|ARCFOUR|IDEA|SEED|CAST5)[\"']"),
    # Symmetric key GENERATION. There was no rule of any kind for KeyGenerator, and the corpus
    # contains 58 call sites -- 28 of them the bare string "AES". A key-generation call is the
    # clearest statement in Java that a symmetric key exists, so omitting it entirely was the
    # single largest gap in the table.
    dict(id="ECD-SRC-JAVA-KEYGEN-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, key_map={"128": 128, "192": 192, "256": 256},
         evidence="discovered",
         regex=r"KeyGenerator\.getInstance\(\s*[\"']?(?:AES|DES|TripleDES|Blowfish|RC2|"
                r"RC4|ARCFOUR|ChaCha20)[\"']?\s*\)"
                r"|KeyGenerator\.getInstance\(\s*[\"'](\d+)"),
    # `new SecretKeySpec(keyBytes, "AES")` -- a raw symmetric key being wrapped. 17 call sites in
    # the corpus, with no rule at all. This is where an at-rest key actually enters a program.
    dict(id="ECD-SRC-JAVA-SECRETKEY-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"new\s+SecretKeySpec\s*\([^,)]+,\s*[\"']"
                r"(?:AES|DES|TripleDES|DESede|Blowfish|RC2|ARCFOUR|ChaCha20|AESWrap)[\"']\s*\)"),
    # Cipher.getInstance with an INLINE transformation. The pre-existing rule covered only
    # AES/(GCM|CBC|CTR|ECB), so "RSA", "DES" and "Blowfish" all passed unremarked.
    dict(id="ECD-SRC-JAVA-CIPHER-001", name="AES", primitive="ae", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"Cipher\.getInstance\(\s*[\"']"
                r"(?:DES|DESede|TripleDES|Blowfish|RC2|RC4|ARCFOUR|IDEA|Camellia|SEED|"
                r"AESWrap|CAST5|RSA(?:/(?:ECB|PKCS1(?:Padding)?|OAEP(?:With(?:RSAAndSHA1|"
                r"SHA-256)Padding)?))?)(?:/[\w-]+)*[\"']\s*\)"),
    dict(id="ECD-SRC-JAVA-MAC-001", name="HMAC", primitive="mac", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"Mac\.getInstance\(\s*[\"'](?:Hmac(?:SHA(?:1|224|256|384|512)|MD5)|"
                r"HMAC(?:-\w+)?)[\"']\s*\)"),
    # MessageDigest across the whole JCA family. MD2 and MD4 were absent from the table
    # entirely, so the two most broken hashes a JVM will accept produced no finding at all.
    # MessageDigest across the JCA family. MD2 and MD4 were absent from the table entirely, so
    # the two most broken hashes a JVM will accept produced no finding at all.
    #
    # Only MD2 and MD4 are new here. MD5 is already owned by ECD-SRC-MD5-001, and matching it
    # again published the same algorithm twice from two rule_ids -- which the dedup key cannot
    # collapse. SHA-1/256/384/512 belong to ECD-SRC-SHA1-001 / ECD-SRC-SHA2-001.
    dict(id="ECD-SRC-JAVA-DIGEST-001", name="MD5", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"MessageDigest\.getInstance\(\s*[\"'](?:MD2|MD4)[\"']\s*\)"),
    # REMOVED: ECD-SRC-JAVA-DIGEST-002.
    # It matched ANY quoted SHA string, which made `MessageDigest.getInstance("SHA-256")` fire
    # THREE rules at once -- ECD-SRC-JAVA-DIGEST-001, ECD-SRC-JAVA-DIGEST-002 and the
    # pre-existing ECD-SRC-SHA2-001. `_finalise` dedups on (file, name, rule_id, line), so a
    # different rule_id escapes collapsing, and the same line is then reported as multiple
    # findings. An independent audit caught this; the benchmark did not, because it scores
    # distinct LOCATIONS and so cannot see a duplicate.
    #
    # `DIGEST-001` already covers the call site, and `CONST-004` covers the declaration form.
    # A bare quoted hash string outside both is prose, not a call site.
    # Elliptic-curve JCA. `KeyPairGenerator.getInstance("EC")` was already covered, but the curve
    # SPEC was not, and the spec string is where the key size actually lives.
    dict(id="ECD-SRC-JAVA-EC-001", name="ECC", primitive="signature", artefact_class="source",
         uses="signing", key_group=1, evidence="discovered",
         regex=r"ECGenParameterSpec\s*\(\s*[\"'](secp\w+|P-\d+|prime\w+)[\"']"
                r"|[\"'](?:secp256r1|secp256k1|secp384r1|secp521r1|prime256v1)[\"']"),
    dict(id="ECD-SRC-JAVA-DSA-001", name="DSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"KeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']"
                r"|Signature\.getInstance\(\s*[\"']SHA\d+withDSA[\"']"),
    # THE LARGEST MEASURED CATEGORY (53 of 164 Java misses): a JCE transformation assigned to a
    # String constant and then passed by NAME. `Cipher.getInstance(crypto)` carries no algorithm
    # text at all, so the call site is unmatchable and the declaration is the only evidence.
    # Each family gets its own rule because the primitive differs, and a legacy transformation
    # must never be reported under the AES name.
    dict(id="ECD-SRC-JAVA-CONST-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, key_map={"128": 128, "192": 192, "256": 256},
         evidence="discovered",
         regex=r"String\s+\w+\s*=\s*[\"']AES(?:/|[-])(?:GCM|CBC|CTR|ECB|CFB|OFB|CFB128)"
                r"(?:/[\w-]+)*[\"']"
                r"|[\"']AES-(\d+)(?:-(?:GCM|CBC|CTR))?[\"']"),
    # A JCE transformation assigned to a String constant. `Cipher.getInstance(crypto)` carries
    # no algorithm text at all, so the call site is unmatchable and the declaration is the only
    # evidence. RSA and SHA constants are NOT here: they need their own rules because the
    # primitive differs, and a legacy transformation must never be reported under those names.
    dict(id="ECD-SRC-JAVA-CONST-003", name="RSA", primitive="pke", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"String\s+\w+\s*=\s*[\"']RSA(?:/[\w-]+)*[\"']"),
    dict(id="ECD-SRC-JAVA-CONST-004", name="SHA", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"String\s+\w+\s*=\s*[\"'](?:SHA-?1|SHA-?224|SHA-?256|SHA-?384|SHA-?512|MD5|"
                r"MD2|MD4)[\"']"),
    # SecureRandom vs the non-cryptographic generators. `new java.util.Random()` and
    # `Math.random()` are what CryptoAPI-Bench is built to catch, and the tool could not see
    # them at all because no rule named the weak generators.
    dict(id="ECD-SRC-JAVA-WEAKRNG-001", name="PRNG", primitive="other", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"new\s+(?:java\.util\.)?Random\s*\(|Math\.random\s*\(\)"),
    # ---- PHP (ext/openssl, ext-sodium, ext/hash) -------------------------------------------------
    # PHP's crypto surface is almost entirely `openssl_*` and `sodium_crypto_*`. There was no
    # rule for either, and `.php` was not even in SOURCE_EXTENSIONS, so a PHP codebase produced
    # no findings at all. Every regex here requires a FUNCTION CALL, never a bare cipher word --
    # the word "AES" appears in PHP prose and in variable names constantly.
    dict(id="ECD-PHP-AES-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, key_map={"128": 128, "192": 192, "256": 256},
         evidence="discovered",
         regex=r"openssl_(?:encrypt|decrypt)\s*\([^,]+,\s*[\"']"
                r"(?:aes-\d+-(\d+)(?:-(?:gcm|cbc|ctr|cfb|ofb|ecb)|-rfc)\w*|"
                r"aes-\d+-(?:gcm|cbc|ctr|cfb|ofb|ecb))"),
    # The cipher-name-only form, e.g. `openssl_cipher_iv_length('aes-256-cbc')` or a cipher
    # held in a config array. Scoped to a quoted literal or a named call so prose cannot match.
    dict(id="ECD-PHP-AES-002", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, key_map={"128": 128, "192": 192, "256": 256},
         evidence="discovered",
         regex=r"openssl_cipher_iv_length\s*\(\s*[\"']aes-(\d+)"
                r"|openssl_(?:cipher_iv_length|random_pseudo_bytes)\s*\(\s*[\"']aes-\d+"),
    dict(id="ECD-PHP-KEM-001", name="RSA", primitive="pke", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"openssl_(?:public_encrypt|private_decrypt|pkcs7_encrypt|pkcs7_decrypt)\s*\("
                r"|openssl_pkey_new\s*\(|openssl_pkey_get_(?:public|private)\s*\("),
    dict(id="ECD-PHP-SIG-001", name="RSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"openssl_sign\s*\(|openssl_verify\s*\("),
    # sodium_crypto_box / secretbox / aead_* are libsodium bindings and are POST-QUANTUM-READY
    # only in the sense that they are modern; the primitives still need classifying. A dedicated
    # rule per family keeps the primitive honest.
    dict(id="ECD-PHP-SODIUM-001", name="ChaCha20", primitive="stream-cipher", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"sodium_crypto_(?:aead_)?chacha20(?:_ietf)?_(?:encrypt|decrypt)\s*\("),
    dict(id="ECD-PHP-SODIUM-002", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"sodium_crypto_(?:aead_)?aes(?:256gcm|xchacha20poly1305_)?_(?:encrypt|decrypt)\s*\("),
    dict(id="ECD-PHP-SIG-002", name="Ed25519", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"sodium_crypto_sign_(?:open|verify_detached|keypair)\s*\("),
    dict(id="ECD-PHP-HASH-001", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"\bhash\s*\(\s*[\"']sha1[\"']|\bhash_hmac\s*\(\s*[\"']sha1[\"']"
                r"|\bhash\s*\(\s*[\"']md5[\"']|\bhash_hmac\s*\(\s*[\"']md5[\"']"),
    # `rand()` and `mt_rand()` are not cryptographic. Reported as their own primitive so the
    # recommendation is "replace the generator", not "migrate this cipher".
    dict(id="ECD-PHP-WEAKRNG-001", name="PRNG", primitive="other", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"(?<![A-Za-z0-9_$>])(?:mt_rand|uniqid|str_shuffle)\s*\(\s*\)"
                r"|(?<![A-Za-z0-9_$>])rand\s*\(\s*\)"),
    # ---- Ruby (OpenSSL::, Digest::, SecureRandom) -------------------------------------------------
    # Ruby exposes OpenSSL as namespaced classes, and `OpenSSL::Cipher.new('aes-256-gcm')` is
    # the single most common symmetric call in the ecosystem. There was no rule for it and `.rb`
    # was not in SOURCE_EXTENSIONS, so a Rails app produced no findings at all.
    dict(id="ECD-RB-AES-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, key_map={"128": 128, "192": 192, "256": 256},
         evidence="discovered",
         regex=r"OpenSSL::Cipher\.new\s*\(\s*[\"']aes-(\d+)"
                r"|OpenSSL::Cipher::AES\.new\s*\(\s*[\"']?([\w-]*)"),
    dict(id="ECD-RB-AES-002", name="ChaCha20", primitive="stream-cipher", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"OpenSSL::Cipher\.new\s*\(\s*[\"'](?:chacha20|rc4)"),
    # Legacy ciphers, named as themselves so they are never reported under the AES name.
    dict(id="ECD-RB-LEGACY-001", name="DES", primitive="block-cipher", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"OpenSSL::Cipher\.new\s*\(\s*[\"'](?:des|des-cbc|bf-cbc|rc2|rc4|id7|"
                r"cast5|camellia)[\"']"
                r"|OpenSSL::Cipher\.new\s*\(\s*[\"']des-ede3[\"']"),
    dict(id="ECD-RB-RSA-001", name="RSA", primitive="pke", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"OpenSSL::PKey::RSA\.new\s*\(|OpenSSL::PKey\.read\s*\("),
    # Scoped to an explicit `OpenSSL::PKey::` receiver ONLY. An earlier version also allowed a
    # bare `key.sign(`, which matched paramiko's `self.key.sign(` in Python -- an SSH host-key
    # operation, not an RSA signature -- and cost 6 false positives on the Python corpus.
    # The optional `.new` matters: `OpenSSL::PKey::RSA.new.sign_pss(...)` is the idiomatic
    # one-liner, so a pattern without it would miss the most common Ruby shape there is.
    dict(id="ECD-RB-SIG-001", name="RSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"OpenSSL::PKey::\w+(?:\.new)?\.(?:sign|verify)(?:_pss)?\s*\("),
    dict(id="ECD-RB-EC-001", name="ECC", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"OpenSSL::PKey::EC\.new\s*\(|OpenSSL::PKey::EC\.generate\s*\("),
    dict(id="ECD-RB-DH-001", name="DH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"OpenSSL::PKey::DH\.new\s*\(|OpenSSL::PKey::DH\.generate_params\s*\("),
    dict(id="ECD-RB-MAC-001", name="HMAC", primitive="mac", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"OpenSSL::HMAC\.(?:new|digest)\s*\(|OpenSSL::HMAC\.hexdigest\s*\("),
    dict(id="ECD-RB-HASH-001", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"Digest::(MD5|SHA1)\b|"
                r"OpenSSL::Digest::(MD5|SHA1)\b|"
                r"OpenSSL::Digest::Digest\b.*[\"']sha1[\"']"),
    dict(id="ECD-RB-HASH-002", name="SHA", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"Digest::SHA(?:256|384|512)\b|"
                r"OpenSSL::Digest::SHA(?:256|384|512)\b|"
                r"OpenSSL::Digest\.new\s*\(\s*[\"']SHA-?(?:256|384|512)"),
    # `rand` is the Ruby spelling of the same weakness. `SecureRandom` is the correct call and
    # is deliberately NOT matched here -- a rule that fired on the secure generator too would
    # make the finding meaningless.
    dict(id="ECD-RB-WEAKRNG-001", name="PRNG", primitive="other", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"(?<![A-Za-z0-9_.:@$])Kernel\.rand\s*\(|(?<![A-Za-z0-9_.:@$])rand\s*\(\s*\)"),
    # ---- ECC ---------------------------------------------------------------------------------
    # Key AGREEMENT only. `ec.generate_private_key(ec.SECP256R1())` is a generic key-pair
    # generator and was previously matched here as ECDH AND by ECD-SRC-PYCA-EC-001/002 as
    # ECDSA, so one statement produced three findings with two mutually exclusive primitives
    # (key-agreement AND signature) and the recommender offered both ML-KEM and ML-DSA for the
    # same line. A bare key-pair generator does not say which operation follows, so that form is
    # excluded here and the curve object is typed by the PYCA rules instead. Every OTHER
    # spelling below is an unambiguous key-agreement signal and is kept: removing `X25519` and
    # `EVP_PKEY_EC` with it cost real detections, which the differential tests caught.
    dict(id="ECD-SRC-ECDH-001", name="ECDH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=1, evidence="discovered",
         # A plain alternation with no wrapping group. An earlier version wrapped this in `(?:...)`
         # and the group was never closed, which `re` accepted but which made the pattern match
         # almost nothing -- the reachability test caught it immediately.
         #
         # The last alternative is a key-pair GENERATOR with a captured curve, so `key_length`
         # resolves to 256/384/521. It is a genuine key-agreement signal and was briefly removed,
         # which cost measured recall on paramiko; the duplicate it caused is fixed downstream,
         # where a curve with no use context is no longer renamed to ECDSA/signature.
         regex=r"ECDH_compute_key|KeyAgreement\.getInstance\(\s*[\"']ECDH|"
                r"exchanges\.ECDH\b|derive_private_key\(|"
                r"EllipticCurvePublicNumbers\b|ECDHPrivateKey\b|"
                # `X25519` must NOT have a trailing word boundary. The real code is
                # `X25519PrivateKey` / `x25519.X25519PublicKey`, and because `P` is a word
                # character, `\bX25519\b` matches none of it -- the corpus measured 2/22 hits with
                # the boundary and 22/22 without it.
                r"DiffieHellman|X25519|EVP_PKEY_EC\b|"
                # `.exchange(peer_public_key)` is the actual ECDH operation in the
                # `cryptography` library, matched only where the argument name says so -- a bare
                # `.exchange()` is far too common in ordinary Python to key off.
                r"[Ee][Cc][Dd][Hh]\w*\s*\.\s*exchange\(|"
                r"\.exchange\(\s*(?:peer|remote|their|public|dh)[\w_]*\s*\)|"
                r"generate_private_key\(\s*ec\.(SECP\d+R1)\(\)"),
    dict(id="ECD-SRC-ECDSA-001", name="ECDSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"ec\.ECDSA\(|ECDSA_sign|Signature\.getInstance\(\s*[\"'](SHA\d+withECDSA|ECDSA)|"
               r"ecdsa\.SigningKey|SHA\d+withECDSA"),
    dict(id="ECD-SRC-ECC-001", name="ECC", primitive="signature", artefact_class="source",
         uses="signing", key_group=1, evidence="discovered",
         regex=r"KeyPairGenerator\.getInstance\(\s*[\"']EC[\"']\s*\)|EC_KEY_generate_key|"
               r"(secp256r1|prime256v1|secp384r1|secp521r1)"),
    # ---- EdDSA / DSA / DH -------------------------------------------------------------------
    dict(id="ECD-SRC-EDDSA-001", name="Ed25519", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"Ed25519PrivateKey|Ed448PrivateKey|EVP_PKEY_ED25519|\bEd25519\b|\bEd448\b"),
    dict(id="ECD-SRC-DSA-001", name="DSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"EVP_PKEY_DSA|DSA_generate_parameters|dsa\.generate_parameters\(|"
               r"KeyPairGenerator\.getInstance\(\s*[\"']DSA"),
    dict(id="ECD-SRC-DH-001", name="DH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"EVP_PKEY_DH\b|DH_generate|DH_get_|ffdhe\d+|modp_\d+|"
               r"KeyAgreement\.getInstance\(\s*[\"']DH"),
    # ---- Python `cryptography` object references ---------------------------------------------
    # Added against MEASURED misses from benchmark/labels/paramiko_pq.json, not against a guess
    # about what "better recall" means. The library selects an algorithm by REFERENCING an
    # object -- `algorithms.AES`, `hashes.SHA256`, `ec.SECP256R1` -- and none of those spellings
    # matched any existing rule, so 40-odd genuine ECDSA/RSA/AES sites were invisible to us.
    # These are unambiguous: the dotted path is the library's own vocabulary, so matching it
    # cannot fire on an unrelated identifier.
    dict(id="ECD-SRC-PYCA-AES-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"algorithms\.(AES|ARC4|TripleDES|ChaCha20|ChaCha20Poly1305|Camellia|Blowfish|"
                r"CAST5|SEED|IDEA)\b"),
    # `MD5` and `BLAKE2` were listed here, but this rule reports name="SHA" -- so `hashes.MD5(`
    # was published as a SHA finding. The primitive is right and the ALGORITHM NAME is wrong,
    # which is worse than a miss: a consumer reading the CBOM is told an MD5 call is SHA-2.
    # The SHA-1-specific rule below owns MD5, and BLAKE2 has no name of its own in this table.
    dict(id="ECD-SRC-PYCA-HASH-001", name="SHA", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"hashes\.(SHA224|SHA256|SHA384|SHA512|SHA3_\d+_\d+)\b"),
    dict(id="ECD-SRC-PYCA-HASH-002", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"hashes\.SHA1\b|MD5\(\s*(?:usedforsecurity\s*=\s*False)?\s*\)"),
    dict(id="ECD-SRC-PYCA-EC-001", name="ECC", primitive="signature", artefact_class="source",
         uses="signing", key_group=1, evidence="discovered",
         regex=r"ec\.(SECP(?P<sz>192|224|256|384|521)R1|SECP256K1)\b"),
    dict(id="ECD-SRC-PYCA-ECDH-001", name="ECDH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"exchanges\.ECDH\b|derive_private_key\(|"
                r"EllipticCurvePublicNumbers\b|ECDHPrivateKey\b"),
    dict(id="ECD-SRC-PYCA-ED-001", name="Ed25519", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"ed25519\.(Ed25519PrivateKey|Ed25519PublicKey)\b|ed448\.Ed448PrivateKey\b"),
    # ENCRYPTION only. `padding.PSS` is a SIGNATURE padding scheme (it is what RSASSA-PSS uses),
    # and listing it here made one identifier report as both `pke` and `signature` for the same
    # line, so the recommender offered a decrypt target and a signing target for one statement.
    # PSS is matched by ECD-SRC-RSA-002, which is where it belongs.
    dict(id="ECD-SRC-PYCA-RSA-001", name="RSA", primitive="pke", artefact_class="source",
         uses="at-rest", key_group=1, evidence="discovered",
         regex=r"rsa\.(RSAPrivateNumbers|RSAPublicNumbers|RSAPrivateKey|RSAKey)\b|"
                r"padding\.(OAEP|PKCS1v15)\b|asymmetric\.rsa\b"),
    # ---- hashlib direct imports ----------------------------------------------------------------
    # `from hashlib import sha1, md5` names the algorithm as a bound name. `hashlib.sha256(...)`
    # is already covered elsewhere; the import form was not.
    dict(id="ECD-SRC-HASHLIB-001", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"from\s+hashlib\s+import\s+[^\n]*\bsha1\b|"
                r"from\s+hashlib\s+import\s+[^\n]*\bmd5\b.*|hashlib\.new\(\s*[\"']sha1[\"']"),
    # `hash_algo = hashlib.sha256` -- an algorithm object bound to a name. The dotted call
    # `hashlib.sha256(...)` was already covered; the ASSIGNMENT form was not, and it is how
    # libraries store an algorithm choice in a variable.
    dict(id="ECD-SRC-HASHLIB-002", name="SHA", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"hashlib\.(?:sha1|sha224|sha256|sha384|sha512|sha3_\d+_\d+|blake2\w*|md5)\b(?!\s*\()"),
    dict(id="ECD-SRC-HASHLIB-003", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"from\s+hashlib\s+import\s+[^\n]*\bmd5\b|hashlib\.md5\b(?!\s*\()"),
    # OpenSSH GCM/ChaCha cipher names, and HMAC wire names. `hmac-sha2-*` is an authentication
    # tag, not an encryption cipher, so it is a MAC rather than a cipher-suite primitive.
    dict(id="ECD-SRC-SSH-CIPHER-002", name="AES", primitive="ae", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"[\"']aes(?:128|192|256)-(?:gcm|ctr)@openssh\.com[\"']|"
                r"[\"']chacha20-poly1305@openssh\.com[\"']"),
    dict(id="ECD-SRC-SSH-MAC-001", name="HMAC", primitive="mac", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"[\"'](?:hmac-sha2-(?:256|512)|hmac-sha1(?:-96|-160)?|"
                r"umac-64@openssh\.com|umac-128@openssh\.com)[\"']"),
    # `diffie-hellman-group-exchange-sha256` is finite-field DH, NOT ECDH. The KEX rule above
    # deliberately lists only the elliptic names; this is the missing DH half.
    #
    # The alternation is not symmetric, and getting it wrong fails silently. Fixed groups are
    # `group14-sha256` -- digits run straight into "-sha", no separator. But the exchange group
    # is `group-exchange-sha256`, WITH a hyphen. Writing `group(?:1|14|16|18|exchange)` therefore
    # spells "groupexchange-sha256" and never matches the single name the rule was added for.
    dict(id="ECD-SRC-SSH-DH-001", name="DH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"[\"']diffie-hellman-group(?:1|14|16|18|-exchange)-sha(?:1|256|384|512)[\"']"),
    # REMOVED: ECD-SRC-PYCA-EC-002.
    # Its pattern (`ec.EllipticCurvePrivateKey`, `ec.SECP\w*R1`) is a strict SUBSET of
    # ECD-SRC-PYCA-EC-001, so `ec.generate_private_key(ec.SECP256R1())` matched both and the
    # curve was reported twice from two rule_ids. `-001` already captures the size, so the
    # second finding carried no extra information -- only an extra CBOM component.
    # `from cryptography.hazmat.primitives.asymmetric.x25519 import ...` -- the import path
    # itself names the algorithm family.
    dict(id="ECD-SRC-PYCA-X-001", name="X25519", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"primitives\.asymmetric\.x25519\b|x25519\.(?:X25519PrivateKey|X25519PublicKey)\b"),
    # ---- SSH / TLS algorithm identifier strings -----------------------------------------------
    # RFC 4253 / RFC 5656 / OpenSSH wire names. These are exact algorithm identifiers, and an
    # SSH implementation is nothing BUT these strings, so a codebase that names one is using it.
    # The signature/cipher names are kept in separate rules because they imply a different
    # primitive, and conflating them is the error Phase-1 gap H6 warns about.
    dict(id="ECD-SRC-SSH-KEX-001", name="ECDH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         # ELLIPTIC names only. `diffie-hellman-group*` is finite-field DH and belongs to
         # ECD-SRC-SSH-DH-001; listing it here too made one identifier report as BOTH ECDH and
         # DH, which is a wrong algorithm name in the CBOM and an inflated finding count.
         regex=r"[\"'](?:ecdh-sha2-nistp(?:256|384|521)|"
                r"curve25519-sha256(?:@libssh\.org)?|"
                r"ecdh-sha2-nistp256k)[\"']"),
    dict(id="ECD-SRC-SSH-SIG-001", name="ECDSA", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"[\"']ecdsa-sha2-nistp(?:256|384|521)[\"']|[\"']ssh-rsa[\"']|"
                r"[\"']rsa-sha2-(?:256|512)[\"']|[\"']ssh-dss[\"']"),
    dict(id="ECD-SRC-SSH-ED-001", name="Ed25519", primitive="signature", artefact_class="source",
         uses="signing", key_group=None, evidence="discovered",
         regex=r"[\"']ssh-ed25519[\"']"),
    dict(id="ECD-SRC-SSH-CIPHER-001", name="AES", primitive="ae", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"[\"'](?:aes(?:128|192|256)-(?:ctr|gcm|cbc)|3des-cbc|"
                r"aes128-cbc|aes256-cbc)[\"']"),
    dict(id="ECD-SRC-SSH-LEGACY-001", name="3DES", primitive="block-cipher", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"[\"'](?:3des-cbc|des-cbc|arcfour|arcfour256|blowfish-cbc|cast128-cbc)[\"']"),
    # ---- Symmetric --------------------------------------------------------------------------
    dict(id="ECD-SRC-AES-001", name="AES", primitive="ae", artefact_class="source",
         uses="at-rest", key_group=1, evidence="discovered",
         key_map={"128": 128, "192": 192, "256": 256},
         regex=r"AESGCM\(|algorithms\.AES\(|AES\.new\(|Crypto\.Cipher\.AES|"
               r"Cipher\.getInstance\(\s*[\"']AES/(?:GCM|CBC|CTR|ECB)|EVP_aes_(128|192|256)"),
    dict(id="ECD-SRC-CHACHA-001", name="ChaCha20", primitive="ae", artefact_class="source",
         uses="tls", key_group=None, evidence="discovered",
         regex=r"ChaCha20Poly1305|EVP_chacha20"),
    # ---- Hashes -----------------------------------------------------------------------------
    dict(id="ECD-SRC-SHA2-001", name="SHA256", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"hashes\.SHA256\(|MessageDigest\.getInstance\(\s*[\"']SHA-?256|EVP_sha256|sha256\("),
    dict(id="ECD-SRC-SHA1-001", name="SHA1", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"hashes\.SHA1\(|MessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']|EVP_sha1|sha1\("),
    dict(id="ECD-SRC-MD5-001", name="MD5", primitive="hash", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"\bmd5\(|MessageDigest\.getInstance\(\s*[\"']MD5[\"']|EVP_md5|MD5_Init"),
    # ---- Protocol / configuration -----------------------------------------------------------
    dict(id="ECD-CFG-TLS-001", name="TLS", primitive="protocol", artefact_class="config",
         uses="tls", key_group=None, evidence="configured",
         regex=r"ssl_protocols\s+[^;]+;|TLSv1(\.[0-3])?|tls1_[0-3]|MinProtocol\s*=\s*\S+"),
    dict(id="ECD-CFG-LEGACY-001", name="LEGACY-CIPHER", primitive="protocol",
         artefact_class="config", uses="tls", key_group=None, evidence="configured",
         regex=r"\b(3DES|DES-CBC3|RC4|NULL-SHA|EXPORT)\b"),

    # ---- Hardcoded Keys ----
    dict(id="ECD-KEY-PEM-001", name="Private Key (PEM)", primitive="key", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    dict(id="ECD-KEY-PGP-001", name="Private Key (PGP)", primitive="key", artefact_class="source",
         uses="at-rest", key_group=None, evidence="discovered",
         regex=r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
         
    # ---- Protocols ----
    # Apache/mod_ssl ONLY. This rule previously also carried an `ssl_protocols TLSv1.x`
    # alternative, which was 83% redundant with ECD-CFG-TLS-001 (that rule's pattern is
    # `ssl_protocols\s+[^;]+;`, a strict superset) AND missed the most common legacy nginx line
    # in existence, `ssl_protocols TLSv1 TLSv1.1;`, because it required a dotted version.
    # A rule added to catch legacy TLS that is blind to legacy TLS, and that doubles a rule
    # that is not, is worse than no rule. What is uniquely Apache's is the `SSLProtocol`
    # directive, so that is all this keeps -- case-insensitively, because Apache directives are.
    # `type="protocol"` is what routes the finding to cbom's protocol branch.
    dict(id="ECD-PROTO-TLS-001", name="TLS Configuration", primitive="protocol", artefact_class="config",
         type="protocol", uses="tls", key_group=None, evidence="configured",
         regex=r"(?i)SSLProtocol\s+(?:all|[-+]?SSLv[0-9.]*|none)\b"),

    # ---- Cloud Services / Hardware Modules --------------------------------------------------
    # A KMS call is a CAPABILITY, not an algorithm. It names no cipher and no key size, so the
    # scanner cannot say anything quantum-relevant about the keys it protects -- and pretending
    # otherwise is a guess. What it CAN say is that a managed key service is in the estate and
    # must be inventoried, which is exactly the `cryptographic-library` capability the
    # recommender already routes to "inventory as a dependency" and the assurance taxonomy
    # already grades as `capability` rather than `used`.
    #
    # `primitive="cloud-service"` and `primitive="hardware-module"` are not CycloneDX 1.7 enum
    # members, so all four were silently canonicalised to "unknown" and shipped as
    # assetType=algorithm / primitive=unknown / tier=LOW with no migration target.
    dict(id="ECD-CLOUD-KMS-001", name="AWS KMS", primitive="cryptographic-library",
         artefact_class="source", type="library", uses="at-rest", key_group=None,
         evidence="dependency",
         regex=r"boto3\.client\(\s*['\"]kms['\"]\s*\)|aws_kms_key|kms\.Decrypt|kms\.Encrypt"),
    # `SecretClient(` alone is far too generic -- it matches any Azure SDK credential helper.
    # Anchored to the key-vault namespace instead.
    dict(id="ECD-CLOUD-AZURE-001", name="Azure Key Vault", primitive="cryptographic-library",
         artefact_class="source", type="library", uses="at-rest", key_group=None,
         evidence="dependency",
         regex=r"azure\.keyvault|KeyVaultClient|azurervault|key_vault\.client"),
    dict(id="ECD-CLOUD-GCP-001", name="Google Cloud KMS", primitive="cryptographic-library",
         artefact_class="source", type="library", uses="at-rest", key_group=None,
         evidence="dependency",
         regex=r"google-cloud-kms|KeyManagementServiceClient|google\.cloud\.kms"),
    # `PKCS11` with no boundary matches any identifier containing those six characters -- a
    # variable, a vendored filename, a comment. Anchored to what actually appears in code.
    dict(id="ECD-HARDWARE-PKCS11-001", name="PKCS#11 HSM", primitive="cryptographic-library",
         artefact_class="source", type="library", uses="at-rest", key_group=None,
         evidence="dependency",
         regex=r"\bSunPKCS11\b|\bPKCS11\b|pkcs11\.(?:get_token|lib|load)|PyKCS11"),
]

# Binary/firmware evidence: symbol or string fragments identifying a crypto library or algorithm.
BINARY_MARKERS = [
    ("OpenSSL/libcrypto", r"libcrypto|OpenSSL\s+\d|OPENSSL_VERSION|OpenSSL 1\.[01]\.\d|OpenSSL 3\.\d"),
    ("BoringSSL",         r"BoringSSL"),
    ("libsodium",         r"libsodium|sodium_init|crypto_box_curve25519xsalsa20poly1305"),
    ("mbedTLS",           r"m ?bedtls|mbedtls|polarssl"),
    ("wolfSSL",           r"wolfssl|wolfSSL_"),
    ("BCL/BouncyCastle",  r"org\.bouncycastle|BouncyCastle"),
    ("NSS",               r"NSS_\d|libnss3"),
    ("libgcrypt",         r"libgcrypt|gcry_"),
]

_COMPILED_RULES = [(dict(rule), re.compile(rule["regex"])) for rule in RULES]
_COMPILED_MARKERS = [(label, re.compile(pat)) for label, pat in BINARY_MARKERS]


def _extract_key_size(rule, match):
    """Numeric key size for a rule hit, or None. Maps group values to sizes where declared."""
    key_group = rule.get("key_group")
    if not key_group:
        return None
    try:
        raw = None
        for i in range(key_group, len(match.groups()) + 1):
            g = match.group(i)
            if g:
                raw = g
                break
        if raw is None:
            return None
        key_map = rule.get("key_map")
        if key_map is not None:
            return key_map.get(str(raw))
        return int(raw)
    except (ValueError, IndexError):
        return None


def _refine_uses(rule, snippet_context):
    """Promote the rule's default `uses` when nearby tokens say otherwise.

    e.g. an RSA sign() call near "TLS"/"handshake" is still a signature; but an ECDSA call
    inside a file whose neighbours negotiate TLS keeps `uses=tls` untouched.
    """
    ctx = snippet_context.lower()
    if "handshake" in ctx or "clienthello" in ctx or "tls" in ctx.replace(" ", ""):
        if rule.get("uses") == "signing" and ("certificate" in ctx or "sign(" in ctx):
            return "signing"
        return "tls"
    if "sign(" in ctx or "signature" in ctx or "certificate" in ctx:
        return "signing"
    if "at-rest" in ctx or "encrypt_file" in ctx or "db" in ctx:
        return "at-rest"
    return rule.get("uses", "at-rest")


def _extract_printable_strings(data, min_len=4):
    """Pure-Python replacement for the external `strings` binary (which is absent on Windows)."""
    out, cur = [], bytearray()
    for byte in data:
        if 32 <= byte < 127 or byte in (9, 10, 13):
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                out.append(bytes(cur).decode("ascii", errors="replace"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(bytes(cur).decode("ascii", errors="replace"))
    return out


class _LazyML:
    """Optional ML branch. Imported lazily so scanning works without PyTorch installed.

    The transformer is a *supplemental* signal: regex misses it but the model is confident,
    or the model confirms what regex found. It never sets risk values by itself.
    """
    def __init__(self):
        self.available = False
        self.reason = "not initialised"
        self.engine = None

    def initialise(self):
        if self.engine is not None or (self.available or self.reason != "not initialised"):
            return
        try:
            from engine.ml.inference import AdvancedCryptoInference
            self.engine = AdvancedCryptoInference()
            self.available = bool(getattr(self.engine, "loaded", False))
            self.reason = "loaded" if self.available else "model file not loaded"
        except Exception as exc:  # keep the scan working without torch / without the .pth
            self.available = False
            self.engine = None
            missing = "torch" if "torch" in str(exc).lower() else str(exc)[:120]
            self.reason = f"ML engine unavailable ({missing}); regex-only mode"

    def predict(self, code):
        self.initialise()
        if not self.available or self.engine is None:
            return None, 0.0, 0.0
        try:
            return self.engine.predict(code)
        except Exception:
            return None, 0.0, 0.0


ML_FALLBACK_CONFIDENCE_MIN = 0.90

CURVE_KEY_SIZES = {
    "secp256r1": 256, "prime256v1": 256, "secp384r1": 384, "secp521r1": 521,
    "SECP256R1": 256, "SECP384R1": 384, "SECP521R1": 521,
}
CURVE_KEY_SIZES_LOWER = {k.lower(): v for k, v in CURVE_KEY_SIZES.items()}


# ---------------------------------------------------------------------------------------------
# Comment blanking.
#
# A regex that matches inside a comment reports a cryptographic primitive the program does not
# use. Measured on the adversarial decoy suite (tests/fixtures/decoys), this was our single
# largest false-positive source: a Java file whose only mention of `KeyPairGenerator.getInstance
# ("RSA")` sat inside a Javadoc block was reported as an RSA finding.
#
# The text is blanked, not deleted: every replaced character becomes a space and newlines are
# preserved, so every byte OFFSET survives and reported line numbers stay correct. A `.replace`
# that dropped the comment would shift every subsequent line -- silently corrupting every
# location in the CBOM. There is a regression test for exactly that.
# ---------------------------------------------------------------------------------------------
_C_LINE_COMMENT = re.compile(r"//[^\n]*")
_C_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_PY_HASH_COMMENT = re.compile(r"#[^\n]*")
_PY_DOCSTRING = re.compile(r"(?:[rRbBuUfF]{0,2})(?:\"\"\"|''').*?(?:\"\"\"|''')", re.DOTALL)
# PHP 8 attributes are `#[...]` and are CODE, not comments. The negative lookbehind keeps them
# intact while still blanking an ordinary `#` comment on the same line.
_PHP_HASH_COMMENT = re.compile(r"(?<!\[)#[^\n]*")
# Ruby interpolation is `#{...}` and is also CODE. Same reasoning: do not blank the whole line.
_RUBY_HASH_COMMENT = re.compile(r"#(?!\{)[^\n]*")
# Ruby's block-comment form, and PHP's. `=begin`/`=end` must be at the start of a line.
_RUBY_BLOCK_COMMENT = re.compile(r"(?m)^=begin\b.*?^=end\b[^\n]*", re.DOTALL)


def _blank(match):
    """Erase matched text while preserving length and line structure."""
    return re.sub(r"[^\n]", " ", match.group(0))


def _strip_comments(content, path):
    """Blank comments and docstrings so rules match CODE, not prose.

    Deliberately conservative: a construct it cannot identify is left untouched, because erasing
    something that matters is worse than reporting a mention. Python `#` handling applies only to
    Python-family files -- `#` opens a comment in the config formats we scan but means something
    else on a C preprocessor line.

    PHP and Ruby need their own `#` handling, and this was a MEASURED prerequisite rather than a
    nicety. Both use `#` as their PRIMARY comment style, so without a branch here every rule in
    the PHP and Ruby packs fired on prose -- a file containing "# use OpenSSL::Cipher::AES"
    produced a crypto finding, and the tool would have reported a comment as an algorithm. A
    decoy file was measured producing two such false positives before this branch existed.

    Two exclusions per language, both because the construct is code and not a comment:
      * PHP 8 attributes are `#[Attr]`, hence the `(?<!\\[)` lookbehind.
      * Ruby interpolation is `#{expr}`, hence the `(?<!\\{)` lookahead.
    """
    lower = (path or "").lower()
    try:
        text = _C_BLOCK_COMMENT.sub(_blank, content)
        text = _C_LINE_COMMENT.sub(_blank, text)
        if lower.endswith((".py", ".pyw")):
            # A '#' inside a string is not a comment; the docstring pass runs first so a
            # triple-quoted block containing a '#' is removed as one unit.
            text = _PY_DOCSTRING.sub(_blank, text)
            text = _PY_HASH_COMMENT.sub(_blank, text)
        elif lower.endswith((".php", ".php5", ".phtml")):
            text = _PHP_HASH_COMMENT.sub(_blank, text)
        elif lower.endswith((".rb", ".rake", ".gemspec")):
            text = _RUBY_BLOCK_COMMENT.sub(_blank, text)
            text = _RUBY_HASH_COMMENT.sub(_blank, text)
        return text
    except re.error:                                    # pathological nesting: leave as-is
        return content


class ECDATScanner:
    """Scan source files, binaries and container images for cryptographic artefacts.

    Findings carry canonical primitives ('pke' | 'signature' | 'key-agreement' | 'ae' | 'hash'),
    extracted key sizes, `uses`, `evidence_class`, the matching rule id, file/line provenance
    and the ML diagnostics -- everything `engine.mosca.calculate_risk` needs without proxies.
    """

    def __init__(self, enable_ml=True, ml_window_chars=4000):
        self.enable_ml = enable_ml
        self.ml_window_chars = ml_window_chars
        self.ml = _LazyML() if enable_ml else None
        self.saw_container = False
        self.errors = []        # files that could not be read: "clean" must never mean "unread"
        # Paths counted as scanned, so `_note_error` can convert one to "skipped" rather than
        # double-counting it. See `_note_error` for why the manifest must still add up.
        self._counted_scanned = set()
        self.coverage = {
            "scanners_run": set(),
            "files_seen": 0,
            "files_scanned": 0,
            "files_skipped": 0,
            "ml_reason": "disabled" if not enable_ml else "pending",
        }

    # ------------------------------------------------------------------ internals

    def _note_error(self, path, reason):
        """Record that a file could not be read, and count it as SKIPPED, not scanned.

        `_scan_path` counts a file as scanned BEFORE the read is attempted, because a read
        failure is only knowable afterwards. Without undoing that here, one undecodable file is
        counted as both scanned and skipped and the manifest double-counts it: an end-to-end test
        caught `seen=5, scanned=4, skipped=2`, which is not a number anyone can trust. The
        invariant `files_seen == files_scanned + files_skipped` is the whole point of the
        manifest, so a file we could not read counts once, as skipped.
        """
        self.errors.append({"file": path, "reason": reason})
        if path in self._counted_scanned:
            self._counted_scanned.discard(path)
            self.coverage["files_scanned"] -= 1
        self.coverage["files_skipped"] += 1

    def _note_scanned(self, path=None):
        self.coverage["files_scanned"] += 1
        if path is not None:
            self._counted_scanned.add(path)
    def _ml_predict_windowed(self, content):
        """Run the transformer over the head of the content (documented window, not the whole
        file). Returns (label, confidence, ast_depth). The model only ever sees the first
        `ml_window_chars` characters; anything beyond that is covered by the rule table."""
        if self.ml is None:
            return None, 0.0, 0.0
        pred, conf, depth = self.ml.predict(content[: self.ml_window_chars])
        return pred, float(conf or 0.0), float(depth or 0.0)

    def _match_rules(self, file_path, content):
        # Rules run against comment-stripped text so a mention in prose is not a finding. Offsets
        # are preserved, so `line` below still points at the original source line.
        content = _strip_comments(content, file_path)
        findings = []
        lowered_name = os.path.basename(file_path).lower()
        is_config = lowered_name in CONFIG_FILENAMES or file_path.lower().endswith(CONFIG_EXTENSIONS)
        for rule, rx in _COMPILED_RULES:
            for match in rx.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                key_length = _extract_key_size(rule, match)
                name = rule["name"]
                primitive = rule["primitive"]
                evidence_class = rule["evidence"]
                if is_config and rule["evidence"] == "discovered":
                    evidence_class = "configured"
                uses = _refine_uses(rule, content[max(0, match.start() - 400): match.end() + 400])
                # A curve OBJECT is not an operation. `ec.SECP256R1()` names the algorithm but
                # not whether it will be used to agree a key or to sign, and guessing makes the
                # tool assert one of the two from nothing.
                #
                # The old code inferred the name AND the primitive from nearby prose: a bare ECC
                # hit with no TLS context was renamed "ECDSA / signature". That is a coin-flip
                # presented as a finding, and it is what let one line be reported as both ECDH
                # and ECDSA. The curve size is still resolved; the OPERATION is left unstated, and
                # `engine/purpose.py` reports the purpose as unresolved so a human decides.
                if name in ("ECC", "ECDH"):
                    for grp in match.groups() or ():
                        if grp and grp.lower() in CURVE_KEY_SIZES_LOWER:
                            key_length = CURVE_KEY_SIZES_LOWER[grp.lower()]
                if name == "ECC":
                    # Only TLS context establishes key agreement. Otherwise the operation is
                    # left UNSTATED rather than defaulted to "signature", which asserts an intent
                    # the evidence does not contain. The name stays "ECC" -- the algorithm family
                    # the code actually names -- and the break model still resolves from it.
                    if uses == "tls":
                        name, primitive = "ECDH", "key-agreement"
                    else:
                        name, primitive = "ECC", "unknown"
                finding = {
                    "file": file_path,
                    "line": line,
                    # Read the type from the rule instead of hardcoding "algorithm". A rule
                    # that matches a KMS call or an HSM handle is detecting a CAPABILITY, not
                    # an algorithm, and calling it an algorithm made every such finding land
                    # in the `used` assurance bucket and carry a primitive the schema has no
                    # word for. `engine/cbom.py` already has a working library branch, so
                    # this needs no other code change.
                    "type": rule.get("type", "algorithm"),
                    "name": name,
                    "primitive": primitive,
                    "rule_id": rule["id"],
                    "scanner": "source-scanner",
                    "evidence_class": evidence_class,
                    "artefact_class": rule["artefact_class"],
                    "uses": uses,
                    "match": match.group(0)[:160],
                }
                if key_length:
                    finding["key_length"] = key_length
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------ source files

    def _scan_source_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="strict") as fh:
                content = fh.read()
        except UnicodeDecodeError:
            self._note_error(file_path, "undecodable bytes (not UTF-8)")
            return []
        except OSError as exc:
            self._note_error(file_path, f"unreadable ({exc.strerror or exc})")
            return []

        if not content.strip():
            return []

        findings = self._match_rules(file_path, content)

        dl_pred, dl_conf, ast_depth = self._ml_predict_windowed(content)
        for f in findings:
            f["dl_confidence"] = round(dl_conf if dl_pred == f["name"] else 0.8, 4)
            f["ast_depth"] = round(ast_depth, 2)
            f["ml_model_label"] = dl_pred

        matched_rules = {f["rule_id"] for f in findings}
        if not matched_rules and dl_pred and dl_conf >= ML_FALLBACK_CONFIDENCE_MIN:
            findings.append({
                "file": file_path,
                "line": None,
                "type": "algorithm",
                "name": str(dl_pred),
                "primitive": "unknown",
                "rule_id": "ECD-ML-FALLBACK",
                "scanner": "ml-scanner",
                "evidence_class": "discovered",
                "artefact_class": "source",
                "uses": "at-rest",
                "match": None,
                "dl_confidence": round(dl_conf, 4),
                "ast_depth": round(ast_depth, 2),
                "ml_model_label": dl_pred,
                "ml_note": f"rule table missed it; transformer confidence {dl_conf:.2f} >= 0.90",
            })
        return findings

    # ------------------------------------------------------------------ binaries

    def _scan_binary_data(self, label, data):
        """Algorithm and library evidence from raw bytes, without the external `strings` binary."""
        blob = " ".join(_extract_printable_strings(data))
        findings = []
        for marker_name, rx in _COMPILED_MARKERS:
            match = rx.search(blob)
            if match:
                findings.append({
                    "file": label,
                    "line": None,
                    "type": "library",
                    "name": marker_name,
                    "primitive": "cryptographic-library",
                    "rule_id": "ECD-BIN-LIB-001",
                    "scanner": "binary-scanner",
                    "evidence_class": "discovered",
                    "artefact_class": "library",
                    "uses": "at-rest",
                    "match": match.group(0)[:160],
                    "dl_confidence": 0.0,
                    "ast_depth": 0.0,
                })
        return findings

    def _scan_binary_file(self, file_path):
        try:
            with open(file_path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            self._note_error(file_path, f"unreadable binary ({exc.strerror or exc})")
            return []
        return self._scan_binary_data(file_path, data)

    # ------------------------------------------------------------------ containers

    def _scan_container_image(self, image_path):
        """Scan docker/OCI tarballs layer by layer. Each layer is treated as an archive whose
        members are routed back into this scanner (source vs binary by extension) or, for unknown
        extensions, searched for crypto-relevant strings."""
        findings = []
        opened = None
        try:
            if image_path.endswith(".tgz") or image_path.endswith(".tar.gz"):
                opened = tarfile.open(image_path, "r:gz")
            else:
                opened = tarfile.open(image_path, "r:")
        except (tarfile.TarError, OSError, EOFError) as exc:
            self._note_error(image_path, f"not a readable container image ({exc})")
            return []
        try:
            # `getmembers()` is INSIDE the guard, and that is the whole point. In stream mode
            # ("r:") the archive is parsed lazily: a truncated file opens without error and only
            # raises when the members are read. With this call outside the try, one corrupt .tar
            # -- a partially-written `docker save`, an interrupted upload -- raises ReadError out
            # of scan_directory and destroys every other finding in the tree, because os.walk
            # never finishes. A scan must degrade to "this file could not be read", never to
            # "the whole scan died".
            members = opened.getmembers()
        except (tarfile.TarError, OSError, EOFError) as exc:
            self._note_error(image_path, f"not a readable container image ({exc})")
            return []
        try:
            for member in members:
                if not member.isfile():
                    continue
                name = member.name.lower()
                try:
                    handle = opened.extractfile(member)
                    if handle is None:
                        continue
                    data = handle.read(25 * 1024 * 1024)   # 25 MB/member cap
                except (OSError, EOFError, KeyError):
                    self._note_error(f"{image_path}!{member.name}", "could not extract layer member")
                    continue
                if name.endswith(SOURCE_EXTENSIONS) or name.endswith(CONFIG_EXTENSIONS):
                    try:
                        text = data.decode("utf-8")
                    except UnicodeDecodeError:
                        self._note_error(f"{image_path}!{member.name}", "undecodable bytes")
                        continue
                    layer_findings = self._match_rules(f"{image_path}!{member.name}", text)
                    for f in layer_findings:
                        f["evidence_class"] = "configured"
                    findings.extend(layer_findings)
                elif name.endswith(BINARY_EXTENSIONS):
                    for f in self._scan_binary_data(f"{image_path}!{member.name}", data):
                        f["evidence_class"] = "configured"
                        findings.append(f)
                elif member.size and member.size < 5 * 1024 * 1024:
                    # Unknown files are only searched for library markers, never flagged as "uses":
                    # a string match inside an image layer is presence evidence, not usage.
                    blob = " ".join(_extract_printable_strings(data))
                    for marker_name, rx in _COMPILED_MARKERS:
                        if rx.search(blob):
                            findings.append({
                                "file": f"{image_path}!{member.name}",
                                "line": None,
                                "type": "library",
                                "name": marker_name,
                                "primitive": "cryptographic-library",
                                "rule_id": "ECD-IMG-LIB-001",
                                "scanner": "container-scanner",
                                "evidence_class": "configured",
                                "artefact_class": "library",
                                "uses": "at-rest",
                                "match": f"image layer: {member.name}",
                                "dl_confidence": 0.0,
                                "ast_depth": 0.0,
                            })
        finally:
            opened.close()
        return findings

    # ------------------------------------------------------------------ entry point

    def scan_directory(self, directory_path):
        """Recursively scan a directory, a single file, or a container image tarball.

        Combines: source rule table (every rule runs -- no dead patterns), the optional
        transformer as a supplemental signal, in-house binary string extraction (no external
        `strings` binary), and docker/OCI layer scanning. Failures are recorded in
        `self.errors` and the coverage manifest, so a caller can distinguish "no crypto here"
        from "could not look here".
        """
        findings = []
        if os.path.isfile(directory_path):
            # A single-file scan must go through the SAME de-duplication and coverage
            # finalisation as a directory scan. Returning early here made the same bytes on disk
            # give two different answers depending on how they were submitted: duplicates survived,
            # `scanners_run` stayed empty, and `ml_reason` was never resolved. Both are documented
            # entry points, so they must agree.
            self.coverage["files_seen"] += 1
            if is_credential_store(os.path.basename(directory_path)):
                self._note_error(directory_path, "credential store: contents never read")
            elif resolve_within(os.path.dirname(os.path.abspath(directory_path)) or ".",
                                directory_path) is None:
                self._note_error(directory_path, "symlink escapes the scan root: not followed")
            else:
                findings.extend(self._scan_path(directory_path))
            return self._finalise(findings)
        if not os.path.isdir(directory_path):
            self._note_error(directory_path, "path does not exist or is not a directory")
            return self._finalise(findings)
        # Filesystem containment policy (see engine/fspolicy.py): refuse a synthetic filesystem
        # outright, and never follow a symlink out of the scan root.
        try:
            real_root = check_root(directory_path)
        except Exception as exc:                                   # noqa: BLE001
            self._note_error(directory_path, f"refused by filesystem policy: {exc}")
            return findings

        for root, dirs, files in os.walk(real_root):
            dirs[:] = [d for d in dirs
                       if resolve_within(real_root, os.path.join(root, d))]
            for fname in files:
                self.coverage["files_seen"] += 1
                fpath = os.path.join(root, fname)
                if is_credential_store(fname):
                    self._note_error(fpath, "credential store: contents never read")
                    continue
                if resolve_within(real_root, fpath) is None:
                    self._note_error(fpath, "symlink escapes the scan root: not followed")
                    continue
                findings.extend(self._scan_path(fpath))
        if self.ml is not None:
            self.ml.initialise()
            self.coverage["ml_reason"] = self.ml.reason
        else:
            self.coverage["ml_reason"] = "disabled"
        return self._finalise(findings)

    def _finalise(self, findings):
        """De-duplicate and close the coverage manifest. Shared by every entry point.

        Extracted so a single-file scan and a directory scan cannot drift apart: when this ran
        only at the end of the directory path, `cli.py file.py` returned duplicates and an empty
        `scanners_run`, so the same bytes gave two different answers.
        """
        # Deduplicate: same file + same name + same rule + same line = one finding.
        unique, seen = [], set()
        for f in findings:
            key = (f.get("file"), f.get("name"), f.get("rule_id"), f.get("line"))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.coverage["scanners_run"] = sorted({
            f.get("scanner", "unknown") for f in unique
        } | ({"container-scanner"} if self.saw_container else set()))
        return unique

    def _scan_path(self, fpath):
        lowered = fpath.lower()
        if lowered.endswith(CONTAINER_EXTENSIONS):
            self.saw_container = True
            self._note_scanned(fpath)
            return self._scan_container_image(fpath)
        if lowered.endswith(SOURCE_EXTENSIONS):
            self._note_scanned(fpath)
            return self._scan_source_file(fpath)
        # Config-like paths are scanned regardless of extension.
        if os.path.basename(fpath).lower() in CONFIG_FILENAMES or lowered.endswith(CONFIG_EXTENSIONS):
            self._note_scanned(fpath)
            return self._scan_source_file(fpath)
        if lowered.endswith(BINARY_EXTENSIONS):
            self._note_scanned(fpath)
            return self._scan_binary_file(fpath)
        # Out of scope by extension. It MUST still be counted as skipped, otherwise
        # `files_seen` exceeds `files_scanned + files_skipped` and the coverage manifest
        # cannot account for every file it walked. A number that does not add up makes the
        # whole manifest untrustworthy -- it is the one artefact whose entire job is to be
        # believed, so a silent drop here undoes the point of having it.
        self.coverage["files_skipped"] += 1
        return []

    # ------------------------------------------------------------------ coverage

    def coverage_manifest(self, findings=None):
        """What was scanned, what failed, and what was never in scope. Callers should render
        this alongside results so 'not found' and 'not examined' are distinguishable.

        When `findings` is supplied, the assurance breakdown and the proven-use count are
        included: the raw finding total is misleading on its own, because it mixes proven call
        sites with capabilities nothing invokes.
        """
        manifest = {
            "scanners_run": sorted(self.coverage["scanners_run"]),
            "files_seen": self.coverage["files_seen"],
            "files_scanned": self.coverage["files_scanned"],
            "files_skipped": self.coverage["files_skipped"],
            "ml_reason": self.coverage["ml_reason"],
            "ml_window_chars": self.ml_window_chars,
            "errors": list(self.errors),
            "never_in_scope": [
                "network-negotiated crypto (requires a capture sensor)",
                "cloud KMS / managed keys (requires provider APIs)",
                "HSM / TPM internal keys (requires attestation)",
                "SaaS / third-party boundary crypto (requires attestation)",
                "silicon-embedded keys (requires attestation)",
            ],
        }
        if findings is not None:
            manifest["findings_total"] = len(findings)
            manifest["assurance_histogram"] = assurance_histogram(findings)
            manifest["proven_use"] = proven_use_count(findings)
            # Count unresolved purpose only where a PQC target is actually in question. A hash or
            # a symmetric cipher has no purpose ambiguity that matters -- counting them would
            # inflate a number that should mean "a human must look at this".
            manifest["unresolved_purpose"] = unresolved_purpose_count(findings)
        return manifest



