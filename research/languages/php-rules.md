# PHP detection rule pack - design proposal

**Status: DESIGN ONLY. No engine file and no test was modified.** Every regex below was compiled
and executed against the real `engine/scanner.py` code paths (`_match_rules` ->
`_extract_key_size` -> `_refine_uses`) in a throwaway harness outside the repository. Every
result quoted as *measured* was observed, not predicted. Section 12 lists what was **not**
verified.

**Provenance.** Written from the PHP standard library surface (`ext/openssl`, `ext/hash`,
`ext/sodium`) and from my own knowledge of those extensions, plus direct reading of this
repository's engine. No competitor project was fetched, read or referenced. I had no PHP runtime
available, so every claim about PHP *behaviour* (as opposed to PHP *spelling*) is marked
**[doc]** and is flagged for confirmation in section 12.

---

## 0. Read this first: seven engine facts that constrain every rule below

Established by reading the code and confirmed by running it. They are why several
otherwise-obvious rules are absent, marked CONFLICTING, or declined.

### F1 - One rule id per line is free; two rule ids with the same `name` is inflation

`_finalise` de-duplicates on `(file, name, rule_id, line)` (`scanner.py:737`). Therefore:

* Several matches of the **same** rule on one line collapse to **one** finding. Alternatives
  inside a single regex are free.
* Two **different** rule ids that both yield `name="AES"` on one line produce **two** findings and
  therefore **two** CBOM components for a single statement.

This is the defect class the engine has already fixed twice - see the comments at
`scanner.py:127-130` (PSS reported as both `pke` and `signature`) and `scanner.py:48-55` (an ECC
key-pair generator reported as both ECDH and ECDSA). **Design law for this pack: split a rule only
when the halves must carry a different `name`, `primitive` or `mode`.**

### F2 - Two shipped rules already own some cipher-string tokens, and they are lower-case only

`IM-SRC-SSH-CIPHER-001` is `["'](?:aes(?:128|192|256)-(?:ctr|gcm|cbc)|...)["']` and
`IM-SRC-SSH-LEGACY-001` is `["'](?:3des-cbc|des-cbc|arcfour|arcfour256|blowfish-cbc|cast128-cbc)["']`.
Both are language-agnostic and case-sensitive, so:

* PHP's dominant spelling `'AES-256-CBC'` is matched by **nothing** today (measured).
* A case-insensitive PHP/Ruby cipher rule would double-count every lower-case literal.

**Division of labour adopted here:** the two SSH rules keep ownership of *lower-case quoted
OpenSSL/SSH cipher strings*; this pack owns (a) upper-case PHP spellings, (b) modes nobody lists
(`ecb`, `cfb`, `ofb`, `xts`, `ccm`, `ocb`, `eax`, `siv`), (c) constant and symbol forms, and
(d) calls whose cipher is not a literal. PREREQ-1 in section 10 states the alternative.

### F3 - `IM-SRC-AES-001` already matches `AES.new(`

Its regex contains `AES\.new\(` with **no capture group**, although the rule already declares
`key_group=1` and a `key_map`. Measured: it fires on `OpenSSL::Cipher::AES.new(256, :gcm)` and
yields `key_length=None`. This is why two Ruby rules are marked WITHDRAWN in the companion
document, and it is a one-token fix (E9).

### F4 - `#` comments are blanked for `.py` only, so PHP `#` comments leak findings

`_strip_comments` blanks `//`, `/* ... */`, and - **only when the path ends `.py`/`.pyw`** -
`# ...` (`scanner.py:375-394`). `#` is PHP's most common comment style. Measured on my PHP decoy
set: the single line `# openssl_encrypt($data, 'AES-256-CBC', $key);` produced two findings. The
same is true for Ruby (measured, companion document D2). **This is the largest false-positive
source for both packs and it cannot be fixed from the rule table.** See E1.

### F5 - The scanner never sets `mode`, but the CBOM emitter already consumes it

`cbom._algorithm_properties` reads `finding["mode"]` and maps it through `_canonical_mode`
(`cbom.py:369-372`), which accepts `cbc ctr ecb ccm gcm cfb ofb` and degrades anything else to
`other` (measured). `_match_rules` never writes `mode`. A rule that must say "AES **in ECB mode**"
has nowhere to put it today. E3 is the one-line change that unlocks it.

### F6 - Every rule must be added to the reachability sample map or the suite fails

`tests/test_scanner.py:83` asserts `set(samples) == {r["id"] for r in RULES}`. Adding rules
without adding a positive sample fails with "a rule has no positive test". **Every rule below
therefore carries a `Sample` value in section 4**, already in that file's format.

### F7 - The `primitive` vocabulary is closed, and two members behave badly

From `cbom.PRIMITIVE_ENUM` (measured round-trip): `pke`, `key-agreement`->`key-agree`, `kem`,
`signature`, `ae`, `block-cipher`, `stream-cipher`, `hash`, `mac`, `kdf`, `key-derive`->`kdf`,
`key-wrap`, `combiner`, `xof`, `drbg`, `other`, `unknown`. **`protocol` is not a primitive** - it
maps to `unknown` and is emitted as a protocol asset. No new primitive is proposed.

---

## 1. Measured downstream behaviour of every `name` / `primitive` pair proposed here

Each proposed finding was passed through `resolve_purpose`, `quantum_break_model`,
`_nist_quantum_level` and `get_pqc_recommendation` **before** being proposed. The results
constrain the design and are quoted again in section 8.

| finding | purpose | mosca break | nistQuantumSecurityLevel | recommendation |
|---|---|---|---|---|
| `RSA` / `pke` (keygen only) | unresolved, **signals `[]`** | broken-by-Shor | 0 | **ML-KEM-768** (wrong if the key only signs) |
| `RSA` / `unknown` (keygen only) | unresolved, signals `[]` | broken-by-Shor | *omitted* | **ML-KEM-768** (same problem) |
| `RSA` / `signature` (`openssl_sign`) | signature (`sign(`) | broken-by-Shor | 0 | ML-DSA-44/65 |
| `Ed25519` / `signature` (`sodium_crypto_sign_detached`) | unresolved, signals `[]` | broken-by-Shor | 0 | ML-DSA-44/65 |
| `X25519` / `key-agreement` (`sodium_crypto_scalarmult`) | **key-establishment** (`x25519`) | broken-by-Shor | 0 | X25519MLKEM768 hybrid |
| `RSA` / `signature` (`openssl_pkcs7_sign`) | signature (`sign(`) | broken-by-Shor | 0 | ML-DSA-44/65 |
| `PKCS7` / `unknown` (the alternative I rejected) | unresolved | **not-affected** | *omitted* | Manual review |
| `PBKDF2` / `kdf` | unresolved | not-affected | **0** (false) | Manual review |
| `MT19937` / `drbg` | unresolved | not-affected | *omitted* | Manual review |
| `CSPRNG` / `drbg` | unresolved | not-affected | *omitted* | Manual review |
| `AES` / `block-cipher` + `key_length=256` (ECB) | unresolved | weakened-by-Grover | 5 | **No migration required** |

Three of these are load-bearing problems, not curiosities.

* An **RSA key-generation finding is told to migrate to ML-KEM.** `resolve_purpose` returns
  `unresolved` with an **empty** signal list, so the recommender's refusal branch
  (`recommender.py:232`, which requires `bool(purpose_signals)`) never fires. Worse,
  `primitive="unknown"` does not help: `_normalise_primitive` falls back to the *name* and returns
  `pke` for anything containing "RSA" (`recommender.py:183`). The token `"rsa_new"` already in the
  UNRESOLVED bucket at `purpose.py:47` does not match PHP's or Ruby's spelling. See E2.
* **`primitive="kdf"` emits `nistQuantumSecurityLevel: 0`.** `cbom.py:238-240` lists `kdf` and
  `key-derive` among the Shor-broken primitives. For PBKDF2, Argon2id, scrypt and bcrypt that is
  false, and it contradicts the `not-affected` verdict in the same row - the exact
  self-contradiction `cbom.py:200-214` says was fixed. See E4.
* **An AES-ECB finding is reported as "No migration required."** Correct quantum-wise (Grover,
  not Shor) and useless in practice. Detecting ECB is only worth doing if the mode reaches the
  reader. See A6 and E3.

---

## 2. Pack summary

| family | rules |
|---|---|
| `openssl_encrypt` / `openssl_decrypt` symmetric | 7 |
| legacy and stream ciphers, RC2/RC4 constants | 5 |
| hashes, MAC, KDF, password hashing | 14 |
| asymmetric: RSA / DSA / DH / PKCS#7 / CSR | 8 |
| libsodium | 12 |
| randomness: CSPRNG and weak | 5 |
| configuration: php.ini and framework `cipher` | 3 |
| declined, or already covered by a shipped rule | 14 (section 5) |

**54 rules.** All 54 compile, all 54 fire on their own sample, and no two of them produce the same
`(name, line)` - measured, not asserted. Measured cross-table collisions with the 34 shipped
rules: **zero**.

---

## 3. Proposed rules

`kg` is `key_group`; `-` means `None`. Every regex is byte-for-byte the one that was compiled and
executed; none has been retyped. Because a markdown table cannot hold a one-line prose
justification per regex without becoming unreadable, each family has a table of the five required
fields followed by numbered justification lines.

### 3.1 `openssl_encrypt` / `openssl_decrypt` - symmetric

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-SYM-001 | OPENSSL-SYM | block-cipher | at-rest | - | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*\$[A-Za-z_]` |
| IM-SRC-PHP-AES-ECB-001 | AES | block-cipher | at-rest | 1 | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*aes[-_]?(128\|192\|256)[-_]?ecb\b` |
| IM-SRC-PHP-AES-AEAD-001 | AES | ae | at-rest | 1 | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*aes[-_]?(128\|192\|256)[-_]?(?:gcm\|ccm\|ocb\|eax\|siv)\b` |
| IM-SRC-PHP-AES-OTHER-001 | AES | block-cipher | at-rest | 1 | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*aes[-_]?(128\|192\|256)[-_]?(?:cfb\|ofb\|xts)\b` |
| IM-SRC-PHP-AES-UPPER-001 (dagger) | AES | block-cipher | at-rest | 1 | `(?i:openssl_(?:en\|de)crypt)\s*\([^)]*['"]AES[-_]?(128\|192\|256)\b` |
| IM-SRC-PHP-CHACHA-001 | ChaCha20 | ae | at-rest | - | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*chacha20(?:[-_]poly1305)?\b` |
| IM-SRC-PHP-IV-001 | AES | ae | at-rest | 1 | `(?i:openssl_cipher_iv_length)\s*\(\s*['"]\s*aes[-_]?(128\|192\|256)\b` |

dagger CONFLICTING under PREREQ-1; see F2 and section 10.

* **P-01 `OPENSSL-SYM`.** The `\$[A-Za-z_]` requires a *variable* in argument position 2, so the
  call is real and the algorithm is genuinely unstated; the `[^,()]*` in front of it cannot cross
  a comma or a parenthesis, so it can only ever be the second argument. This is the most useful
  rule in the pack: it finds every `openssl_encrypt()` whose cipher is decided elsewhere, and it
  cannot collide with a literal-cipher rule because the character after the comma is `$`, not a
  quote. It asserts the *existence* of symmetric encryption and declines to name the algorithm
  (A2).
* **P-02 `AES-ECB`.** ECB is a misuse rather than a quantum fact, so it gets its own rule and its
  own primitive: `ae` would be a lie and `block-cipher` is what the mode actually is. The trailing
  `ecb\b` makes it disjoint from P-03 and P-04 on the same line.
* **P-03 `AES-AEAD`.** The mode alternation lists only authenticated modes, so P-03 and P-04 are
  mutually exclusive on any line and cannot both fire; the AEAD/non-AEAD split is what lets the
  pack state the primitive honestly without a `mode` field.
* **P-04 `AES-OTHER`.** `cfb|ofb|xts` are exactly the modes absent from
  `IM-SRC-SSH-CIPHER-001`, so this rule adds coverage rather than duplicating it.
* **P-05 `AES-UPPER`.** **Case is the discriminator, deliberately.** PHP's own documentation and
  essentially all PHP code write the cipher upper-case (`'AES-256-CBC'`), while Ruby's OpenSSL and
  the SSH wire names are lower-case, and `IM-SRC-SSH-CIPHER-001` is lower-case only (measured: no
  PHP cross-table collision). Making this rule case-insensitive would double-count every lower-case
  literal. `[^)]*` rather than `[^,()]*` because the first argument of a real call is frequently
  itself a call, and stopping at the first `)` is the conservative choice: on
  `openssl_encrypt(serialize($d), 'AES-256-CBC', ...)` this rule abstains and P-03/P-04 or F2's
  rule still find the algorithm.
* **P-06 `CHACHA`.** `chacha20(?:[-_]poly1305)?\b` requires a word boundary after the optional
  suffix, so the literal `'ChaCha20Poly1305'` (no separator) is *not* matched and cannot
  double-report against `IM-SRC-CHACHA-001`, which matches that exact spelling.
* **P-07 `IV-LENGTH`.** `openssl_cipher_iv_length` is the only PHP function that takes a cipher
  name and returns its IV size, so naming it names a cipher, and the digits are the key size.

### 3.2 Legacy and stream ciphers

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-3DES-001 | 3DES | block-cipher | at-rest | - | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*(?:3des(?!-cbc)\|des-ede3\|tripledes\|des3)` |
| IM-SRC-PHP-LEGACY-001 | LEGACY-CIPHER | block-cipher | at-rest | - | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*(?:des(?!-cbc)\|bf\|blowfish(?!-cbc)\|cast5\|idea\|seed\|rc2\|sm4)` |
| IM-SRC-PHP-RC4-001 | RC4 | stream-cipher | at-rest | - | `(?i:openssl_(?:en\|de)crypt)\s*\(\s*[^,()]*,\s*['"]\s*rc4\b` |
| IM-SRC-PHP-PKCS7-RC2-001 | RC2 | block-cipher | at-rest | 1 | `OPENSSL_CIPHER_RC2_(40\|64)_CBC` |
| IM-SRC-PHP-RC4-002 | RC4 | stream-cipher | at-rest | - | `OPENSSL_CIPHER_RC4\b` |

`IM-SRC-PHP-PKCS7-RC2-001` uses `key_map={"40": 40, "64": 64}`.

* **P-08 `3DES`.** The `(?!-cbc)` guard excludes exactly the one spelling
  `IM-SRC-SSH-LEGACY-001` already owns (`3des-cbc`) and nothing else, so `des-ede3-cbc` is still
  caught. The guard sits on the `3des` alternative alone; my first version put it after the whole
  group and the rule went dead on its own sample (measured dead, then fixed).
* **P-09 `LEGACY`.** The same guard applied per alternative: `des(?!-cbc)` and `blowfish(?!-cbc)`
  yield to the SSH rule, while `bf`, `cast5`, `idea`, `seed`, `rc2` and `sm4` do not appear in it
  at all. One rule rather than six, because they share `name` and `primitive` and F1 would turn
  six ids into six identical components.
* **P-10 `RC4`.** `['"]\s*rc4\b` matches only the `rc4` spelling; `arcfour`/`arcfour256` belong
  to `IM-SRC-SSH-LEGACY-001` and are deliberately left alone.
* **P-11 `RC2`.** The OpenSSL constant's own name carries the key size, so the capture is the size
  and `key_map` maps it. This matters because RC2-40-CBC is the **documented default cipher of
  `openssl_pkcs7_encrypt`** **[doc]**, so a PKCS#7 call that names no cipher at all is still a
  40-bit RC2 use; the constant only appears when the author chose it explicitly, so this rule
  catches what P-16 cannot.
* **P-12 `RC4-002`.** Same `name` and `primitive` as P-10 but a different spelling, so F1 forces a
  separate id. The two can never co-occur: one needs `openssl_encrypt(`, the other a bare constant.

### 3.3 Hashes, MAC, KDF and password hashing

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-HASH-SHA2-001 | SHA256 | hash | at-rest | - | `(?i:hash\|hash_file\|openssl_digest)\s*\(\s*['"](?:sha2?-?256\|sha-?3-?256)['"]` |
| IM-SRC-PHP-HASH-SHA1-001 | SHA1 | hash | at-rest | - | `(?i:hash\|hash_file\|openssl_digest)\s*\(\s*['"]sha-?1['"]` |
| IM-SRC-PHP-HASH-MD5-001 | MD5 | hash | at-rest | - | `(?i:hash\|hash_file\|openssl_digest)\s*\(\s*['"]md5['"]` |
| IM-SRC-PHP-MAC-001 | HMAC | mac | at-rest | - | `(?i:hash_hmac)\s*\(\s*['"][a-z0-9-]{3,15}['"]` |
| IM-SRC-PHP-KDF-PBKDF2-001 | PBKDF2 | kdf | at-rest | - | `(?i:hash_pbkdf2)\s*\(` |
| IM-SRC-PHP-KDF-HKDF-001 | HKDF | kdf | at-rest | - | `(?i:hash_hkdf)\s*\(` |
| IM-SRC-PHP-PWD-ARGON2-001 | Argon2id | kdf | at-rest | - | `(?i:password_hash)\s*\([^,()]+,\s*(?:PASSWORD_)?ARGON2I?D?\b` |
| IM-SRC-PHP-PWD-DEFAULT-001 | PASSWORD-HASH | kdf | at-rest | - | `(?i:password_hash)\s*\(\s*[^,()]+(?:\s*,\s*(?:PASSWORD_DEFAULT\|NULL)\s*)?\)` |
| IM-SRC-PHP-PWD-INFO-001 | PASSWORD-HASH | kdf | at-rest | - | `(?i:password_get_info)\s*\(` |
| IM-SRC-PHP-DIGESTALG-SHA1-001 | SHA1 | hash | signing | - | `['"]digest_alg['"]\s*=>\s*['"]sha-?1['"]` |
| IM-SRC-PHP-DIGESTALG-SHA2-001 | SHA2 | hash | signing | - | `['"]digest_alg['"]\s*=>\s*['"]sha-?(?:224\|256\|384\|512)['"]` |
| IM-SRC-PHP-SHA1-SIGALG-001 | SHA1 | hash | signing | - | `(?i:openssl_(?:sign\|verify))\s*\([^)]*OPENSSL_ALGO_SHA1\b` |
| IM-SRC-PHP-SIGN-DEFAULT-001 | SHA1 | hash | signing | - | `(?i:openssl_sign)\s*\(\s*[^,()]+,\s*[^,()]+,\s*[^,()]+\s*\)` |
| IM-SRC-PHP-SHA2-SIGALG-001 | SHA2 | hash | signing | - | `(?i:openssl_(?:sign\|verify))\s*\([^)]*OPENSSL_ALGO_SHA(?:224\|256\|384\|512)\b` |

* **P-13/14/15 `HASH-*`.** `hash()` is the only PHP entry point that takes the algorithm as a
  string in argument 1, and the case-insensitive scope is *correct* rather than loose because PHP
  algorithm names are case-insensitive; the quoted literal is what makes this a call rather than a
  mention. `openssl_digest` is included because it is a documented alias of `hash()` **[doc]**. The
  bare `sha1()` and `md5()` **functions** are deliberately absent: `IM-SRC-SHA1-001` and
  `IM-SRC-MD5-001` already match them (their regexes contain `sha1\(` and `\bmd5\(`), so new
  rules would be pure duplication under F1.
* **P-16 `MAC`.** The quoted first argument forces the digest to be visible, which is what makes
  this an HMAC *use* rather than a function name; the token `hmac-sha2-256` that
  `IM-SRC-SSH-MAC-001` owns cannot match a bare digest name, so there is no overlap (measured).
* **P-17/18 `KDF`.** `hash_pbkdf2` and `hash_hkdf` are separate rules because they carry different
  `name`s, and F1 makes different names a legitimate reason to split. Both take the algorithm as a
  string, so the call alone is enough evidence.
* **P-19 `ARGON2`.** The constant is the algorithm; `ARGON2I?D?` admits `ARGON2I`, `ARGON2ID` and
  `ARGON2D`, and the rule names the result `Argon2id`, the only one of the three still recommended
  **[doc + opinion]**. If the I/D distinction matters to you, split it into three rules.
* **P-20 `PWD-DEFAULT`.** The closing parenthesis immediately after one argument, or after
  `PASSWORD_DEFAULT`/`NULL`, is what distinguishes the *default* algorithm from an explicitly named
  one, so this rule and P-19 are mutually exclusive on a line and cannot both fire.
  `PASSWORD_DEFAULT` is bcrypt in every PHP version I know of, but it is version-dependent by
  design, so the `name` is deliberately the family `PASSWORD-HASH` and not `bcrypt`.
* **P-21 `PWD-INFO`.** `password_get_info()` means password hashing with a known algorithm is in
  use in this codebase; it reports the algorithm, so its presence is the evidence.
* **P-22/23 `DIGESTALG`.** `digest_alg` is an OpenSSL *option key*, and the quoted value is the
  only place PHP lets you state the digest for a CSR or a PKCS#7 operation without naming a
  constant; the `=>` pins the match to an options array.
* **P-24 `SHA1-SIGALG`.** `OPENSSL_ALGO_SHA1` is a constant unique to this purpose, and the match
  text also contains `openssl_sign(`, which makes `resolve_purpose` return **signature** via its
  `sign(` needle (measured) - so this finding is fully resolved rather than unresolved.
* **P-25 `SIGN-DEFAULT`.** The rule I would argue for hardest. The fourth parameter of
  `openssl_sign()`/`openssl_verify()` defaults to `OPENSSL_ALGO_SHA1` **[doc, high confidence]**, so
  a call with exactly three arguments *is* a SHA-1 signature whether or not the author knew.
  Requiring the closing parenthesis after three comma-free arguments is what makes "exactly three"
  provable from the text; on a four-argument call the pattern cannot match, because `[^,()]+`
  cannot cross the third comma.
* **P-26 `SHA2-SIGALG`.** `name="SHA2"` rather than `SHA256` because the constant may be
  SHA-224/256/384/512 and naming it SHA256 would be false for three of the four. The cost is that
  `cbom` then omits `nistQuantumSecurityLevel` instead of publishing a category, which is the
  correct trade (measured).

### 3.4 Asymmetric: RSA, DSA, DH, PKCS#7, CSR

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-RSA-PKE-001 | RSA | pke | at-rest | - | `(?i:openssl_(?:public_encrypt\|private_decrypt\|seal\|open))\s*\(` |
| IM-SRC-PHP-RSA-SIG-001 | RSA | signature | signing | - | `(?i:openssl_(?:sign\|verify))\s*\(` |
| IM-SRC-PHP-PKCS7-ENC-001 | RSA | pke | at-rest | - | `(?i:openssl_pkcs7_encrypt)\s*\(` |
| IM-SRC-PHP-PKCS7-SIG-001 | RSA | signature | signing | - | `(?i:openssl_pkcs7_sign)\s*\(` |
| IM-SRC-PHP-CSR-001 | RSA | signature | signing | - | `(?i:openssl_csr_sign)\s*\(` |
| IM-SRC-PHP-RSA-KEYGEN-001 | RSA | unknown | at-rest | 1 | three alternatives, below |
| IM-SRC-PHP-DSA-KEYGEN-001 | DSA | signature | signing | 1 | three alternatives, below |
| IM-SRC-PHP-DH-KEYGEN-001 | DH | key-agreement | tls | 1 | three alternatives, below |

The three keygen rules share one shape, parameterised by the `OPENSSL_KEYTYPE_*` constant
(`RSA` shown; substitute `DSA` or `DH`):

```
(?i:OPENSSL_KEYTYPE_RSA)['"]?\s*,?\s*['"]private_key_bits['"]?\s*=>\s*(\d+)
|['"]private_key_bits['"]?\s*=>\s*(\d+)\s*,\s*['"]private_key_type['"]?\s*=>\s*(?i:OPENSSL_KEYTYPE_RSA)
|(?i:OPENSSL_KEYTYPE_RSA)\b
```

* **P-27 `RSA-PKE`.** These four functions are PHP's public-key encryption surface. `seal`/`open`
  are the *correct* hybrid pattern (a fresh random content key) and `public_encrypt` the PKCS#1
  v1.5 one; both are key transport, so they share a `name` and a `primitive` and are therefore one
  rule. **The rule asserts the primitive and declines to assert the padding** - A4.
* **P-28 `RSA-SIG`.** The two functions that create and check an RSA signature. `verify` is
  included because a verification call is still evidence that the scheme is SHA-1-with-RSA, which
  is the actionable fact, and because the default-digest problem (P-25) applies to both.
* **P-29/30 `PKCS7`.** The two PKCS#7 operations have genuinely different primitives (enveloped
  data is key transport; a PKCS#7 signature is a signature), so F1 requires two ids. **Both assert
  the algorithm family, which is the family assertion in this pack I am least comfortable with** -
  A5 has the measurement that settles it.
* **P-31 `CSR`.** Signing a certificate request is a signature by definition, whatever the key
  type; the function name is PHP's own and cannot collide with anything.
* **P-32/33/34 `*-KEYGEN`.** Three alternatives because the options array may list the type before
  or after the size and either order must yield the size; the third catches the type given alone.
  `key_group=1` is correct even though the size is group 1 in the first alternative and group 2 in
  the second, because `_extract_key_size` walks forward from `key_group` to the first non-empty
  group (`scanner.py:255-272`) - measured, both orders yield `key_length=2048`. The family comes
  from the `OPENSSL_KEYTYPE_*` constant itself, the strongest family evidence available in PHP
  source. **Primitives differ per family on purpose:** DSA cannot encrypt, so its purpose is
  settled at `signature`; finite-field DH keys exist only to agree a key, so `key-agreement` is
  settled; RSA does both, so generation settles nothing and the rule emits `primitive="unknown"`
  (A1).

### 3.5 libsodium (ext/sodium)

Every one of these functions has a **fixed** algorithm with no parameter to vary, so the function
name alone is a complete algorithm assertion. That is the opposite of Java's
`KeyPairGenerator.getInstance(...)`, and it is why these rules can be confident where
`IM-SRC-ECDH-001` had to abstain (see the comment at `scanner.py:48-55`).

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-SODIUM-SECRETBOX-001 | XSalsa20-Poly1305 | ae | at-rest | - | `(?i:sodium_crypto_secretbox(?:_open)?)\s*\(` |
| IM-SRC-PHP-SODIUM-AEAD-AES-001 | AES | ae | at-rest | - | `(?i:sodium_crypto_aead_aes256gcm_(?:encrypt\|decrypt))\s*\(` |
| IM-SRC-PHP-SODIUM-AEAD-CHACHA-001 | ChaCha20 | ae | at-rest | - | `(?i:sodium_crypto_aead_(?:x?chacha20poly1305_ietf)_(?:encrypt\|decrypt))\s*\(` |
| IM-SRC-PHP-SODIUM-BOX-001 | X25519-XSalsa20-Poly1305 | pke | at-rest | - | `(?i:sodium_crypto_box(?:_seal\|_seal_open)?)\s*\(` |
| IM-SRC-PHP-SODIUM-BOXKEY-001 | X25519 | key-agreement | tls | - | `(?i:sodium_crypto_box_keypair\|sodium_crypto_scalarmult(?:_base)?)\s*\(` |
| IM-SRC-PHP-SODIUM-SIGN-001 | Ed25519 | signature | signing | - | `(?i:sodium_crypto_sign(?:_detached\|_verify_detached\|_open)?)\s*\(` |
| IM-SRC-PHP-SODIUM-SIGNKEY-001 | Ed25519 | signature | signing | - | `(?i:sodium_crypto_sign_(?:seed_)?keypair)\s*\(` |
| IM-SRC-PHP-SODIUM-KX-001 | X25519-XChaCha20-Poly1305 | key-agreement | tls | - | `(?i:sodium_crypto_kx_(?:client\|server)_session_keys)\s*\(` |
| IM-SRC-PHP-SODIUM-AUTH-001 | BLAKE2b | mac | at-rest | - | `(?i:sodium_crypto_(?:auth\|verify))\s*\(` |
| IM-SRC-PHP-SODIUM-GHASH-001 | BLAKE2b | hash | at-rest | - | `(?i:sodium_crypto_generichash)\s*\(\s*[^,()]+\s*\)` |
| IM-SRC-PHP-SODIUM-GMAC-001 | BLAKE2b | mac | at-rest | - | `(?i:sodium_crypto_generichash)\s*\(\s*[^,()]+,[^,()]+\)\|(?i:sodium_crypto_generichash_init)\s*\(` |
| IM-SRC-PHP-SODIUM-PWHASH-001 | scrypt | kdf | at-rest | - | `(?i:sodium_crypto_pwhash(?:_str)?)\s*\(` |

* **P-35 `SECRETBOX`.** `secretbox` is XSalsa20-Poly1305 with a 32-byte key **[doc]**; the key size
  is fixed by the algorithm and cannot be captured from source, so `key_length` is left unset and
  the recommender's "Confirm key size" branch is the honest outcome (E6 proposes a static table).
* **P-36/37 `AEAD`.** The AEAD function names contain the algorithm, so no separate cipher-string
  rule is needed. These are the only two AEAD families I am confident enough to name;
  `sodium_crypto_aead_aegis256_*` is **omitted** because I could not establish its PHP spelling or
  availability, and a guessed rule either never fires or fires wrongly.
* **P-38 `BOX`.** The `(?:_seal|_seal_open)?` suffix group with a mandatory `\s*\(` after it means
  `sodium_crypto_box_keypair(` cannot match, because the next character is `_` and not `(`; that
  is what lets P-38 and P-39 coexist without inflation under F1.
* **P-39 `BOXKEY`.** One rule for two spellings because both are the X25519 scalar and therefore the
  same primitive. The `x25519` needle at `purpose.py:44` makes this finding resolve to
  **key-establishment** and the recommender names the X25519MLKEM768 hybrid (measured) - the best
  downstream result in the pack, from a nine-character regex.
* **P-40/41 `SIGN` / `SIGNKEY`.** Split only because P-41 asserts `signature` for a *keypair* call,
  which is sound here and would not be for a generic generator: `sodium_crypto_sign_keypair` can
  only ever produce an Ed25519 signing key, so the API itself settles its purpose. This is the one
  place in either pack where key *generation* is confidently typed, and the reason is that the
  algorithm is fixed by the function name - precisely the case `scanner.py:48-55` could not accept
  for `KeyPairGenerator.getInstance("EC")`.
* **P-42 `KX`.** `crypto_kx` is a combined X25519 + XChaCha20-Poly1305 key exchange **[doc]**. Its
  `name` contains no needle from `purpose.py`, so purpose stays unresolved, but the primitive is
  stated so the recommender names a KEM, which is right. *Uncertain*: the PHP version that exposed
  these functions (I believe 8.1, unverified - section 12).
* **P-43 `AUTH`.** `crypto_auth`/`crypto_verify` are a keyed BLAKE2b authenticator **[doc]**, i.e.
  a MAC, not a hash. The `name` is `BLAKE2b`; calling it `HMAC` would be wrong.
* **P-44/45 `GHASH` / `GMAC`.** The only place in either pack where a comma inside the call
  separates two different primitives. `sodium_crypto_generichash($msg)` is an unkeyed hash;
  `sodium_crypto_generichash($msg, $key)` is a MAC; `generichash_init` is always keyed. The first
  pattern requires the closing parenthesis after exactly one argument and the second requires a
  comma, so they are provably disjoint on one line. Guessing here would report a MAC as a hash.
* **P-46 `PWHASH`.** `crypto_pwhash` is scrypt **[doc]**; the optional `_str` keeps this one rule
  instead of two, since both share `name` and `primitive`.

### 3.6 Randomness

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-PHP-RNG-001 | CSPRNG | drbg | at-rest | - | `(?i:random_bytes\|random_int)\s*\(` |
| IM-SRC-PHP-RNG-OPENSSL-001 | CSPRNG | drbg | at-rest | - | `(?i:openssl_random_pseudo_bytes)\s*\(` |
| IM-SRC-PHP-WEAKRNG-MT-001 | MT19937 | drbg | at-rest | - | `(?i:mt_rand\|mt_srand\|mt_getrandmax)\s*\(` |
| IM-SRC-PHP-WEAKRNG-RAND-001 | LIBC-RAND | drbg | at-rest | - | `(?<![A-Za-z0-9_$:>])rand\s*\(` |
| IM-SRC-PHP-WEAKRNG-WEAK-001 | INSECURE-RNG | drbg | at-rest | - | `(?i:uniqid\|str_shuffle\|shuffle\|lcg_value\|array_rand)\s*\(` |

* **P-47 `CSPRNG`.** `random_bytes`/`random_int` are PHP's CSPRNG entry points **[doc]**; the
  `\s*\(` is belt-and-braces because they cannot be used as bare words.
* **P-48 `OPENSSL-RAND`.** `openssl_random_pseudo_bytes` is a separate function with a separate
  `$strong_output` out-parameter, and its output is only as good as the platform CSPRNG, which is
  why it gets its own rule rather than an alternative inside P-47's pattern. F1 permits this
  because the two calls never co-occur on a line.
* **P-49 `MT19937`.** The Mersenne Twister family, named as such so a reader is not left guessing
  which PRNG. `mt_srand` and `mt_getrandmax` are included because a *seeding* call is more damning
  evidence than a draw: it shows the state is being managed deliberately.
* **P-50 `LIBC-RAND`.** The lookbehind is the whole point. PHP's `mt_rand(`, `srand(`,
  `array_rand(` and `str_shuffle(` all *contain* `rand(` or end with it, and without the guard a
  single `mt_rand(` call produces two findings under two different names, one of them false. `_`,
  `$`, `:` and `>` are all excluded so `$rand`, `Foo::rand` and `$obj->rand` are not matched either.
  Measured: `mt_rand(1000, 9999)` produces exactly one finding, from P-49.
* **P-51 `INSECURE-RNG`.** One rule for five entropy-hostile functions because they share `name`
  and `primitive`; `str_shuffle(` is matched as a whole so the inner `shuffle(` cannot produce a
  second hit, `finditer` resuming after the end of the first match.
* **Caveat, stated loudly.** All five of these findings route to `RULE-UNKNOWN -> "Manual review
  required"` and every one is rated `not-affected` by `mosca` (measured). For `mt_rand` in a token
  generator that is a severe understatement: the defect is classical, not quantum. The engine has
  no advisory or severity channel, so these rules are *detection-complete and action-invisible*.
  E7 is the minimum fix; until it exists, do not present these findings as a quantum result.

### 3.7 Configuration

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-CFG-PHP-CA-001 | CA-BUNDLE | unknown | tls | - | `(?i:\bopenssl\.(?:cafile\|capath)\s*=\s*\S+)` |
| IM-SRC-PHP-CFG-CIPHER-001 | AES | block-cipher | at-rest | 1 | `(?i)['"]cipher['"]\s*=>\s*['"]\s*aes[-_]?(128\|192\|256)(?![-_]?ecb)\b` |
| IM-SRC-PHP-CFG-CIPHER-ECB-001 | AES | block-cipher | at-rest | 1 | `(?i)['"]cipher['"]\s*=>\s*['"]\s*aes[-_]?(128\|192\|256)[-_]?ecb` |

All three use `evidence="configured"`, so `artefact_class` is `config`.

* **P-52 `CA-BUNDLE`.** `openssl.cafile` and `openssl.capath` are the only php.ini keys that set a
  CA trust path **[doc, high confidence]**, so the key name alone is the assertion. No line anchor
  is used: the rules compile without `re.MULTILINE`, so `^` would only ever match the top of the
  file. `primitive="unknown"` is deliberate - a trust store is not a cryptographic primitive, and
  `RULE-UNKNOWN -> manual review` is the correct destination. Note one measured side effect:
  `_refine_uses` saw "certificate" inside the *value* `ca-certificates.crt` and set
  `uses="signing"` on this finding. That is a false use-context derived from a file path, and it
  is a bug in `_refine_uses`, not in this rule (E5).
* **P-53/54 `CFG-CIPHER`.** `'cipher' => 'AES-256-CBC'` is the Symfony/Laravel session-cipher
  setting **[doc]**. Requiring the quoted `cipher` key *and* the `=>` pins this to a configuration
  array and keeps it out of prose, and the `(?![-_]?ecb)` lookahead on the first rule makes the two
  mutually exclusive, so ECB is reported once, by the rule that means it. `evidence="configured"`
  is declared rather than `discovered` because `_match_rules` only ever *downgrades*
  `discovered -> configured` for config-extension files; it never upgrades, so the claim stays
  correct for `config/app.php`, which is a `.php` source file by extension and configuration by
  content. That mismatch between extension and content is a real limitation of extension-based
  routing, and it is the honest reason for the choice.

---

## 4. Reachability samples (required by F6)

Add these to the `samples` dict in `tests/test_scanner.py`, which asserts set equality with
`{r["id"] for r in RULES}`. All 54 were executed; every one fires its own rule.

```python
"IM-SRC-PHP-SYM-001": "$c = openssl_encrypt($data, $cipher, $key);",
"IM-SRC-PHP-AES-ECB-001": "$c = openssl_encrypt($d, 'aes-256-ecb', $k, 0, $iv);",
"IM-SRC-PHP-AES-UPPER-001": "$c = openssl_encrypt($d, 'AES-256-CBC', $k, 0, $iv);",
"IM-SRC-PHP-AES-AEAD-001": "$c = openssl_encrypt($d, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv);",
"IM-SRC-PHP-AES-OTHER-001": "$c = openssl_encrypt($d, 'aes-128-ofb', $k);",
"IM-SRC-PHP-CHACHA-001": "$c = openssl_encrypt($d, 'chacha20-poly1305', $k, 0, $n);",
"IM-SRC-PHP-IV-001": "$n = openssl_cipher_iv_length('aes-256-gcm');",
"IM-SRC-PHP-3DES-001": "$c = openssl_encrypt($d, 'des-ede3-cbc', $k);",
"IM-SRC-PHP-LEGACY-001": "$c = openssl_encrypt($d, 'bf-cbc', $k);",
"IM-SRC-PHP-RC4-001": "$c = openssl_encrypt($d, 'rc4', $k);",
"IM-SRC-PHP-PKCS7-RC2-001": "$p = openssl_pkcs7_encrypt($f, $crt, $pub, 0, OPENSSL_CIPHER_RC2_40_CBC);",
"IM-SRC-PHP-RC4-002": "$p = openssl_pkcs7_encrypt($f, $crt, $pub, 0, OPENSSL_CIPHER_RC4);",
"IM-SRC-PHP-PKCS7-ENC-001": "$p = openssl_pkcs7_encrypt($f, $crt, $pub);",
"IM-SRC-PHP-PKCS7-SIG-001": "$p = openssl_pkcs7_sign($d, $crt, $key, $h);",
"IM-SRC-PHP-CSR-001": "$csr = openssl_csr_sign($csr, $key, 365, $opts);",
"IM-SRC-PHP-RSA-PKE-001": "openssl_public_encrypt($d, $out, $pub);",
"IM-SRC-PHP-RSA-SIG-001": "openssl_sign($d, $sig, $key, OPENSSL_ALGO_SHA256);",
"IM-SRC-PHP-SHA1-SIGALG-001": "openssl_sign($d, $sig, $key, OPENSSL_ALGO_SHA1);",
"IM-SRC-PHP-SIGN-DEFAULT-001": "openssl_sign($data, $signature, $privKey);",
"IM-SRC-PHP-SHA2-SIGALG-001": "openssl_verify($d, $sig, $pub, OPENSSL_ALGO_SHA512);",
"IM-SRC-PHP-RSA-KEYGEN-001": "$k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);",
"IM-SRC-PHP-DSA-KEYGEN-001": "$k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_DSA]);",
"IM-SRC-PHP-DH-KEYGEN-001": "$k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_DH]);",
"IM-SRC-PHP-HASH-SHA2-001": "$h = hash('sha256', $password);",
"IM-SRC-PHP-HASH-SHA1-001": "$h = hash('sha1', $data);",
"IM-SRC-PHP-HASH-MD5-001": "$h = hash('md5', $file);",
"IM-SRC-PHP-MAC-001": "$t = hash_hmac('sha256', $data, $key);",
"IM-SRC-PHP-KDF-PBKDF2-001": "$k = hash_pbkdf2('sha256', $p, $s, 100000);",
"IM-SRC-PHP-KDF-HKDF-001": "$k = hash_hkdf('sha256', $ikm, 32);",
"IM-SRC-PHP-PWD-ARGON2-001": "$h = password_hash($p, PASSWORD_ARGON2ID);",
"IM-SRC-PHP-PWD-DEFAULT-001": "$h = password_hash($p);",
"IM-SRC-PHP-PWD-INFO-001": "$i = password_get_info($hash);",
"IM-SRC-PHP-DIGESTALG-SHA1-001": "$csr = openssl_csr_new($dn, $k, ['digest_alg' => 'sha1']);",
"IM-SRC-PHP-DIGESTALG-SHA2-001": "$csr = openssl_csr_new($dn, $k, ['digest_alg' => 'sha256']);",
"IM-SRC-PHP-SODIUM-SECRETBOX-001": "$c = sodium_crypto_secretbox($m, $n, $k);",
"IM-SRC-PHP-SODIUM-AEAD-AES-001": "$c = sodium_crypto_aead_aes256gcm_encrypt($m, $ad, $n, $k);",
"IM-SRC-PHP-SODIUM-AEAD-CHACHA-001": "$c = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($m, $ad, $n, $k);",
"IM-SRC-PHP-SODIUM-BOX-001": "$c = sodium_crypto_box_seal($m, $pk);",
"IM-SRC-PHP-SODIUM-BOXKEY-001": "$kp = sodium_crypto_box_keypair();",
"IM-SRC-PHP-SODIUM-SIGN-001": "$sig = sodium_crypto_sign_detached($m, $sk);",
"IM-SRC-PHP-SODIUM-SIGNKEY-001": "$kp = sodium_crypto_sign_keypair();",
"IM-SRC-PHP-SODIUM-KX-001": "$r = sodium_crypto_kx_client_session_keys($pk, $sk);",
"IM-SRC-PHP-SODIUM-AUTH-001": "$t = sodium_crypto_auth($m, $k);",
"IM-SRC-PHP-SODIUM-GHASH-001": "$h = sodium_crypto_generichash($m);",
"IM-SRC-PHP-SODIUM-GMAC-001": "$t = sodium_crypto_generichash($m, $k);",
"IM-SRC-PHP-SODIUM-PWHASH-001": "$h = sodium_crypto_pwhash(32, $p);",
"IM-SRC-PHP-RNG-001": "$b = random_bytes(32);",
"IM-SRC-PHP-RNG-OPENSSL-001": "$b = openssl_random_pseudo_bytes(32, $strong);",
"IM-SRC-PHP-WEAKRNG-MT-001": "$n = mt_rand(1000, 9999);",
"IM-SRC-PHP-WEAKRNG-RAND-001": "$n = rand(1, 6);",
"IM-SRC-PHP-WEAKRNG-WEAK-001": "$id = uniqid('req_', true);",
"IM-CFG-PHP-CA-001": "openssl.cafile = /etc/ssl/certs/ca-certificates.crt",
"IM-SRC-PHP-CFG-CIPHER-001": "    'cipher' => 'AES-256-CBC',",
"IM-SRC-PHP-CFG-CIPHER-ECB-001": "    'cipher' => 'AES-256-ECB',",
```

---

## 5. Declined, and already covered - with reasons

Declining is a design decision and each of these is one.

| API considered | Decision | Reason |
|---|---|---|
| `openssl_x509_read/parse/export/check_private_key`, `openssl_x509_verify` | **DECLINE** | `engine/certificates.py` (75 KB, 42 tests) already parses X.509 properly. A regex that "detects" `openssl_x509_parse` would duplicate a real parser with a worse one. |
| `openssl_pkcs12_read/export/parse` | **DECLINE, gap recorded** | PKCS#12 is a *key container*; the certificate sensor handles PEM/DER, not PKCS#12. A `primitive="unknown"` rule would route to manual review without adding information. A gap in the certificate sensor, not in the rule table. |
| `openssl_csr_new` | **DECLINE** | It takes an already-generated `$privkey`; key generation is caught by P-32 and the signature by P-31, so a rule here would be a third finding for one statement (F1). Its `digest_alg` option *is* covered, by P-22. |
| `openssl_seal` / `openssl_open` as a separate rule | **MERGED into P-27** | Same primitive, same `name`; the merge is what F1 requires. |
| An `OPENSSL_KEYTYPE_EC` key-generation rule | **DECLINE** | `IM-SRC-ECC-001` already matches the curve literal `prime256v1`/`secp256r1`/... in the same options array, so a new rule would produce a second component named `ECC` for one statement. The only uncovered form is `OPENSSL_KEYTYPE_EC` with no `curve` key, which is not worth a duplicate. See also the note in section 10 about how the engine rewrites any `name="ECC"` finding. |
| `sha1($x)`, `md5($x)` (the bare PHP functions) | **NO NEW RULE** | Already matched by `IM-SRC-SHA1-001` (`sha1\(`) and `IM-SRC-MD5-001` (`\bmd5\(`). Verified by reading those regexes. |
| `openssl_get_cipher_methods()`, `openssl_get_md_methods()` | **DECLINE** | These are *capability enumeration*. Reporting them as algorithm use would claim a use the code does not make. The engine has an `ASSURANCE_CAPABILITY` concept, but a source rule cannot express it. |
| `hash_equals()` | **DECLINE** | Not a primitive. Evidence that the author cared about comparison is not an algorithm claim. |
| `openssl_cipher_key_length()` | **DECLINE** | Removed in PHP 8.0 **[doc, high confidence]**. A rule for a function that cannot be called on any supported version is dead weight. |
| `mcrypt_*` | **DECLINE** | Removed from PHP 7.2 **[doc, high confidence]**. Same reasoning as `openssl_cipher_key_length`. |
| `php.ini` `ssl.cipher_list` / `openssl.cipher_list` | **DECLINE - uncertain** | I could not establish that either key exists. `openssl.cafile`/`capath` I am confident about. A guessed ini key produces a rule that never fires. |
| Apache `SSLOpenSSLConfCmd CipherString ...`, `SSLCipherSuite ...` | **DECLINE** | `IM-CFG-LEGACY-001` already covers the legacy suite names in config files, and a second rule would double-report (F1). A non-legacy `SSLCipherSuite` line is TLS configuration, not an algorithm. |
| WordPress `AUTH_KEY`, Laravel `APP_KEY`, `DB_PASSWORD` | **DECLINE - and a disclosure note** | These are *secrets*, not algorithms. `.env` is already in `CREDENTIAL_STORE_NAMES` and is never read (`fspolicy.py:27`), but **`wp-config.php`, `config/credentials.yml.enc` and `secrets/*.pem` are not on that list**, and would be read with their key material placed in an evidence snippet. An `fspolicy` gap, not a rule-table gap: E8. |
| phpseclib (`phpseclib\Crypt\RSA`, `…\AES`, `…\Random`) | **DEFERRED - section 9** | Very widely used, but I cannot check its API surface from here, and a rule built on a guessed class name is exactly what `test_every_rule_is_actually_executed` exists to catch. |
| defuse/php-encryption (`Defuse\Crypto\Crypto::encrypt`) | **DEFERRED - section 9** | Same reason. Its cipher is selected by a class constant, which is the pattern this pack handles well, so it is a good candidate once the constant names are confirmed. |
| laminas/laminas-crypt, symfony/password-hasher | **DEFERRED - section 9** | Same reason. |
| `sodium_crypto_aead_aegis256_*` | **DECLINE - uncertain** | I could not establish the PHP function spelling or the PHP version that exposed it. |
| `Sodium\Crypto` / `ParagonIE_Sodium_Compat` polyfill classes | **DEFERRED** | Real; listed in section 9 rather than guessed at here. |
| Cross-language bleed: any rule matching a bare `cipher:` YAML key or a bare `sha256(` in a non-PHP file | **AVOIDED BY DESIGN** | Every anchor in this pack is either a PHP-reserved spelling (`openssl_`, `sodium_`, `PASSWORD_`, `OPENSSL_`, `OPENSSL_ALGO_`, `OPENSSL_CIPHER_`) or carries a no-receiver guard. Measured cross-table collisions: zero, in both directions. That is a property of these 54 regexes, not of the engine - E10 proposes the durable fix. |

---

## 6. Adversarial decoys

Three decoys per language were required. These are the PHP three, all executed against the pack.
D1 is built so that a naive `aes-\d+` string rule fires five times; D2 found a real preprocessing
bug; D3 is a capability/introspection call.

### D1 - prose, a docstring and a string that quotes an entire migration note

```php
<?php
// The old vault used AES-256-CBC and RSA-2048; both move to PQC in 2027.
$releaseNotes = "rotate openssl_encrypt() away from 'AES-256-CBC' to 'AES-256-GCM'";
/* historic: hash('sha1', $pw) and md5($file) were used before 2019 */
class CryptoHelper { public function sha256Hex(string $s): string { return $s; } }
$available = openssl_get_cipher_methods();
$out = openssl_error_string();
$LOGGER->info("cipher rotation complete, see the runbook for AES-256-GCM");
```

**Measured: zero findings from this pack.** Why each rule abstains: P-05 needs `openssl_encrypt(`
*followed by* a quoted `AES-...` before the first `)`, and the prose has `openssl_encrypt()` with
the parenthesis immediately closed, so `[^)]*` has nothing to cross; P-03 and P-04 need the same
call; P-01 needs a `$` in argument 2. P-13/14/15 need `hash(` - the only occurrences are inside a
`/* ... */` block, which `_strip_comments` blanks. `sha256Hex(` is not a rule token.
`openssl_get_cipher_methods()` and `openssl_error_string()` are declined in section 5.

### D2 - the PHP `#` comment, which found a real bug

```php
<?php
# openssl_encrypt($data, 'AES-256-CBC', $key);
$doc = "call random_bytes(16) for tokens";
```

**Measured: two false positives - `IM-SRC-PHP-AES-UPPER-001` and `IM-SRC-PHP-RNG-001`.** The
second comes from the *string* on line 2, not from the comment, which shows the rules are right and
the *preprocessing* is missing: `_strip_comments` applies `#` handling only when the path ends
`.py`/`.pyw` (`scanner.py:387-389`), and `#` is PHP's most common comment style. The `//` and
`/* */` forms in D1 were blanked correctly, so the gap is specific and narrow.

There is no rule-level fix. E1 is the cheapest correct one: a `.php`/`.phtml`/`.rb` branch in
`_strip_comments` that blanks `#` to end of line **except** after `#[` (PHP 8 attribute), inside
`#{...}` (Ruby interpolation) or `?#` (Ruby character literal), and inside a Ruby
`=begin`/`=end` block. Every one of those exclusions is a place where naive `#` blanking corrupts
real code, which is why I am proposing the change rather than making it.

### D3 - capability enumeration, an error call and an unrelated `array_rand`

```php
<?php
$available = openssl_get_cipher_methods();
$in = in_array('aes-256-gcm', $available, true);
$out = openssl_error_string();
$rows = array_rand($options, 3);
```

**Measured: one finding - `IM-SRC-PHP-WEAKRNG-WEAK-001` on `array_rand(`, and it is correct.**
`openssl_get_cipher_methods()` is declined in section 5 because it enumerates rather than uses.
`array_rand` *is* entropy-hostile by the rule's definition and a static analyser cannot prove the
array is a deck of cards; flagging it is the same position `tests/fixtures/decoys/decoy_source.py`
takes when it says a `hashlib.sha256` cache key "is content addressing and cache-key use rather
than a security use - a static scanner cannot prove that from the call alone - flagging them is
correct; judging their purpose is a review step, not a detection step."

### Non-decoys: real calls a static analyser must not judge

| line | why it is reported anyway |
|---|---|
| `$etag = hash('sha256', $path);` | content addressing, not security - indistinguishable from a password hash at the call site |
| `$n = mt_rand(1000, 9999);` | a four-digit display code, not a token - and still the rule's whole point |
| `$rows = array_rand($options, 3);` | picking a UI option, not key material |
| `$h = password_hash($p);` | the algorithm is `PASSWORD_DEFAULT` and version-dependent, so the family is all we can assert |

---

## 7. Cross-table collisions with the shipped rules

**Measured: the PHP pack produces zero cross-table collisions.** I ran all 54 rules together with
the 34 shipped ones over every positive sample and grouped findings by `(name, line)`; nothing was
claimed by two different owners. Two collisions were found during development and designed out:

* **`IM-SRC-PHP-AES-UPPER-001` vs `IM-SRC-SSH-CIPHER-001`.** These would collide on
  `'aes-256-cbc'` if the PHP rule were case-insensitive. Resolved by making case the discriminator
  (P-05), not by a negative lookahead - a lookahead cannot know what another rule will claim.
* **`IM-SRC-PHP-3DES-001` / `-LEGACY-001` vs `IM-SRC-SSH-LEGACY-001`.** Resolved with
  per-alternative `(?!-cbc)` guards naming exactly the tokens the SSH rule owns.

One conditional conflict remains. If the team takes **PREREQ-1** - make `IM-SRC-SSH-CIPHER-001`
case-insensitive and widen its mode list, which is the better long-term design - then
`IM-SRC-PHP-AES-UPPER-001` becomes redundant *and* colliding and must be dropped. It is the only
rule whose status depends on a prerequisite.

### 7.1 One behaviour of the engine these rules must live with

`_match_rules` rewrites `name`/`primitive` for any finding whose `name` is `ECC` or `ECDH`:

```python
if name == "ECC":
    if uses == "tls":  name, primitive = "ECDH", "key-agreement"
    else:               name, primitive = "ECC", "unknown"
```

No PHP rule in this pack emits `name="ECC"`, so nothing here is affected. It is recorded because
the obvious PHP rule - `OPENSSL_KEYTYPE_EC` key generation - would have been, and because the
rewrite means such a rule's declared `primitive` is only a placeholder. That, plus the
duplicate-component problem in section 5, is why the EC key-generation rule is declined.

---

## 8. Ambiguity register - what each rule asserts, and what it declines

"Assert" means the rule states it as fact in `name`/`primitive`. "Decline" means the finding exists
but the unresolvable part is left unsaid, usually so `engine/purpose.py` reports `unresolved` and a
human decides.

### A1 - `openssl_pkey_new` for an RSA key: family certain, purpose not

The `OPENSSL_KEYTYPE_RSA` constant settles the algorithm beyond doubt. It does not settle what the
key is *for*: an RSA key signs and encrypts, and nothing in the call says which.

* **Assert:** `name="RSA"`, `key_length` from `private_key_bits`.
* **Decline:** the primitive. The rule emits `primitive="unknown"`, following the precedent the
  engine set for a bare curve object (`scanner.py:483-491`, "the OPERATION is left UNSTATED").
* **Measured consequence, and it is bad:** the recommender still says **ML-KEM-768**, because
  `_normalise_primitive` falls back to the *name* and maps anything containing "RSA" to `pke`
  (`recommender.py:183`), and because `resolve_purpose` returns an *empty* signal list so the
  refusal branch never fires. Choosing `primitive="pke"` instead at least publishes
  `nistQuantumSecurityLevel: 0`, which `unknown` omits. **My recommendation is therefore
  `primitive="pke"` plus E2, not `unknown`** - the `unknown` looks safer and is not, because of the
  name fallback. The table says `unknown` because that is what I measured; I am flagging the
  reversal rather than quietly making it.
* **Resolve it by:** the call that consumes the key, or a certificate KeyUsage extension.
* **Contrast:** the DSA and DH keygen rules (P-33/P-34) *do* assert a primitive, and legitimately -
  DSA cannot encrypt and a DH key exists only to agree a key, so for those two families generation
  alone settles the purpose. The ambiguity is RSA's alone.

### A2 - `openssl_encrypt($d, $cipher, $k)`: existence certain, algorithm absent

* **Assert:** that PHP symmetric encryption is in use. `name="OPENSSL-SYM"`,
  `primitive="block-cipher"`, `uses="at-rest"`.
* **Decline:** algorithm, key size and mode. All three live in a variable.
* **Why this shape:** `mosca` rates it `not-affected`, which is *correct* - a symmetric cipher is
  not a Shor target - and `cbom` omits `nistQuantumSecurityLevel` rather than inventing one. The
  recommender's `RULE-SYM-UNKNOWN -> "Confirm key size (inventory gap)"` branch is the correct
  destination. Calling it `AES` would be the tempting lie and is refused.
* **Resolve it by:** the assignment or constant that defines `$cipher`.

### A3 - `openssl_sign($data, $sig, $key)` with three arguments

* **Assert:** a signature exists (`primitive="signature"`, `name="RSA"`), **and** that its digest
  is SHA-1 (a second finding, `name="SHA1"`, `primitive="hash"`), because the fourth parameter
  defaults to `OPENSSL_ALGO_SHA1` **[doc, high confidence]**.
* **Decline:** nothing. This is the rare case where the *absence* of an argument is the evidence.
* **Why two findings are correct here:** they are two different assets - a signature scheme and a
  digest - and the engine's model is one component per finding. They do not inflate a count, they
  describe a signature. Contrast with F1, where two rules describing the *same* asset under the
  same `name` do inflate.
* **Uncertainty:** I could not execute PHP to confirm the default. The rule is only as good as that
  default, so this is the one rule in the pack I would want a maintainer to confirm against the
  manual for their supported PHP versions before shipping. It is also the highest-value rule in the
  pack: an implicit SHA-1 signature is invisible to every other rule here *and* to the existing
  table.

### A4 - `openssl_public_encrypt($d, $out, $pub, OPENSSL_PKCS1_PADDING)`

* **Assert:** `name="RSA"`, `primitive="pke"`, `uses="at-rest"`. Key transport is what the function
  does.
* **Decline:** the padding. This is a deliberate refusal, and the reason is F1 plus precedent: the
  engine already fixed a bug where one identifier was reported under two rules for the same line
  (`scanner.py:127-130`), and emitting a second "RSA" component for the same call to carry the
  padding would repeat exactly that.
* **Padding is a classical defect, not a quantum one.** PKCS#1 v1.5 encryption is the
  Bleichenbacher/Manger oracle, which has nothing to do with a CRQC. It belongs in an advisory
  channel (E7), not in a quantum-migration CBOM. `_canonical_mode("pkcs1v15")` returns `"other"`
  (measured), so even with E3 the padding could not be published in the standard `mode` field.
* **Resolve it by:** the padding argument, as a separate finding if the team wants it.

### A5 - PKCS#7 and CSR: operation certain, algorithm family not - the one real compromise

`openssl_pkcs7_encrypt`, `openssl_pkcs7_sign` and `openssl_csr_sign` all take a certificate or a
key as a parameter. Nothing in the call says whether that key is RSA or EC, and PHP's
`openssl_pkcs7_*` functions accept either **[doc]**.

Option 1 - name it `PKCS7`, `primitive="unknown"`. **Measured:** `mosca` -> `not-affected`,
`nistQuantumSecurityLevel` omitted, recommendation "Manual review required". A CMS signature is
then published as quantum-safe. That is the false-assurance class `mosca.py:125-150` was rewritten
to eliminate, and I will not ship it.

Option 2 - name it `RSA`. **Measured:** `broken-by-Shor`, level 0, recommendation ML-DSA-44/65.
If the key was EC the algorithm *label* is wrong while the *advice* is right and the exposure is
real.

**I recommend option 2, and I flag it as the least comfortable assertion in the pack.** The reason
it is still right: a wrong family name in a CBOM is a correctable data-quality error a reviewer
can see, whereas a `not-affected` verdict on a live signing key is a silent miss. The finding keeps
the literal `match` text, so the reviewer can see what was actually called. The third option -
`name="RSA"` with `primitive="unknown"` - combines Option 1's silence with Option 2's label and is
strictly worse than either.

* **Resolve it by:** the certificate's `publicKeyAlgorithm`, which `engine/certificates.py` already
  parses. A future cross-sensor rule could type these findings from the certificate instead of from
  the call site; that is the correct fix and it is out of scope for a regex table.

### A6 - AES in ECB mode

* **Assert:** AES, the key size, and that the mode is ECB - carried as `primitive="block-cipher"`,
  which is what ECB actually is, since it provides no authentication.
* **Decline:** any quantum claim. **Measured:** the finding is rated `weakened-by-Grover` and the
  recommendation is "No migration required", which is true and useless.
* **This rule exists to be read by a human**, and today the mode survives only in the `rule_id`.
  E3 makes it appear in `algorithmProperties.mode: "ecb"` (measured: `_canonical_mode("ecb")` is
  `"ecb"`) and in `resolve_purpose`'s blob. Without E3 I would still keep the rule - the `rule_id` is
  auditable - but I would not describe it as actionable.
* **F1 note:** P-02 and P-05 both emit `name="AES"`, so if the `ecb` lookahead were ever relaxed,
  `'AES-256-ECB'` would produce two components. It is not relaxed, and the measured duplicate check
  is clean.

### A7 - `mt_rand` / `rand` / `uniqid`: a serious defect with no quantum dimension

* **Assert:** that a non-cryptographic PRNG is in use (`primitive="drbg"`, `name` naming which one).
* **Decline:** any claim that this is a quantum-migration item. Measured: `not-affected`, and the
  recommendation is "Manual review required" because `_normalise_primitive("drbg")` has no entry
  and the names contain no needle.
* **Honest framing:** reporting `mt_rand` in a session-token generator as "not affected" is
  technically true and operationally dangerous. These rules are in the pack because the brief asks
  for them and because a CSPRNG inventory is useless without its inverse, but they need E7 before
  anyone puts them in front of an operator. I would rather ship them labelled than not ship them.

### A8 - `password_hash($p)` with no algorithm argument

* **Assert:** that password hashing is in use, and that the algorithm is the platform default.
* **Decline:** the algorithm name. `PASSWORD_DEFAULT` is bcrypt in current PHP **[doc]** but is
  version-dependent by design, so the `name` is the family `PASSWORD-HASH`. Naming it `bcrypt`
  would be a claim about a version, not about the code.
* **Resolve it by:** `password_get_info()` on a real hash, which is P-21 - so the two rules together
  answer the question without either over-claiming.

---

## 9. Uncertainty register and deferred work

Everything I am not certain about, stated as such rather than asserted.

| claim | confidence | how to settle it |
|---|---|---|
| `openssl_sign()` / `openssl_verify()` default to `OPENSSL_ALGO_SHA1` | **high**, from documentation; not executed | read the `openssl_sign` manual page for each supported PHP version. If wrong, P-25 is the only rule affected. |
| `openssl_pkcs7_encrypt()` defaults to `OPENSSL_CIPHER_RC2_40_CBC` | **high**, from documentation; not executed | read the `openssl_pkcs7_encrypt` manual page. If wrong, P-11 still catches the explicit case. |
| `sodium_crypto_secretbox` is XSalsa20-Poly1305 with a 32-byte key | high | libsodium docs; stable for many years. |
| `sodium_crypto_sign*` is Ed25519 only | high | libsodium docs; the API has no algorithm parameter. |
| `sodium_crypto_box*` is X25519-XSalsa20-Poly1305 | high | libsodium docs. |
| `sodium_crypto_kx_*` exists in PHP, and from which version | **medium** - I believe PHP 8.1, unverified | `php --re libsodium` or the `sodium_crypto_kx_client_session_keys` manual page. If the name is wrong, P-42 is simply dead and the reachability test will say so. |
| `sodium_crypto_aead_aegis256_*` naming and availability | **low** - deliberately omitted | libsodium 1.0.19+ and the PHP ext version table. |
| `openssl.cafile` / `openssl.capath` are php.ini keys | high | the `openssl` INI page. |
| `ssl.cipher_list` / `openssl.cipher_list` exist | **low** - rule declined | the `openssl` INI page. |
| `'cipher' => 'AES-256-CBC'` is the Laravel/Symfony session cipher key | high | `config/app.php` in any Laravel app; also used by Magento's `app/etc/env.php` under a `crypt` key, which I have **not** verified. |
| PHP `#` is a comment in all supported versions | high | language reference; the PHP 8 `#[Attribute]` syntax is the only conflict and E1 excludes it. |
| phpseclib / defuse / laminas / symfony-password-hasher APIs | **none - deferred** | read the gem/package source. Candidate shapes, for whoever picks this up: `phpseclib\Crypt\RSA::createKey(\|LOCK_RSA\|)` and `->setEncryptionMode(\|CRYPT_RSA_MODE_OAEP\|)` for RSA; `Defuse\Crypto\Crypto::encrypt($plaintext, $key)` with the cipher chosen by a `Crypto::CIPHER_AES256_CBC`-style constant for defuse. Note that phpseclib 3 moved to `\phpseclib3\Crypt\RSA`, so a rule must cover both vendor prefixes. |
| `ParagonIE_Sodium_Compat` / `Sodium\Crypto` polyfill class names | **low - deferred** | the package source. |
| Whether the pack's rules can be restricted to PHP file extensions | n/a | E10. Today they rely on PHP-reserved spellings; measured zero collisions, but that is a property of these regexes and not of the engine. |

---

## 10. Required engine changes - none of these are applied

Ranked by how much damage they do if left undone. All are additive and none requires changing an
existing rule's *meaning*.

| id | change | why it is needed | evidence |
|---|---|---|---|
| **PREREQ-1** | Either (a) make `IM-SRC-SSH-CIPHER-001` case-insensitive and widen its mode list to `cfb\|ofb\|xts\|ccm\|ocb\|eax\|siv`, or (b) keep it as it is. **If (a), drop `IM-SRC-PHP-AES-UPPER-001`.** | (a) is the better design - one rule should own quoted OpenSSL cipher strings regardless of case, and the SSH rules should never have been language-agnostic. (b) is zero-risk. Choosing (a) without dropping the PHP rule double-counts every upper-case literal. | F2, section 7 |
| **E1** | Extend `_strip_comments` to blank `#` comments for `.php`, `.phtml`, `.inc`, `.module`, `.rb`, `.rake`, `.gemspec`, excluding `#[` (PHP 8 attribute), `#{...}` and `?#` (Ruby), and `=begin`/`=end` blocks. | **Largest measured false-positive source in both packs.** `#` is the dominant comment style in both languages and is currently only handled for `.py`. | F4, D2 (measured: 2 FPs in a 2-line file) |
| **E2** | Add `openssl_keytype_rsa`, `openssl_pkey_new`, `pkey::rsa.generate`, `pkey::rsa.new` to the UNRESOLVED needle tuple in `purpose.py`, alongside the existing `rsa_new`. | The recommender only declines to name a target when `bool(purpose_signals)`. A bare key generator currently produces an **empty** signal list, so `openssl_pkey_new(... OPENSSL_KEYTYPE_RSA ...)` is confidently told to migrate to ML-KEM even if the key only ever signs. The existing `rsa_new` token does not match a dotted spelling. | section 1, A1 (measured) |
| **E3** | One line in `_match_rules`: `if rule.get("mode"): finding["mode"] = rule["mode"]`. Optionally add a `mode` key to the rule dict. | `cbom.py:369-372` already reads `finding["mode"]` and `_canonical_mode` already maps `gcm cbc ecb ccm cfb ofb ctr`. Without this, "this was ECB" survives only in a field no consumer reads, and an ECB finding is reported as "No migration required". | F5, A6 (measured) |
| **E4** | Decide whether `kdf` and `key-derive` belong in the Shor-broken list at `cbom.py:238-240`. **Recommendation: remove them.** | Measured: a PBKDF2 finding emits `nistQuantumSecurityLevel: 0` ("a CRQC breaks this") in the same row where `mosca` says `not-affected`. PBKDF2, Argon2id, scrypt and bcrypt are not Shor targets. This is the self-contradiction class `cbom.py:200-214` says was fixed. | section 1 (measured) |
| **E5** | Tighten `_refine_uses` so that `certificate` / `sign(` in the matched *value* cannot set `uses`. | Measured: `openssl.cafile = /etc/ssl/certs/ca-certificates.crt` produced `uses="signing"` because the path contains "certificate". | P-52 (measured) |
| **E6** | Optional: a `fixed_key_bits` key on rules, so an algorithm whose key size is fixed by construction (libsodium secretbox, box, sign, AEAD) can publish it. | These findings currently land in the recommender's "Confirm key size (inventory gap)" branch even though the size is known by definition - 32 bytes. | P-35 (measured) |
| **E7** | Optional, but the pack is weak without it: an advisory channel for classical-but-not-quantum defects (ECB mode, PKCS#1 v1.5 padding, MT19937, `null` ciphers). A minimal version is a `severity` or `advisory` key on the rule plus an `im:`-namespaced property, which is this project's existing convention for data the standard has no slot for. | Measured: every one of these findings is routed to `RULE-UNKNOWN -> "Manual review required"` and rated `not-affected`. Detection-complete and action-invisible is a poor place to stop, and the honest thing is to say so rather than let the CBOM imply "fine". | A4, A6, A7 (measured) |
| **E8** | Add `wp-config.php`, `credentials.yml.enc`, `secrets.yml`, and a `*.pem`-not-`id_*` rule to `CREDENTIAL_STORE_NAMES`. | These files hold key material and are not on the list, so they are read and any rule match lands in an evidence snippet. Found while doing this work; it is an `fspolicy` issue, not a rule-table issue. | `fspolicy.py:24-31`, section 5 |
| **E9** | Add a capture group to `IM-SRC-AES-001`'s `AES\.new\(` alternative, e.g. `AES\.new\(\s*(\d+)`. | That rule already declares `key_group=1` and a `key_map` but its `AES.new(` alternative has no group, so Ruby's `OpenSSL::Cipher::AES.new(256, :gcm)` is detected with `key_length=None`. A one-token fix; it is what makes the Ruby ctor rules withdrawable. | F3 (measured) |
| **E10** | Optional: an `extensions=` key on rules, so a pack rule can be restricted to `.php/.phtml/.inc` or `.rb/.rake/.gemspec`. | The durable fix for cross-language bleed. The pack does not need it today - measured zero collisions in both directions - but that is a property of these regexes, not of the engine. | section 5, section 7 |
| **E11** | Extend the recommender-totality test's primitive domain with `kdf`, `drbg`, `stream-cipher`. | The pack introduces those three primitive values and a fixed-domain property test would be asserting totality over a domain the engine no longer has. I am not editing tests; this is a required follow-up for whoever merges the pack. | `tests/test_properties.py:75-95` |

---

## 11. Validation plan

What I ran, and what the team should run before merging. All of it is reproducible from this
document; nothing here required modifying the repository.

**What I ran.** A throwaway harness outside the repo imported `engine.scanner`, replaced
`RULES` and `_COMPILED_RULES` **in memory** with the candidate pack, and called the real
`IndraMeshScanner._match_rules()` on each positive sample, each decoy, and a combined table. Results:

| check | result |
|---|---|
| every regex compiles | 54/54 |
| every rule fires on its own positive sample | 54/54 |
| two rules producing the same `(name, line)` within the pack | 0 |
| a decoy line producing a finding from this pack | 1 of 3 decoys, and that one finding is argued to be a true positive (D3) |
| a `(name, line)` claimed by both this pack and a shipped rule | 0 |
| `key_length` resolved from the capture | as tabulated in section 3 |

**What the team should add before merging** (tests, not engine):

1. The 54 samples in section 4 into `tests/test_scanner.py::samples`. Mandatory: the set-equality
   assertion at line 83 fails otherwise.
2. A `tests/fixtures/decoys/decoy_php.php` carrying D1, D2 and D3, asserting that only the
   documented D3 finding appears. Mirror the existing `decoy_source.py` structure, including its
   "NON-DECOY" section, so the intent of each line is recorded next to the assertion.
3. A differential test in the style of `test_differential.py::test_the_same_snippet_scanned_as_py_and_as_c_finds_the_same_algorithms`:
   a PHP snippet with no `//`, `/* */` or `#` must yield identical findings as `.php` and as `.rb`.
   That test is what pins the "no language-specific anchor" property and it will fail loudly if a
   future rule loses it.
4. A test asserting the F1 invariant directly: for every sample file, no `(name, line)` pair is
   produced by two different `rule_id`s. This is the check that would have caught the PSS and
   ECC/ECDH bugs the engine already fixed, generalised.
5. A mutation test per rule, in the style of `test_mutation_kills.py`: delete one capture group or
   one alternation branch and assert the reachability test fails. A rule whose regex can be
   mutilated without the suite noticing is a rule nobody is really testing.
6. Recall measurement on a real corpus, in the style of `benchmark/`: run the pack over a pinned
   checkout of a PHP framework (a Laravel app plus a Symfony component plus a phpseclib user) and
   label the findings by hand. **Until that exists, no recall number should be quoted for this
   pack** - the parameteriko figures in `benchmark/RESULTS.md` are the standard this project holds
   itself to, and a rule count is not a recall figure.

---

## 12. What was not verified, stated plainly

* **No PHP runtime was available.** Every regex was executed against the *scanner*, not against
  PHP. That verifies the regex matches the text I claim it matches; it does not verify that PHP
  code in the wild is written that way. Section 9 lists each behavioural claim separately with its
  confidence, because the two are different questions and only the first is answered.
* **No PHP corpus was scanned.** These rules have zero measured recall. Section 11 item 6 is the
  work that would give them one.
* **The vendor tier (phpseclib, defuse, laminas, symfony/password-hasher, sodium polyfills) has no
  regexes.** I would rather ship 54 verified rules and name 5 unverified gaps than 59 rules of which
  5 are guesses.
* **The recommended `primitive` for RSA key generation is self-contradictory in this document** and
  I have left the measured value in the table rather than the value I recommend. A1 explains both
  and E2 is what removes the contradiction.
* **The pack has no per-language gating**, so a non-PHP file containing the literal text
  `openssl_encrypt(` would be scanned by these rules. Measured collisions against real
  Java/JS/TS/C/Python corpora: none, because every anchor is a PHP-reserved spelling. That is a
  property of the regexes, not a guarantee from the engine, and E10 is the durable fix.
