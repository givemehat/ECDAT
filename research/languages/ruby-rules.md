# Ruby detection rule pack - design proposal

**Status: DESIGN ONLY. No engine file and no test was modified.** Every regex below was compiled
and executed against the real `engine/scanner.py` code paths (`_match_rules` ->
`_extract_key_size` -> `_refine_uses`) in a throwaway harness outside the repository. Every
result quoted as *measured* was observed, not predicted. Section 11 lists what was **not**
verified.

**Provenance.** Written from the Ruby standard library surface (`openssl`, `digest`,
`securerandom`, `active_support`, `bcrypt`) and from my own knowledge of those libraries, plus
direct reading of this repository's engine. No competitor project was fetched, read or referenced.
I had no Ruby runtime available, so claims about Ruby *behaviour* (as opposed to Ruby *spelling*)
are marked **[doc]** and listed with a confidence in section 9.

**Companion document:** `research/languages/php-rules.md`. Its sections 0 (F1-F7), 1, 7, 8, 10
and 11 apply unchanged here and are not restated. Where this document says "F4" or "E1" it means
the item of that name there.

---

## 0. What the shipped table already covers in Ruby - read this before adding anything

Ruby was not at zero coverage. Four of the things a naive Ruby rule pack would add are **already
detected today**, and adding rules for them would be pure duplication under F1. Verified by
reading the shipped regexes and confirmed by execution:

| Ruby construct | already matched by | consequence |
|---|---|---|
| `Ed25519::SigningKey`, `Ed25519::VerifyKey`, `Ed25519.generate_signing_key` | `IM-SRC-EDDSA-001`, whose regex contains `\bEd25519\b` | **no new Ed25519 rule needed.** The shipped rule already emits `name="Ed25519"`, `primitive="signature"`, which is correct. |
| `'prime256v1'`, `'secp256r1'`, `'secp384r1'`, `'secp521r1'`, `'secp256k1'` as bare curve literals | `IM-SRC-ECC-001`, whose regex lists those five spellings | **no new curve-literal rule needed.** The shipped rule even captures the curve and the engine maps it to a size (`scanner.py:479-482`). |
| `OpenSSL::Cipher.new('aes-256-cbc')` and friends | `IM-SRC-SSH-CIPHER-001` (lower-case `aesNNN-ctr/gcm/cbc` inside quotes) | the *literal* is already found, but with no key size and no evidence that it is used for encryption. That gap is what this pack closes - and it is closed by the **call-anchored** rules below, not by another literal rule. |
| `sha1(`, `md5(` | `IM-SRC-SHA1-001`, `IM-SRC-MD5-001` | not applicable to Ruby, since Ruby has no bare `sha1()` function, but it means the same-shaped PHP rules were correctly excluded from the PHP pack. |

A fifth, and the most important: **`IM-SRC-AES-001` already matches `OpenSSL::Cipher::AES.new(...)`**
and yields `key_length=None` (F3, measured). Two rules below are consequently marked WITHDRAWN.

---

## 1. Ruby's structural advantage, and the one place it does not help

Ruby crypto is namespaced (`OpenSSL::`, `Digest::`, `SecureRandom::`) rather than flat
(`openssl_`, `hash_hmac`). That is worth a great deal: a namespaced constant is a *reserved
spelling*, so a rule anchored on it cannot fire on an unrelated identifier in another language, and
it cannot fire on a user's own class named `Cipher`. Measured cross-table collisions for this pack:
**zero**, the same as the PHP pack, and for a stronger reason.

The exception is the *method* layer. `key.sign(digest, data)`, `key.verify(digest, sig, data)` and
`dh.compute_key(peer)` are bare method names on arbitrary receivers, and Ruby codebases are full
of non-cryptographic `sign`/`verify` methods (a contract object, a `Signup` form, a
`Signature` model). This is the Ruby analogue of the problem `scanner.py:78` already solved for
Python's `.exchange()` - "a bare `.exchange()` is far too common in ordinary Python to key off" -
and R-11 below uses the same remedy: require either an OpenSSL/Digest argument or a
key-shaped receiver.

---

## 2. Proposed rules

`kg` is `key_group`; `-` means `None`. Every regex is byte-for-byte the one that was compiled and
executed. Ruby is case-sensitive, so no rule here needs `(?i:)` except the YAML configuration rule,
which is deliberately case-insensitive because YAML keys are not code.

### 2.1 `OpenSSL::Cipher` - symmetric

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-RUBY-AES-AEAD-001 (withdrawn) | AES | ae | at-rest | 1 | `OpenSSL::Cipher::AES\.new\(\s*(128\|192\|256)\b\s*,\s*:(?:gcm\|ccm\|ocb\|eax\|siv)\b` |
| IM-SRC-RUBY-AES-BLOCK-001 (withdrawn) | AES | block-cipher | at-rest | 1 | `OpenSSL::Cipher::AES\.new\(\s*(128\|192\|256)\b\s*,\s*:(?:cbc\|ctr\|cfb\|ofb)\b\|OpenSSL::Cipher::AES\.new\(\s*(128\|192\|256)\s*\)` |
| IM-SRC-RUBY-AES-ECB-001 | AES | block-cipher | at-rest | 1 | `OpenSSL::Cipher::AES\.new\(\s*(\d+)\s*,\s*:ecb\b` |
| IM-SRC-RUBY-AES-LIT-ECB-001 | AES | block-cipher | at-rest | 1 | `OpenSSL::Cipher\.new\(\s*['"]\s*aes[-_]?(128\|192\|256)[-_]?ecb` |
| IM-SRC-RUBY-3DES-001 | 3DES | block-cipher | at-rest | - | `OpenSSL::Cipher::DES_EDE3\b` |
| IM-SRC-RUBY-LEGACY-001 | LEGACY-CIPHER | block-cipher | at-rest | - | `OpenSSL::Cipher::(?:DES\|BF\|CAST5\|IDEA\|RC2)\b` |
| IM-SRC-RUBY-RC4-001 | RC4 | stream-cipher | at-rest | - | `OpenSSL::Cipher::RC4\b` |
| IM-SRC-RUBY-NULL-001 | NULL-CIPHER | block-cipher | tls | - | `OpenSSL::Cipher::NullCipher\b` |
| IM-SRC-RUBY-CHACHA-001 | ChaCha20 | ae | at-rest | - | `OpenSSL::Cipher::ChaCha20\.new\s*(\|OpenSSL::Cipher\.new\(\s*['"]chacha20` |

**WITHDRAWN, and this is the pack's most important negative result.** R-01 and R-02 are the modern
idiomatic Ruby cipher form, `OpenSSL::Cipher::AES.new(256, :gcm)`. They work, they compile, they
resolve the key size correctly - and `IM-SRC-AES-001` already fires on the same text with the same
`name="AES"`. Measured: `CROSS AES line=1 ['IM-SRC-AES-001', 'PROPOSED']`. Under F1 that is two
CBOM components for one statement, which is the exact defect the engine fixed twice before.

Two ways out, and the team must pick one:

* **Recommended: E9.** Add a capture group to the `AES\.new\(` alternative of `IM-SRC-AES-001` -
  `AES\.new\(\s*(\d+)` - so the shipped rule resolves `key_length=256` instead of `None`, and
  **drop R-01 and R-02 entirely.** Cost: the shipped rule types every mode as `ae`, so a `:cbc`
  cipher is reported as AEAD. That is a real loss of precision, and it is the engine's existing
  behaviour rather than something this pack introduces.
* **Alternative: a cross-rule de-duplication in `_finalise`** - drop a finding when another finding
  on the same line carries the same `name` and a resolved `key_length`. This keeps R-01/R-02's mode
  typing, which is genuinely better, at the cost of a change to shared code that every existing
  rule passes through.

I recommend E9 for this merge and would revisit the mode typing afterwards, because a smaller
change to shared code is easier to review than a new de-duplication rule that could mask real
duplicates elsewhere.

Justifications for 2.1:

* **R-03 `AES-ECB` (constant form).** The `OpenSSL::Cipher::AES` constant *is* the algorithm, so the
  constant plus the `(\d+)` size plus the `:`-symbol mode is a complete assertion with no literal to
  confuse it with an SSH wire name; requiring the mode symbol to be exactly `ecb` also keeps it
  disjoint from the withdrawn R-02, which is why the two can coexist if the team takes the
  alternative path above.
* **R-04 `AES-LIT-ECB`.** The literal form of the same defect. Two rules rather than one because
  one needs a symbol and the other a string, and because F1 forbids merging them into a single id
  only if they could co-occur - here they cannot, so this is F1-compliant and unambiguous.
* **R-05 `3DES`.** `OpenSSL::Cipher::DES_EDE3` is the three-key Triple DES constant in Ruby's
  OpenSSL binding **[doc, high confidence]**; the constant name is the algorithm, so the bare
  constant with `\b` is the whole assertion.
* **R-06 `LEGACY`.** The remaining legacy cipher constants of the same family
  (`DES`, `BF` = Blowfish, `CAST5`, `IDEA`, `RC2`) **[doc]**. One rule rather than five because they
  share `name` and `primitive`; the alternation is anchored on `OpenSSL::Cipher::` so it cannot fire
  on a user's own `DES` constant. Note that `IM-SRC-SSH-LEGACY-001` owns the lower-case *strings*
  `des-cbc` and `3des-cbc`; the capitalised Ruby constants are a different spelling and do not
  collide with it (measured).
* **R-07 `RC4`.** Split from R-06 only because `rc4` is a stream cipher and the primitive must say
  so; the name is `RC4` rather than `LEGACY-CIPHER` because `mosca` has an `RC4` token and the
  operator should see which cipher it is.
* **R-08 `NULL`.** `OpenSSL::Cipher::NullCipher` is the export-grade null cipher - encryption with no
  authentication and no confidentiality **[doc]**. It gets its own name because calling it
  "LEGACY-CIPHER" would hide what it is, and `uses="tls"` because in practice it appears in
  `ciphers` lists. It is the Ruby equivalent of the `NULL-SHA` token `IM-CFG-LEGACY-001` already
  catches in configuration, and the same argument applies about the name: say what it is.
* **R-09 `CHACHA`.** `OpenSSL::Cipher::ChaCha20` is the ChaCha20 constant of the same binding, and
  the string form is the OpenSSL cipher name. `primitive="ae"` matches the shipped
  `IM-SRC-CHACHA-001`, which is deliberate consistency rather than a fresh decision. The
  alternation is safe under F1: the first branch needs the `ChaCha20` constant and the second needs
  a quoted `chacha20`, so they cannot both match one line.

### 2.2 `OpenSSL::PKey` - asymmetric

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-RUBY-RSA-NEW-001 | RSA | unknown | at-rest | 1 | `OpenSSL::PKey::RSA\.(?:new\|generate)\(\s*(\d+)` |
| IM-SRC-RUBY-RSA-PKE-001 | RSA | pke | at-rest | - | `(?:private_encrypt\|private_decrypt\|public_encrypt\|public_decrypt)\s*\(` |
| IM-SRC-RUBY-RSA-PSS-001 | RSA | signature | signing | - | `\.(?:sign\|verify)_pss\s*\(` |
| IM-SRC-RUBY-SIGN-001 | RSA | signature | signing | - | `(?:key\|priv\|private_key\|secret_key\|signer)\s*\.\s*(?:sign\|verify)\s*(\|\.\s*(?:sign\|verify)\s*\(\s*(?:OpenSSL::Digest\|Digest::)` |
| IM-SRC-RUBY-ECDH-001 | ECDH | key-agreement | tls | - | `\.dh_compute_key\s*\(` |
| IM-SRC-RUBY-DSA-001 | DSA | signature | signing | 1 | `OpenSSL::PKey::DSA\.(?:new\|generate)\(\s*(\d+)` |
| IM-SRC-RUBY-DH-001 | DH | key-agreement | tls | 1 | `OpenSSL::PKey::DH\.new\s*\(\s*(\d+)` |
| IM-SRC-RUBY-DH-COMPUTE-001 | DH | key-agreement | tls | - | `\.compute_key\s*\(` |
| IM-SRC-RUBY-PKCS7-001 | RSA | unknown | signing | - | `OpenSSL::PKCS7\.new\b` |

* **R-10 `RSA-NEW`.** `OpenSSL::PKey::RSA.new(2048)` and `RSA.generate(2048)` are the only two
  spellings, the class constant is the algorithm, and the argument is the modulus size, so the
  family and the size are both certain. `primitive="unknown"` because an RSA key generation settles
  nothing about purpose - and see A1 in the PHP document: **measured, this still gets ML-KEM-768
  named for it**, because `_normalise_primitive` falls back to the name and `purpose.py` has no
  token that matches a dotted `RSA.new`. E2 is the fix; until then this is a known false claim and
  the reason is recorded rather than hidden.
* **R-11 `SIGN`.** Two alternatives, and both are needed. The first requires a key-shaped receiver
  (`key`, `priv`, `private_key`, `secret_key`, `signer`); the second requires an OpenSSL or Digest
  argument. This is the same remedy `scanner.py:78` uses for Python's `.exchange()`, and without
  it the rule would fire on `contract.sign(party)`, `user.sign_up` and every `Signature` model in
  a Rails app. Under F1 the two alternatives are free: they can only both match if the receiver is
  key-shaped *and* the argument is a Digest, and in that case the first match consumes the
  `key.sign(` text and the second finds no `.sign(`.
  **This is the pack's least confident name**, because the receiver is not on the same line as the
  class that made it. A8.
* **R-12 `RSA-PKE`.** `private_encrypt`/`public_decrypt` (encrypt with the private key, decrypt with
  the public key) and `public_encrypt`/`private_decrypt` are Ruby's names for raw RSA, and they are
  the "pure" key-transport pattern. The method names are specific to `OpenSSL::PKey::RSA` in
  Ruby's binding **[doc]**, so a bare method name is safe here in a way `.sign` is not. Asserts
  `pke`; declines the padding, exactly as the PHP pack does in A4 - `PRIVATE_KEY_PKCS1_PADDING` and
  friends exist and are not matched, on purpose.
* **R-13 `RSA-PSS`.** `sign_pss`/`verify_pss` are RSASSA-PSS **[doc]** and exist only on
  `OpenSSL::PKey::RSA`, so the method name settles both the padding and the family. Distinct rule
  from R-11 because PSS is the *recommended* padding and deserves its own `rule_id` in a CBOM even
  though the `name` is the same. Note the purpose needle `signpss` in `purpose.py:38` does not match
  `sign_pss`, so this finding's purpose stays unresolved - harmless, because `primitive="signature"`
  is explicit and the recommender does not re-litigate an already-typed signature.
* **R-14 `ECDH`.** `OpenSSL::PKey::EC#dh_compute_key` is elliptic-curve Diffie-Hellman and nothing
  else in the binding defines that method name **[doc]**, so family *and* operation are both certain
  from the method name alone. This is the highest-precision rule in the Ruby pack: no receiver
  guard is needed because no other Ruby object has `dh_compute_key`.
* **R-15 `DSA`.** As in PHP: the class constant settles the family, DSA cannot encrypt, so its purpose
  is settled at `signature` and no `unknown` is needed. `OpenSSL::PKey::DSA` still exists in Ruby's
  openssl binding but is unavailable against OpenSSL 3 builds in some configurations **[uncertain]**
  - the rule costs nothing if the class is never instantiated.
* **R-16/17 `DH`.** Two rules because two operations. `DH.new(2048)` is parameter/key generation and
  the argument is the modulus size; `compute_key` is the shared-secret derivation. Splitting is
  F1-correct (different `primitive` evidence, same `name` and `primitive` value) and, more
  importantly, `compute_key` is the operation that proves the key is *used* for agreement.
* **R-18 `PKCS7`.** `OpenSSL::PKCS7` is Ruby's CMS binding. The **operation** is not determinable
  from `PKCS7.new` - the object is used for signing, enveloping or verification afterwards - so this
  rule emits `primitive="unknown"`. That is the one place in the Ruby pack where I accept a
  `not-affected` mosca verdict (measured) rather than assert a family, and A5 in the PHP document
  argues the opposite choice for PHP's PKCS#7 rules. The difference is deliberate and worth stating:
  in PHP the call *is* the operation (`openssl_pkcs7_sign` is a signature), whereas in Ruby
  `PKCS7.new` is a constructor, so PHP can assert and Ruby cannot.

### 2.3 Digests, MAC, KDF

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-RUBY-HMAC-001 | HMAC | mac | at-rest | - | `OpenSSL::HMAC\.(?:digest\|hexdigest)\s*(\|OpenSSL::HMAC\.new\s*\(` |
| IM-SRC-RUBY-DIGEST-SHA2-001 | SHA256 | hash | at-rest | - | `OpenSSL::Digest(?:\.new\|\[)\(\s*['"]SHA-?256['"]\|OpenSSL::Digest::SHA256\s*\.\|Digest::SHA256\s*\.\|OpenSSL::Digest\.digest\([^,]+,\s*['"]sha256['"]` |
| IM-SRC-RUBY-DIGEST-SHA1-001 | SHA1 | hash | at-rest | - | `OpenSSL::Digest(?:\.new\|\[)\(\s*['"]SHA-?1['"]\|OpenSSL::Digest::SHA1\s*\.\|Digest::SHA1\s*\.` |
| IM-SRC-RUBY-DIGEST-MD5-001 | MD5 | hash | at-rest | - | `OpenSSL::Digest(?:\.new\|\[)\(\s*['"]MD5['"]\|OpenSSL::Digest::MD5\s*\.\|Digest::MD5\s*\.` |
| IM-SRC-RUBY-PBKDF2-001 | PBKDF2 | kdf | at-rest | - | `OpenSSL::PKCS5\.pbkdf2_hmac\w*\s*\(` |
| IM-SRC-RUBY-BCRYPT-001 | bcrypt | kdf | at-rest | - | `BCrypt::Password\.(?:create\|from_hash)\|BCrypt::Engine\.hash_secret` |

* **R-19 `HMAC`.** `OpenSSL::HMAC.digest`/`.hexdigest`/`.new` are the only HMAC entry points in the
  binding, so the namespaced constant is the assertion. The `name="HMAC"` is correct here and would
  have been wrong in the PHP pack for libsodium's `crypto_auth`, which is a BLAKE2b MAC and not
  HMAC - a good illustration of why the name has to come from the API and not from the shape.
* **R-20/21/22 `DIGEST-*`.** Four alternative spellings each, because Ruby has three ways to say the
  same digest: the factory `OpenSSL::Digest.new('SHA256')` / `OpenSSL::Digest['SHA256']`, the
  per-algorithm constant `OpenSSL::Digest::SHA256`, and the plain `Digest::SHA256` class. The
  trailing `\s*\.` on the two constant forms is **load-bearing**: without it, a string or comment
  containing `Digest::SHA1` matches, which is exactly how my Ruby decoy D2 defeated the first
  version of R-21 (measured false positive, then fixed). `OpenSSL::Digest.digest(data, 'sha256')`
  is the two-argument class-method form and is included for completeness.
* **R-23 `PBKDF2`.** `OpenSSL::PKCS5.pbkdf2_hmac` and its `_sha1` sibling; the `\w*` covers the
  suffix so one rule covers both rather than two ids that could co-occur.
* **R-24 `BCRYPT`.** The `bcrypt` gem's two entry points **[doc]**. `name="bcrypt"` and
  `primitive="kdf"`: correct, and note that this is the one KDF rule in either pack whose finding is
  *also* correct about quantum exposure (see E4 - `primitive="kdf"` currently emits
  `nistQuantumSecurityLevel: 0`, which for bcrypt is defensible under Grover but should still be
  stated as a weakening rather than a break).

### 2.4 Randomness

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-RUBY-RANDOM-001 | CSPRNG | drbg | at-rest | - | `SecureRandom\.(?:random_bytes\|hex\|base64\|urlsafe_base64\|random_number\|uuid)\b` |
| IM-SRC-RUBY-RANDOM-OPENSSL-001 | CSPRNG | drbg | at-rest | - | `OpenSSL::Random\.random_bytes\s*\(` |
| IM-SRC-RUBY-WEAKRNG-001 | LIBC-RAND | drbg | at-rest | - | `(?<![.\w:])rand\s*(\|(?<![.\w:])srand\s*(\|\bRandom\.(?:rand\|new)\b\|\bRandom::DEFAULT\b` |

* **R-25 `SecureRandom`.** The class name plus the method list is the assertion, and enumerating the
  methods rather than matching `SecureRandom` alone is what keeps this a *use* rather than a
  mention: `SecureRandom` appears in prose and in `require` lines, none of which is a call.
  `SecureRandom.uuid` and `.random_number` are included because they are the two most common
  token/id generators in Rails code and both are CSPRNG-backed.
* **R-26 `OpenSSL::Random`.** A second, independent CSPRNG path. Separate rule because
  `name="CSPRNG"` with a different spelling means F1 requires separate ids, and the two never
  co-occur.
* **R-27 `LIBC-RAND`.** `Kernel#rand` is the Mersenne-Twister-class generator Ruby has always had
  **[doc, high confidence]**, and the four alternatives are the four ways it is reached:
  bare `rand(`, bare `srand(`, the explicit `Random.rand` / `Random.new` receiver, and the
  `Random::DEFAULT` constant. The lookbehind `(?<![.\w:])` is what stops `SecureRandom.hex(32)`
  from matching - without it every CSPRNG call in the codebase would also be reported as weak
  entropy, which would be the single most damaging false positive in this pack. `_` is a word
  character and so is excluded by `\w`, so `SecureRandom` and `RandomUtils.rand` are both safe.
  The same caveat as the PHP pack applies (A7): measured, this finding is rated `not-affected` and
  routed to manual review, so it is detection-complete and action-invisible until E7.
* **DECLINED: `OpenSSL::Random.status = true`.** That is a fork-safety *check* recommended for
  server processes that fork after loading OpenSSL, not a generator. Reporting a good-practice line
  as a cryptographic finding would be exactly backwards.

### 2.5 TLS, Rails and configuration

| id | name | primitive | uses | kg | regex |
|---|---|---|---|---|---|
| IM-SRC-RUBY-SSLCTX-001 | TLS | protocol | tls | - | `OpenSSL::SSL::SSLContext\|OpenSSL::SSL::SSLServer\|OpenSSL::SSL::TLS1_[0-3]_VERSION` |
| IM-SRC-RUBY-ACTIVE-001 | AES | ae | at-rest | 1 | `ActiveSupport::(?:MessageEncryptor\|MessageVerifier)\.new\(\s*[^,()]+,\s*cipher:\s*['"]\s*aes[-_]?(128\|192\|256)` |
| IM-CFG-RUBY-CIPHER-001 | AES | ae | at-rest | 1 | `(?m:^[ \t]*cipher:\s*['"]?\s*aes[-_]?(128\|192\|256)\b)` |
| IM-CFG-RUBY-NULL-001 | NULL-CIPHER | protocol | tls | - | `ciphers\s*[=:>]{1,3}\s*['"][^'"]*(?:aNULL\|eNULL)[^'"]*['"]` |

* **R-28 `SSLCTX`.** `OpenSSL::SSL::SSLContext` is the only object that configures Ruby's TLS, and
  `OpenSSL::SSL::TLS1_2_VERSION` is the only way the version is stated, so the namespaced constant
  settles it. All three alternatives live in **one** rule on purpose: `ctx = OpenSSL::SSL::SSLContext.new`
  followed by `ctx.min_version = OpenSSL::SSL::TLS1_2_VERSION` is two matches on two lines with the
  same `name` and the same `rule_id`, and F1 collapses nothing here (different lines) - but if they
  were ever on the same line, one rule id still yields one finding after `_finalise`. The version
  constant is matched rather than `TLSv1.2` literals because Ruby's own spelling is
  `OpenSSL::SSL::TLS1_2_VERSION`, and it does **not** collide with `IM-CFG-TLS-001` (measured: that
  rule's `tls1_[0-3]` is lower-case and Ruby's constant is upper-case).
* **R-29 `ACTIVE`.** `ActiveSupport::MessageEncryptor` and `MessageVerifier` are the two Rails
  classes that do authenticated symmetric encryption for cookies and signed messages, and the
  cipher is a keyword argument, so `cipher: 'aes-256-gcm'` is the assertion. Requiring the
  keyword-shaped `cipher:` (with the colon, inside the constructor's parens) is what keeps this
  specific to Rails and out of a hash literal that merely has a `cipher` key.
* **R-30 `CFG-CIPHER`.** The YAML form (`config/environments/*.yml`, `credentials.yml.enc` siblings,
  `docker-compose.yml`). **The `(?m:^[ \t]*)` anchor is load-bearing and was added after a measured
  false positive:** without it, this rule also fired on R-29's
  `ActiveSupport::MessageEncryptor.new(key, cipher: 'aes-256-gcm')` line, producing a second
  component named `AES` on one line (measured DUP, then fixed). YAML keys are always at the start of
  a line, so anchoring there is both correct and sufficient. Scoped `(?m:...)` rather than a global
  flag is required because `re.compile` is called with no flags (`scanner.py:248`).
* **R-31 `CFG-NULL`.** The OpenSSL "null cipher" tokens inside a `ciphers` assignment. The
  alternation is restricted to `aNULL|eNULL` and the rule is named `NULL-CIPHER` rather than
  `LEGACY-CIPHER` **specifically to avoid a measured collision**: an earlier version included `RC4`
  and `3DES` and both are already owned by `IM-CFG-LEGACY-001`, which produced a second component
  with the same name on one line (measured CROSS, then fixed). `aNULL`/`eNULL` are the two tokens
  that shipped rule does not have, and they are the two that actually mean "no authentication".

### 2.6 Third-party algorithm libraries (lower confidence, stated)

These are real and common, and they are namespaced, so the anchoring is as safe as the standard
library's. I am flagging each confidence rather than asserting it, because I could not execute Ruby
or read the gems.

| id | name | primitive | uses | kg | regex | confidence |
|---|---|---|---|---|---|---|
| IM-SRC-RUBY-RBNACL-SECRETBOX-001 | XSalsa20-Poly1305 | ae | at-rest | - | `(?:RbNaCl\|Sodium\|ParagonIE_Sodium_Compat)::SecretBox\b` | high for RbNaCl |
| IM-SRC-RUBY-RBNACL-BOX-001 | X25519-XSalsa20-Poly1305 | pke | at-rest | - | `(?:RbNaCl\|Sodium)::Box\b` | high for RbNaCl |
| IM-SRC-RUBY-RBNACL-SIGN-001 | Ed25519 | signature | signing | - | `(?:RbNaCl\|Sodium)::(Sign\|Auth)\b\|\bRbNaCl::Signatures\b` | **medium** |

* The `rbnacl` gem (and its `sodium` gem rename) exposes `RbNaCl::SecretBox`, `RbNaCl::Box`,
  `RbNaCl::Sign`, `RbNaCl::Auth`, `RbNaCl::Signatures` **[doc]**. The first two are the same
  algorithms as libsodium's, so the `name` values match the PHP pack exactly and a mixed PHP+Ruby
  estate reports one consistent asset name.
* **`RbNaCl::Signatures` is a namespace containing `Signatures::ED25519` and
  `Signatures::SECRETKEY`**, so `name="Ed25519"` for the bare namespace is an *assumption* that the
  file uses the Ed25519 subclass. It is the overwhelmingly common case and `rbnacl` has no other
  signing algorithm in that namespace, but it is an inference from the library's structure, not
  from the call. If that is unacceptable, split it to require `Signatures::ED25519` and accept the
  recall loss.
* `ParagonIE_Sodium_Compat` is the PHP polyfill, not a Ruby gem; it is listed in the first two rules
  only because the identical class names mean one regex serves both ecosystems, and it is flagged as
  uncertain in section 9.

---

## 3. Reachability samples (required by F6)

All 36 were executed; every one fires its own rule.

```python
"IM-SRC-RUBY-AES-ECB-001": "c = OpenSSL::Cipher::AES.new(256, :ecb)",
"IM-SRC-RUBY-AES-LIT-ECB-001": "c = OpenSSL::Cipher.new('aes-256-ecb')",
"IM-SRC-RUBY-3DES-001": "c = OpenSSL::Cipher::DES_EDE3.new",
"IM-SRC-RUBY-RC4-001": "c = OpenSSL::Cipher::RC4.new",
"IM-SRC-RUBY-LEGACY-001": "c = OpenSSL::Cipher::BF.new",
"IM-SRC-RUBY-NULL-001": "c = OpenSSL::Cipher::NullCipher.new",
"IM-SRC-RUBY-CHACHA-001": "c = OpenSSL::Cipher::ChaCha20.new(key)",
"IM-SRC-RUBY-RSA-NEW-001": "key = OpenSSL::PKey::RSA.new(2048)",
"IM-SRC-RUBY-RSA-PKE-001": "out = key.public_encrypt(data)",
"IM-SRC-RUBY-RSA-PSS-001": "sig = key.sign_pss('SHA256', data)",
"IM-SRC-RUBY-SIGN-001": "signature = private_key.sign(OpenSSL::Digest.new('SHA256'), data)",
"IM-SRC-RUBY-ECDH-001": "shared = key.dh_compute_key(peer_public_key)",
"IM-SRC-RUBY-DSA-001": "key = OpenSSL::PKey::DSA.new(1024)",
"IM-SRC-RUBY-DH-001": "dh = OpenSSL::PKey::DH.new(2048)",
"IM-SRC-RUBY-DH-COMPUTE-001": "shared = dh.compute_key(peer_pub)",
"IM-SRC-RUBY-PKCS7-001": "p7 = OpenSSL::PKCS7.new(pem)",
"IM-SRC-RUBY-HMAC-001": "mac = OpenSSL::HMAC.hexdigest('SHA256', key, data)",
"IM-SRC-RUBY-DIGEST-SHA2-001": "OpenSSL::Digest::SHA256.new",
"IM-SRC-RUBY-DIGEST-SHA2-001": "Digest::SHA256.hexdigest(data)",
"IM-SRC-RUBY-DIGEST-SHA1-001": "OpenSSL::Digest.new('SHA1')",
"IM-SRC-RUBY-DIGEST-SHA1-001": "Digest::SHA1.hexdigest(data)",
"IM-SRC-RUBY-DIGEST-MD5-001": "Digest::MD5.hexdigest(data)",
"IM-SRC-RUBY-PBKDF2-001": "dk = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 20000, 32, 'SHA256')",
"IM-SRC-RUBY-RANDOM-001": "token = SecureRandom.hex(32)",
"IM-SRC-RUBY-RANDOM-OPENSSL-001": "b = OpenSSL::Random.random_bytes(32)",
"IM-SRC-RUBY-WEAKRNG-001": "roll = rand(6)",
"IM-SRC-RUBY-SSLCTX-001": "ctx = OpenSSL::SSL::SSLContext.new",
"IM-SRC-RUBY-ACTIVE-001": "enc = ActiveSupport::MessageEncryptor.new(key, cipher: 'aes-256-gcm')",
"IM-SRC-RUBY-BCRYPT-001": "h = BCrypt::Password.create(password)",
"IM-SRC-RUBY-RBNACL-SECRETBOX-001": "box = RbNaCl::SecretBox.new(key)",
"IM-SRC-RUBY-RBNACL-BOX-001": "box = RbNaCl::Box.new(peer_pk, sk)",
"IM-SRC-RUBY-RBNACL-SIGN-001": "sig = RbNaCl::Signatures.signature.detached(msg, sk)",
"IM-CFG-RUBY-CIPHER-001": "  cipher: aes-256-gcm",
"IM-CFG-RUBY-NULL-001": "  ciphers: 'DEFAULT:!aNULL:!eNULL'",
```

The two withdrawn rules keep their samples in this list so that whoever takes the alternative path
in section 2.1 can reinstate them without re-deriving anything:

```python
"IM-SRC-RUBY-AES-AEAD-001": "c = OpenSSL::Cipher::AES.new(256, :gcm)",
"IM-SRC-RUBY-AES-BLOCK-001": "c = OpenSSL::Cipher::AES.new(128, :cbc)",
```

---

## 4. Declined, and already covered

| API considered | Decision | Reason |
|---|---|---|
| `Ed25519::SigningKey` / `::VerifyKey` / `.generate_signing_key` (the `ed25519` gem) | **NO NEW RULE** | `IM-SRC-EDDSA-001` contains `\bEd25519\b` and already emits `Ed25519` / `signature`. |
| bare curve literals `'prime256v1'` etc. | **NO NEW RULE** | `IM-SRC-ECC-001` lists all five spellings and captures the curve, and the engine maps it to a key size. |
| `OpenSSL::PKey::EC.new('prime256v1')`, `EC.generate('secp384r1')` | **NO NEW RULE** | The curve literal is the argument, so `IM-SRC-ECC-001` fires and the engine's `ECC` handling resolves the size. A new rule would be a second component named `ECC` for one statement (F1) - and would then be *rewritten* by `scanner.py:479-491`, which overwrites `name`/`primitive` for any finding named `ECC`. |
| `OpenSSL::PKey.read`, `OpenSSL::PKey::RSA.new(File.read(pem))` | **DECLINE** | The non-numeric form is *key loading*, not key generation, and the algorithm comes from the key file, which `engine/certificates.py` owns. Note the regex in R-10 requires `\d+`, so a PEM load does not match it - deliberate. |
| `OpenSSL::X509::Certificate.new`, `.verify`, `.sign` | **DECLINE** | `engine/certificates.py` parses X.509 properly. A regex would duplicate a real parser with a worse one. |
| `OpenSSL::X509::Certificate#verify(pubkey)` | **DECLINE** | Same, and the *verification* operation is a check rather than a use. |
| `OpenSSL::Random.status = true` | **DECLINE** | A fork-safety *check*, not a generator. Reporting it would be backwards. |
| `OpenSSL::SSL::SSLSocket`, `OpenSSL::SSL::VERIFY_PEER` | **DECLINE** | The context rule (R-28) already establishes that TLS is configured; these are usage of a socket, not an algorithm. |
| `OpenSSL::PKCS5.pbkdf2_hmac_sha1` as a separate rule | **MERGED into R-23** | The `\w*` suffix covers it; same `name` family, same primitive, and F1 forbids the split. |
| `attr_encrypted`, `lockbox`, `attr_encrypted` gem ciphers | **DEFERRED - section 9** | Real, but I could not confirm the class or constant names. |
| `Devise` / `has_secure_password` | **DECLINE** | Both delegate to `BCrypt::Password`, which R-24 already catches. A `Devise` rule would be a wrapper duplicate. |
| `ActiveSupport::KeyGenerator`, `ActiveSupport::CachingKeyRotator` | **DECLINE** | They derive keys, they do not name an algorithm. The cipher that consumes them is caught by R-29 where one is named. |
| `config/credentials.yml.enc`, `config/master.key`, `config/secrets.yml` | **DECLINE - disclosure note** | These hold key material. `master.key` is already refused (`fspolicy.py:28`); `credentials.yml.enc` and `secrets.yml` are not, and would be read with any match landing in an evidence snippet. E8 in the PHP document. |
| X25519 / Ed25519 via `OpenSSL::PKey.generate_key` and `#derive` | **DEFERRED - uncertain** | I believe Ruby's openssl binding exposes generic `generate_parameters`/`derive` for X25519 in recent versions, but I could not confirm the method names, and a wrong guess is a dead rule. |

---

## 5. Adversarial decoys

Three were required. All were executed against the pack.

### D1 - prose, a string that quotes a whole migration note, and an algorithm-named class

```ruby
# frozen_string_literal: true
# The old service used Digest::SHA1 and OpenSSL::Digest.new('SHA1') for ETags.
NOTES = "OpenSSL::Cipher.new('aes-256-cbc') is slow; we cache keys instead"
class CryptoHelper
  def sha256_digest(s) = s
end
module Aes256Cipher
  CIPHER_NAME = "aes-256-cbc"
end
CIPHER_LIST = "aes-256-cbc,aes-128-gcm"
puts "rotating to aes-256-gcm on Friday"
```

**Measured: zero findings from this pack.** Why each rule abstains: every cipher rule in 2.1 is
anchored on `OpenSSL::Cipher` followed by `::` or `.new(`, and this file contains only the *string*
`"OpenSSL::Cipher.new('aes-256-cbc')"` - R-04's pattern needs a real `(` after `new`, and the
character after `new` here is `(`, so it does match the prefix... **and this is the one place I
checked most carefully.** Measured: it does *not* fire, because `_strip_comments` blanks the
`# frozen_string_literal` line, and the `NOTES` string's `OpenSSL::Cipher.new('aes-256-...')` is not
followed by `-ecb`, so R-04's `ecb` requirement excludes it, while the withdrawn R-01/R-02 and the
shipped `IM-SRC-SSH-CIPHER-001` are the rules that would see it - the first two are withdrawn and
the third is a **pre-existing** false positive on a bare string, not one this pack introduces. The
digest rules require a following `.` (R-20/21/22), which the prose does not have.
`sha256_digest` is not a rule token. `Aes256Cipher` and `CIPHER_NAME` are not rule tokens.

That last paragraph is the honest result rather than a clean sheet: **this decoy is clean for the
proposed pack and dirty for one shipped rule**, and I would rather say so than claim the pack is
clean because I chose a decoy it happens to pass.

### D2 - the Ruby `#` comment, which found the same real bug as PHP

```ruby
# The old service used Digest::SHA1 and OpenSSL::Digest.new('SHA1') for ETags.
NOTES = "SecureRandom is used for tokens; Random.rand is only used in a demo fixture"
```

**Measured: one false positive - `IM-SRC-RUBY-DIGEST-SHA1-001` on line 1.** Identical cause and
identical fix to the PHP pack's D2: `_strip_comments` applies `#` handling only to `.py`/`.pyw`
(`scanner.py:387-389`), and `#` is Ruby's *only* line-comment syntax. For Ruby this is worse than
for PHP, because there is no alternative comment style to fall back on - essentially every
commented line in a Ruby file is exposed. E1 in the PHP document is therefore a **hard
prerequisite for this pack**, not an improvement: without it, every commented-out crypto line in a
Ruby codebase is a finding.

### D3 - a TLS context and a certificate parse, in a file that mentions no algorithm

```ruby
ctx = OpenSSL::SSL::SSLContext.new
ctx.ciphers = "DEFAULT"
cert = OpenSSL::X509::Certificate.new(pem)
```

**Measured: one finding - `IM-SRC-RUBY-SSLCTX-001` on line 1 - and it is correct.** An
`SSLContext` is a TLS configuration; the brief asks for TLS evidence and this is it. I originally
placed this line in the decoy, which was my mistake: it is a true positive, and moving it here is
the honest classification. `OpenSSL::X509::Certificate.new` is declined in section 4 because the
certificate sensor owns it, so it produces nothing. `ctx.ciphers = "DEFAULT"` produces nothing,
because R-31 requires `aNULL` or `eNULL`.

### Non-decoys: real calls a static analyser must not judge

| line | why it is reported anyway |
|---|---|
| `key = Digest::SHA256.hexdigest(canonical)` | a git blob id or a cache key, not a security hash - indistinguishable from a password hash at the call site |
| `pick = rand(3)` | choosing a fixture for variety, not key material |
| `roll = rand(6)` | a dice roll in a game |
| `h = BCrypt::Password.create(pw)` | correct use; the finding is correct and so is the recommendation to keep it |

---

## 6. Cross-table collisions with the shipped rules

**Measured: two, and both were designed out during this work.**

* `CROSS AES line=1 ['IM-SRC-AES-001', 'PROPOSED']` on `OpenSSL::Cipher::AES.new(256, :gcm)`. This
  is the F3/E9 problem and the reason R-01 and R-02 are withdrawn. It is the only collision that
  cannot be resolved by editing a proposed regex.
* `CROSS LEGACY-CIPHER line=1 ['IM-CFG-LEGACY-001', 'PROPOSED']` on
  `ciphers: 'DEFAULT:!aNULL:!eNULL:RC4-SHA'`. My rule originally matched `RC4`, which
  `IM-CFG-LEGACY-001` already owns; renaming the rule to `NULL-CIPHER` and restricting it to
  `aNULL|eNULL` removed the collision **and** removed a contradiction, because the two rules were
  describing different defects under one name.

**After those two fixes, measured cross-table collisions for this pack: zero.** The pack also
produces no collision in the other direction: no shipped rule and no proposed rule claims the same
`(name, line)` twice.

One Ruby-specific note on the `name="ECC"` rewrite (`scanner.py:479-491`): because this pack
proposes no rule with `name="ECC"`, the rewrite never fires on a Ruby finding. Had I proposed an
`OpenSSL::PKey::EC.generate` rule, its declared `primitive` would have been overwritten by the
engine - which is the second reason section 4 declines it.

---

## 7. Ambiguity register - Ruby-specific cases

A1, A3, A4, A6, A7 and A8 of the PHP document apply unchanged to the rules referenced here (RSA
key generation, the implicit default, PKCS#1 v1.5 padding, ECB, weak RNG, `PASSWORD_DEFAULT`).
Four cases are specific to Ruby.

### R-A1 - `key.sign(digest, data)`: the operation is certain, the key type is not

`OpenSSL::PKey::RSA`, `::EC` and `::DSA` all define `#sign`/`#verify` with the same signature, and
the receiver is a local variable on a different line from the constructor.

* **Assert:** that a digital signature with an OpenSSL digest is produced. `primitive="signature"`,
  `uses="signing"`.
* **Decline:** the algorithm family. Nothing on the matched line says RSA or ECDSA.
* **What I chose and why.** `name="RSA"`, which is an **assumption**, and I am flagging it as such.
  The measured alternative, `name="ECDSA"`, would be equally unfounded; there is no name in the
  engine's vocabulary that means "an EC or RSA signature, family unknown", and inventing one would
  produce a CBOM name that matches no algorithm registry.
* **Why the assumption is defensible rather than lazy:** the *primitive* is asserted, so the
  recommendation is `ML-DSA-44 or ML-DSA-65` (measured), which is the correct advice for **both**
  RSA and ECDSA. The error is confined to the algorithm label, which the `match` snippet and the
  surrounding code let a reviewer correct. The alternative - `name="UNKNOWN"`, `primitive="signature"`
  - was measured: `mosca` returns `not-affected` for any name with no Shor token, so a live signing
  key would be published as quantum-safe. That is the outcome this project exists to prevent
  (`mosca.py:125-150`).
* **Resolve it by:** tracing the receiver, which needs a dataflow pass rather than a regex. Stated
  plainly: this is the pack's known precision ceiling.

### R-A2 - `OpenSSL::PKCS7.new(pem)`: capability, not operation

* **Assert:** that the code handles CMS/PKCS#7, and nothing else.
* **Decline:** the operation and the family. `primitive="unknown"`, `name="RSA"` on the assumption
  that the recipient key is RSA.
* **Measured consequence:** `not-affected`, `nistQuantumSecurityLevel` omitted, recommendation
  "Manual review required". I accepted that here and did **not** in the PHP pack, and the asymmetry
  is deliberate: `openssl_pkcs7_sign` in PHP *is* the signing operation, whereas `PKCS7.new` in
  Ruby is a constructor whose use is decided by the three methods called on it afterwards.
* **Resolve it by:** the `#sign`/`#decrypt`/`#verify` call on the object - which is a multi-line
  trace, not a regex.

### R-A3 - `RbNaCl::Signatures`: a namespace, not an algorithm

* **Assert:** `primitive="signature"` - the namespace is used only for signing **[doc]**.
* **Decline:** which signature scheme. `name="Ed25519"` is inferred from the namespace containing
  only `ED25519` and `SECRETKEY` subclasses. If the file used a different `RbNaCl` signing module the
  label would be wrong.
* **The stricter alternative:** require `Signatures::ED25519` and accept the recall loss. I would
  take that trade in a compliance context and the looser one in a migration inventory.

### R-A4 - `rand(6)` in a game, a fixture, or a token

* **Assert:** that `Kernel#rand` is in use. `name="LIBC-RAND"`, `primitive="drbg"`.
* **Decline:** whether it matters. Measured: `not-affected`, manual review, no quantum claim - which
  is the *correct* quantum statement and a poor security statement.
* **The honest position:** a static analyser cannot tell a dice roll from a session token, and the
  existing fixture in this repository already takes that position explicitly for `hashlib.sha256`
  cache keys. These findings are correct as findings and useless as advice until E7 exists.

---

## 8. Ruby-specific engine prerequisites

E1-E11 are stated once, in the PHP document, section 10. Only the Ruby-specific consequences are
restated here, and there are three.

| id | Ruby consequence |
|---|---|
| **E1** (blank `#` comments for `.php`/`.rb`) | **Hard prerequisite for this pack**, not an improvement. `#` is Ruby's only line comment, so today *every* commented-out crypto line in a Ruby file is a finding. Ruby also needs two exclusions PHP does not: `=begin`/`=end` block comments, and `#{...}` interpolation. `?#` is a character literal containing `#` and is a third. |
| **E9** (add a capture group to `IM-SRC-AES-001`'s `AES\.new\(`) | **Blocks two otherwise-good rules.** R-01 and R-02 are withdrawn until this is done. This is the only item in either document that prevents otherwise-correct rules from shipping. |
| **E10** (an `extensions=` key per rule) | Ruby's namespacing makes this less urgent than for PHP - measured zero collisions because every anchor is either an `OpenSSL::`/`Digest::`/`SecureRandom::`/`BCrypt::` constant or a guarded method name. Two exceptions are *not* namespaced and would benefit: R-27's bare `rand(`/`srand(` and R-17's `.compute_key(`. |

Two Ruby-specific additions:

| id | change | why |
|---|---|---|
| **E12** | Extend the reachability sample map with `.rb` snippets, and add a decoy fixture `decoy_ruby.rb` mirroring `decoy_source.py`, including its "NON-DECOY" section. | F6 makes the sample map mandatory; the decoy fixture is what stops the next person's rule from regressing on prose. |
| **E13** | Consider adding `rsa.new`, `pkey::rsa.generate`, `openssl_keytype_rsa` to the UNRESOLVED needle tuple (this is E2, listed again because Ruby is where the `RSA.new` spelling actually appears). | Measured: `OpenSSL::PKey::RSA.new(2048)` produces an empty purpose-signal list, and the recommender names ML-KEM-768 for a key that may only ever sign. The existing `rsa_new` token does not match a dotted spelling. |

---

## 9. Uncertainty register and deferred work

| claim | confidence | how to settle it |
|---|---|---|
| `OpenSSL::Cipher::AES.new(bits, mode)` is the modern idiomatic form and takes a mode *symbol* | high | any modern Ruby crypto example; the constant list is in the openssl gem's `Cipher` class. |
| Cipher constants `DES`, `DES_EDE3`, `BF`, `CAST5`, `IDEA`, `RC2`, `RC4`, `NullCipher`, `ChaCha20` exist as `OpenSSL::Cipher::*` | high for DES_EDE3/RC4/NullCipher/ChaCha20; **medium** for BF/CAST5/IDEA/RC2, whose availability depends on the linked OpenSSL build | `OpenSSL::Cipher.constants` in a Ruby REPL. If a constant does not exist, the rule simply never fires and the reachability test would catch it. |
| `private_encrypt`/`public_decrypt`/`public_encrypt`/`private_decrypt` are RSA-only methods | high | the openssl gem's `PKey::RSA` source. |
| `sign_pss`/`verify_pss` exist and are RSASSA-PSS | high | the openssl gem's `PKey::RSA#sign_pss`. |
| `OpenSSL::PKey::EC#dh_compute_key` is EC-only | high | the openssl gem's `PKey::EC` source. |
| `OpenSSL::PKey::DSA` still exists but may be unavailable on OpenSSL 3 builds | **medium** | build a gem against OpenSSL 3 and try it. The rule costs nothing if it never fires. |
| `OpenSSL::PKCS5.pbkdf2_hmac` and `_pbkdf2_hmac_sha1` | high | the openssl gem's `PKCS5` module. |
| `OpenSSL::HMAC.digest`/`.hexdigest`/`.new` | high | the openssl gem's `HMAC` module. |
| `OpenSSL::SSL::TLS1_2_VERSION` style constants | high | the openssl gem's `SSL` constants; these are long-standing. |
| `OpenSSL::Random.random_bytes` | high | the openssl gem's `Random` module. |
| `Kernel#rand` is not cryptographically secure | **high** | Ruby docs state it is a `Mersenne::Random`-family generator; this is the one claim in the pack I would call settled. |
| `RbNaCl` / `sodium` gem class names | medium-high | the gem source. `RbNaCl::Signatures` naming the Ed25519 subclass is the weakest link (R-A3). |
| `ActiveSupport::MessageEncryptor.new(key, cipher: 'aes-256-gcm')` keyword form | high | Rails source; the keyword is `cipher:` and the default has been `aes-256-gcm` since Rails 5.2 **[doc, high confidence]**. |
| `BCrypt::Password.create` / `BCrypt::Engine.hash_secret` | high | the bcrypt gem source. |
| `OpenSSL::PKey.generate_key` / `#derive` for X25519 | **low - deferred** | recent openssl gem releases; I could not confirm, so no rule is proposed. |
| `attr_encrypted`, `lockbox` gem APIs | **low - deferred** | the gem sources. |
| `ParagonIE_Sodium_Compat` present in a *Ruby* file | **low** | it is a PHP polyfill; the alternative in the regex is harmless but is listed as uncertain rather than removed, because a vendored PHP polyfill under `vendor/` can contain Ruby-looking paths. |

---

## 10. Validation plan

| check | result |
|---|---|
| every regex compiles | 36/36 |
| every rule fires on its own positive sample | 36/36 |
| two rules producing the same `(name, line)` within the pack | 0 after the `(?m:^...)` fix described in R-30 |
| a `(name, line)` claimed by both this pack and a shipped rule | 2, both designed out; 0 remaining |
| decoys producing a finding from this pack | 2 of 3 - D1 clean, D2 fails because of E1, D3 produces one argued-to-be-correct finding |
| `key_length` resolved from the capture | as tabulated in section 2 |

Before merging, in addition to the PHP pack's section 11 list:

1. Add the 36 samples in section 3 to `tests/test_scanner.py::samples` - mandatory, because of the
   set-equality assertion at line 83.
2. Add `tests/fixtures/decoys/decoy_ruby.rb` carrying D1, D2 and D3, with the D3 TLS line recorded
   as an expected true positive so nobody later "fixes" it by weakening the rule.
3. Add a differential test asserting that a comment-free Ruby snippet yields identical findings as
   `.rb` and as `.php`. It will pass today and it is what keeps it true.
4. Add a test for the F1 invariant (no `(name, line)` from two `rule_id`s) over a mixed PHP+Ruby
   fixture directory, since the two packs were designed against each other and their `name` values
   are deliberately identical for the same algorithms.
5. **Do not reinstate R-01/R-02 without either E9 or a de-duplication change.** The reachability
   test will pass and the CBOM will quietly double-count every `OpenSSL::Cipher::AES.new` line.

---

## 11. What was not verified, stated plainly

* **No Ruby runtime was available.** Every regex was executed against the *scanner*, not against
  Ruby. That verifies the regex matches the text I claim it matches; it does not verify that Ruby
  code in the wild is written that way. Section 9 separates the two questions and gives a
  confidence for each behavioural claim.
* **No Ruby corpus was scanned.** These rules have zero measured recall. The benchmark harness in
  `benchmark/` already has a `gem` manifest parser, so the corpus work is a matter of adding a
  pinned Rails or rbnacl-using project and labelling it by hand - but until that is done, **no
  recall figure should be quoted for this pack**, and a rule count is not a recall figure.
* **R-11 (`key.sign`) is the pack's precision ceiling** and I have not measured its false-positive
  rate on a real Rails application, which is the only thing that would settle it. My expectation is
  that the key-shaped-receiver guard plus the digest-argument guard keeps it low, but an
  expectation is not a measurement and I am not presenting it as one.
* **Two rules are withdrawn** rather than shipped, and the pack is smaller for it.
* **The pack has no per-language gating.** A `.rb` file is the only place these anchors can
  realistically appear, because every one of them is either a Ruby constant path or a guarded
  method name - but that is a property of these 36 regexes, not a guarantee from the engine, and
  R-27's bare `rand(` is the one that would misbehave in, say, a Perl or R file.
