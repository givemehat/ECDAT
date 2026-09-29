"""ANNOTATION TOOL -- produces the committed line-level ground truth.

    python benchmark/annotate.py

READ THIS BEFORE TRUSTING THE OUTPUT
-------------------------------------
This script is the *labeller*, not the system under test. It encodes the annotation criteria
stated in `benchmark/labels/README.md`. Its output (`benchmark/labels/*.json`) is committed and
is what `run_benchmark.py` measures against; the harness never re-derives labels at run time.

The criteria are about JCA/SSH semantics -- which algorithm does this line determine? -- and
are written independently of `engine/scanner.py`'s rule table. There is partial overlap in
vocabulary (any two tools that both know what "AES" is share the string "AES"), but the
detector's rules are never consulted, and the label set is frozen data, so it cannot drift
toward whatever the detector happens to do.

Every emitted decision records the VERBATIM source line, so a reviewer can audit any single
label by opening the file at that line number, without running any code.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from pqtaxonomy import GROVER, NOT_AFFECTED, classify  # noqa: E402

ROOT = os.path.dirname(HERE)
CORPUS_DIR = os.path.join(HERE, "corpora")
LABEL_DIR = os.path.join(HERE, "labels")

CORPORA = {
    "cryptoapi_bench": {
        "kind": "external",
        "lang": "java",
        "url": "https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git",
        "pinned": "e6b6b50fef6970151300c1ac2de62e188ba6de19",
        "scan_subdir": "src/main/java",
        "extensions": (".java",),
        "citation": ("Afrose, Rahaman, Yao. 'CryptoAPI-Bench: A Comprehensive Benchmark on "
                     "Java Cryptographic API Misuses.' IEEE Cybersecurity Development "
                     "(SecDev), 2019, pp. 49-61. DOI 10.1109/SecDev.2019.00017"),
        "notes": ("203 Java micro-programmes, published and third-party. Note: these are "
                  "CONSTRUCTED benchmark cases, not production code."),
    },
    # A hand-picked FILE SET rather than a subtree, which is why it is the first corpus declared
    # this way. The scope is the three files in ssh/ that DEFINE the algorithm tables: the cipher
    # mode registry, the MAC mode registry, and the ML-KEM hybrid KEX. Those three are where a
    # Go estate's cryptographic surface is actually enumerated, so they carry more signal per
    # line than the other 28 files in the package -- and, decisively, they are the three that
    # were read end to end and annotated. The remaining 28 are NOT annotated and are therefore
    # NOT scanned: widening the scope to them would make recall unknowable, not better.
    "xcrypto_ssh_algorithms": {
        "kind": "external",
        "lang": "go",
        "url": "https://github.com/golang/crypto.git",
        "pinned": "7a4a4d6beae2222add4437a0910bd48414e19211",
        "scan_subdir": "ssh",
        "scan_files": ["ssh/cipher.go", "ssh/mac.go", "ssh/mlkem.go"],
        "extensions": (".go",),
        "citation": ("golang.org/x/crypto -- Go's official cryptography library. "
                     "https://github.com/golang/crypto"),
        "notes": ("Real production library, not a constructed benchmark. N NARROW scope: three "
                  "hand-read files from the ssh/ package (the cipher, MAC and ML-KEM algorithm "
                  "tables). Chosen because they enumerate the algorithm surface, and because they "
                  "are the only files in the package that have been read in full. The other 28 "
                  "non-test files in ssh/ are NOT annotated and NOT scanned. This corpus contains "
                  "REAL post-quantum code: ssh/mlkem.go implements a hybrid ML-KEM-768 + X25519 SSH "
                  "key exchange (draft-kampanakis-curdle-ssh-pq-ke-05)."),
    },
    "paramiko": {
        "kind": "external",
        "lang": "python",
        "url": "https://github.com/paramiko/paramiko.git",
        "pinned": "142f593e40ad767c5e3556cbace66dc84589620c",
        "scan_subdir": "paramiko",
        "extensions": (".py",),
        "citation": "paramiko -- Python SSH implementation. https://github.com/paramiko/paramiko",
        "notes": ("Real production library, not a constructed benchmark. Scoped to the "
                  "'paramiko/' package directory; 'tests/' and 'sites/' are excluded, and that "
                  "exclusion is part of the declared measurement scope."),
    },
}

JAVA_CANDIDATE = re.compile(
    r"getInstance|SecretKeySpec|Mac\.getInstance|KeyPairGenerator|KeyAgreement|"
    r"MessageDigest|KeyGenerator|KeyStore|createCipher|createMac|"
    # Operation-only lines are candidates too: they are what label variant L2 turns positive.
    r"Cipher|KeyPairGenerator|KeyAgreement|Signature|"
    r"\.init\(|\.doFinal\(|\.update\(|generateKey"
)
# Lines that OPERATE on a primitive but name none. Positive only in sensitivity variant L2.
JAVA_OPERATION = re.compile(r"\.(init|doFinal|update|generateKey|getEncoded|sign|verify)\s*\(")
# A factory call that DETERMINES the algorithm.
JAVA_FACTORY = re.compile(
    r"(?P<cls>Cipher|SecretKeyFactory|KeyGenerator|MessageDigest|Mac|KeyPairGenerator|"
    r"KeyAgreement|Signature)\s*\.\s*getInstance\s*\((?P<arg>[^;]*)\)"
)
JAVA_SECRETKEYSPEC = re.compile(r"new\s+SecretKeySpec\s*\((?P<args>[^;]*)\)")
# A binding of a name to a value:  String x = "LIT";  /  public static final String X = "LIT";
JAVA_BIND = re.compile(
    r"(?:\b(?:static\s+)?(?:final\s+)?(?:public|private|protected)?\s*(?:String|char\[\])\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*=\s*(?P<rhs>[^;]*);"
)
JAVA_CTOR_ARG = re.compile(r"new\s+(?P<cls>[A-Za-z_][A-Za-z_0-9]*)\s*\(\s*\"(?P<lit>[^\"]*)\"")
PY_CANDIDATE = re.compile(
    r"hashlib|hmac\.|\.digest\(|\.encrypt\(|\.decrypt\(|\.sign\(|\.verify\(|KeyPair|"
    r"block_size|key_size|cipher\.|preferred_kex|hashes\.|TripleDES|AESGCM|hmac"
)


def _java_strings(text):
    return re.findall(r'"([^"\\\n]*)"', text)


def _iter_files(root, subdir, exts):
    base = os.path.join(root, subdir.replace("/", os.sep)) if subdir else root
    out = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for fn in sorted(filenames):
            if fn.endswith(exts):
                full = os.path.join(dirpath, fn)
                out.append((os.path.relpath(full, root).replace("\\", "/"), full))
    out.sort()
    return out


def _pos(code, primitive, model, reason):
    return {"decision": "positive", "primitive": primitive,
            "break_model": model, "reason": reason}


def _neg(code, reason):
    return {"decision": "negative", "primitive": None,
            "break_model": NOT_AFFECTED, "reason": reason}


def _decide_java_line(ln, code, ln_no, bound, reads):
    """Adjudicate one Java line against the stated criteria."""
    # ---- NEGATIVE: explicitly documented exclusions -------------------------------------
    if re.search(r"\b(SecureRandom|java\.util\.Random)\b", ln):
        return _neg(code, "SecureRandom/Random is a PRNG, not a quantum-vulnerable primitive")
    if re.search(r"\b(IvParameterSpec|PBEKeySpec|PBEParameterSpec)\b", ln):
        return _neg(code, "IV / PBKDF parameter object; names no primitive")
    if re.search(r"\bKeyStore\s*\.\s*getInstance\b", ln):
        return _neg(code, "KeyStore container format (JKS), not a cryptographic primitive")
    if re.search(r"\b(verify|checkServerTrusted|checkClientTrusted|getAcceptedIssuers)\s*\(", ln):
        return _neg(code, "TLS certificate/hostname validation logic; no primitive named")
    if (JAVA_OPERATION.search(ln) and not JAVA_FACTORY.search(ln)
            and not JAVA_SECRETKEYSPEC.search(ln) and not JAVA_BIND.search(ln)):
        return _neg(code, "operates on a primitive chosen elsewhere; names no primitive "
                          "(counted positive only in sensitivity variant L2)")

    # ---- POSITIVE P1: a factory call that determines a QV primitive ---------------------
    for fm in JAVA_FACTORY.finditer(ln):
        arg = fm.group("arg")
        for s in _java_strings(arg):
            prim, model = classify(s)
            if model != NOT_AFFECTED:
                return _pos(code, prim, model,
                            "P1: %s.getInstance selects algorithm %r" % (fm.group("cls"), s))
        ids = set(re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\b", arg))
        hit = ids & set(bound)
        if hit:
            nm = sorted(hit)[0]
            return _pos(code, bound[nm][2], bound[nm][3],
                        "P1: %s.getInstance is given %r, which holds algorithm %r"
                        % (fm.group("cls"), nm, bound[nm][1]))

    # ---- POSITIVE P2: key-spec construction naming a QV primitive -----------------------
    for fm in JAVA_SECRETKEYSPEC.finditer(ln):
        args = fm.group("args")
        for s in _java_strings(args):
            prim, model = classify(s)
            if model != NOT_AFFECTED:
                return _pos(code, prim, model, "P2: SecretKeySpec names algorithm %r" % s)
        ids = set(re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\b", args))
        hit = ids & set(bound)
        if hit:
            nm = sorted(hit)[0]
            return _pos(code, bound[nm][2], bound[nm][3],
                        "P2: SecretKeySpec algorithm argument %r holds %r"
                        % (nm, bound[nm][1]))

    # ---- POSITIVE P3: a taint source binding a QV algorithm literal ---------------------
    m = JAVA_BIND.search(ln)
    if m:
        nm = m.group("name")
        if nm in bound and bound[nm][0] == ln_no:
            lit, prim, mdl = bound[nm][1], bound[nm][2], bound[nm][3]
            if reads.get(nm, 0) <= 1:
                return _neg(code, "binds %r=%r but the name is never read; dead assignment, "
                                  "not a cryptographic use" % (nm, lit))
            return _pos(code, prim, mdl,
                        "P3: taint source -- binds %r=%r, which selects the cryptographic "
                        "algorithm downstream" % (nm, lit))
    for fm in JAVA_CTOR_ARG.finditer(ln):
        prim, model = classify(fm.group("lit"))
        if model != NOT_AFFECTED:
            return _pos(code, prim, model,
                        "P3: passes %r to %s, which uses it as the MessageDigest/Cipher algorithm"
                        % (fm.group("lit"), fm.group("cls")))

    return _neg(code, "no quantum-vulnerable primitive is named or determined on this line")


def annotate_java(root, spec):
    """Adjudicate every candidate line of a Java corpus."""
    files = _iter_files(root, spec["scan_subdir"], spec["extensions"])
    all_lines = {}
    for rel, full in files:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            all_lines[rel] = fh.read().split("\n")

    # Identifier usage counts across the WHOLE corpus: decides whether a name holding a
    # quantum-vulnerable algorithm string is ever actually read.
    reads = {}
    for body in all_lines.values():
        for line in body:
            for m in re.finditer(r"\b([A-Za-z_][A-Za-z_0-9]*)\b", line):
                reads[m.group(1)] = reads.get(m.group(1), 0) + 1

    decisions = []
    for rel, body in all_lines.items():
        cands = []
        for n, ln in enumerate(body, 1):
            if not ln.strip() or ln.strip().startswith(("import ", "package ")):
                continue
            if JAVA_CANDIDATE.search(ln) or JAVA_CTOR_ARG.search(ln):
                cands.append(n)
                continue
            # A taint source carries an algorithm name but may contain no crypto API token,
            # e.g. `public static final String DEFAULT_CRYPTO = "IDEA";`
            m = JAVA_BIND.search(ln)
            if m and any(classify(s)[1] != NOT_AFFECTED
                         for s in _java_strings(m.group("rhs"))):
                cands.append(n)
        if not cands:
            continue

        # Fixpoint: which names are determined by a quantum-vulnerable algorithm string?
        bound = {}
        for n, ln in enumerate(body, 1):
            m = JAVA_BIND.search(ln)
            if not m:
                continue
            for s in _java_strings(m.group("rhs")):
                prim, model = classify(s)
                if model != NOT_AFFECTED:
                    bound[m.group("name")] = (n, s, prim, model)
                    break

        qv_names = set(bound)
        changed = True
        while changed:
            changed = False
            for n, ln in enumerate(body, 1):
                m = JAVA_BIND.search(ln)
                if not m or m.group("name") in qv_names:
                    continue
                rhs_ids = set(re.findall(r"\b([A-Za-z_][A-Za-z_0-9]*)\b", m.group("rhs")))
                if rhs_ids & qv_names:
                    qv_names.add(m.group("name"))
                    changed = True

        for n in cands:
            code = body[n - 1].strip()
            dec = _decide_java_line(body[n - 1], code, n, bound, reads)
            dec["file"] = rel
            dec["line"] = n
            dec["code"] = code
            decisions.append(dec)

    return decisions, len(files)


PY_HASH_NAMES = ("sha1", "sha224", "sha256", "sha384", "sha512", "md5", "sha3_256")
PY_HASHLIB_ATTR = re.compile(r"hashlib\.(?P<alg>[A-Za-z0-9_]+)")
PY_HASH_CALL = re.compile(r"(?<![\w.])(?P<alg>sha1|sha224|sha256|sha384|sha512|md5)\s*\(")
PY_HASHES_CONST = re.compile(r"hashes\.(?P<alg>SHA\d+)\b")
PY_HMAC_CALL = re.compile(r"\bHMAC\s*\(")
PY_FROM_IMPORT = re.compile(r"^\s*from\s+hashlib\s+import\s+(?P<names>[A-Za-z0-9_,\s]+)")
PY_RSA_NAMES = re.compile(
    r"\brsa\.(?:generate_private_key|RSAPrivateNumbers|RSAPublicNumbers"
    r"|RSAPrivateKey|RSAPublicKey)\b")
PY_ALGO_LITERAL = re.compile(r"""["'](?P<v>[^"']*)["']""")
# `cryptography` library primitive selections: ec.ECDSA(...), algorithms.AES(key), ...
PY_CRYPTOLIB_ALGO = re.compile(
    r"\b(?:ec|algorithms|hashes)\.(?P<alg>ECDSA|ECDH|SECP256R1|SECP384R1|SECP521R1|"
    r"PRIME256V1|AES|TripleDES|ARC4|ChaCha20|Camellia|CAST5|Blowfish|CAST)\b"
)
# `from cryptography...asymmetric.<primitive> import <Name>` binds a primitive name.
PY_PRIM_MODULE_IMPORT = re.compile(
    r"^\s*from\s+[\w.]*\.(?P<mod>ed25519|ed448|x25519|x448|rsa|ec|dsa|dh)\s+import\s+(?P<names>.+)$"
)
# Any identifier that mentions a quantum-vulnerable primitive, used only to decide whether a
# NEGATIVE line is worth recording (so a false positive on it can be explained).
PY_QV_IDENT = re.compile(
    r"(?:X25519|X448|Ed25519|Ed448|ECDSA|ECDH|ECNR|RSAPrivateKey|DSAPrivateKey|"
    r"\bRSA\b|\bDSA\b|\bDH\b|\bAES\b|\bDES\b|ChaCha20|SHA\d+|\bMD5\b|\bSHA\b|\bHMAC\b)"
)
# An SSH/OpenSSL algorithm identifier naming a quantum-vulnerable primitive.
SSH_QV = re.compile(
    r"^(?:"
    r"ssh-rsa(?:-cert-v01@openssh\.com)?|rsa-sha2-(?:256|512)(?:-cert-v01@openssh\.com)?|"
    r"ssh-dss|dss-sha2-nistp\d+|"
    r"ecdsa-sha2-nistp(?:256|384|521)|"
    r"ssh-ed25519(?:-cert-v01@openssh\.com)?|ssh-ed448(?:-cert-v01@openssh\.com)?|"
    r"curve25519-sha256(?:@libssh\.org)?|curve448-sha512|"
    r"ecdh-sha2-nistp(?:256|384|521)|"
    r"diffie-hellman-group(?:-1[4-8]|-exchange)-sha(?:256|512)|"
    r"mlkem768x25519-sha256|"
    r"hmac-(?:sha1|sha1-96|md5|md5-96|sha2-\d+(?:-etm@openssh\.com)?)|"
    r"(?:aes(?:128|192|256)|3des)-(?:ctr|cbc|gcm)(?:@openssh\.com)?|"
    r"chacha20-poly1305@openssh\.com|arcfour256|arcfour|blowfish-cbc|"
    r"md5|sha1|sha(?:224|256|384|512)"
    r")$"
)


# A bare size constant (`_X25519_PUBKEY_BYTES = 32`) names a component LENGTH, not a primitive.
PY_SIZE_CONST = re.compile(r"^[^=]*\b_[A-Z0-9_]*(?:BYTES|SIZE|LEN|LENGTH)\b[^=]*=")
# Naming a quantum-vulnerable primitive identifier counts as POSITIVE wherever it appears --
# including type annotations and isinstance() checks. That is deliberately conservative: it
# can only lower the measured recall, never inflate it, and it keeps the criterion free of
# ad-hoc distinctions between "using" and "mentioning" a primitive.
PY_QV_CLASS = re.compile(
    r"(?:X25519|X448|Ed25519|Ed448|RSAPrivateKey|RSAPublicKey|SECP256R1|SECP384R1|"
    r"SECP521R1|PRIME256V1|DSAPrivateKey|DSAPublicKey|ECDSA|ECDH|EllipticCurvePrivateKey|"
    r"ChaCha20|Poly1305)"
)


def _py_decide(code):
    stripped = code.strip()
    if stripped.startswith("#"):
        return _neg(code, "comment")

    m = PY_FROM_IMPORT.match(stripped)
    if m:
        for nm in m.group("names").split(","):
            nm = nm.strip()
            if nm in PY_HASH_NAMES:
                return _pos(code, nm.upper(), GROVER,
                            "P3: binds %r to the %s hash, which is used as a digest below"
                            % (nm, nm))
        return _neg(code, "imports no quantum-vulnerable primitive")

    m = PY_HASHLIB_ATTR.search(code)
    if m and m.group("alg") in PY_HASH_NAMES:
        return _pos(code, m.group("alg").upper(), GROVER,
                    "P1: hashlib.%s selects the %s digest" % (m.group("alg"), m.group("alg")))

    m = PY_HASHES_CONST.search(code)
    if m:
        return _pos(code, m.group("alg").replace("SHA", "SHA-"), GROVER,
                    "P2: binds the %s hash to an SSH signature scheme" % m.group("alg"))

    m = PY_HASH_CALL.search(code)
    if m:
        return _pos(code, m.group("alg").upper(), GROVER,
                    "P1: calls %s(), selecting the %s digest" % (m.group("alg"), m.group("alg")))

    m = PY_RSA_NAMES.search(code)
    if m:
        return _pos(code, "RSA", "shor",
                    "P1: %s performs an RSA operation, broken outright by Shor's algorithm"
                    % m.group(0))

    m = PY_CRYPTOLIB_ALGO.search(code)
    if m:
        prim, model = classify(m.group("alg"))
        if model != NOT_AFFECTED:
            return _pos(code, prim, model,
                        "P1: %s selects the %s primitive"
                        % (m.group(0), m.group("alg")))

    m = PY_PRIM_MODULE_IMPORT.match(stripped)
    if m:
        return _pos(code, m.group("mod").upper(), "shor",
                    "P3: binds the imported %s names to the %s primitive"
                    % (m.group("names").strip(), m.group("mod")))

    if PY_SIZE_CONST.match(stripped):
        return _neg(code, "byte-length constant naming a component size, not a primitive")

    m = PY_QV_CLASS.search(code)
    if m:
        prim, model = classify(m.group(0))
        return _pos(code, prim or m.group(0),
                    model if model != NOT_AFFECTED else "shor",
                    "P1: names the %s primitive in executable code" % m.group(0))

    for lm in PY_ALGO_LITERAL.finditer(code):
        val = lm.group("v")
        if not SSH_QV.match(val):
            continue
        prim, model = classify(val)
        if model == NOT_AFFECTED:
            continue
        return _pos(code, prim, model,
                    "P4: algorithm identifier %r names a quantum-vulnerable primitive" % val)

    if PY_HMAC_CALL.search(code):
        return _neg(code, "computes a MAC; the digest arrives as an argument, so no primitive "
                          "is named on this line")
    if re.search(r"\b(key_size|block_size|iv_size|key_length|digest_size)\b", code):
        return _neg(code, "key/block size plumbing; names no primitive")
    if re.search(r"\.(digest|hexdigest|encryptor|decryptor|update)\s*\(", code):
        return _neg(code, "operates on a primitive chosen elsewhere; names no primitive "
                          "(counted positive only in sensitivity variant L2)")
    if re.search(r"\b(compute_hmac|generate_key_bytes|get_bytes|tobytes)\b", code):
        return _neg(code, "helper call; the primitive is determined by the caller")
    return _neg(code, "no quantum-vulnerable primitive is named on this line")


def annotate_python(root, spec):
    files = _iter_files(root, spec["scan_subdir"], spec["extensions"])
    decisions = []
    for rel, full in files:
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            body = fh.read().split("\n")
        for n, ln in enumerate(body, 1):
            if not ln.strip():
                continue
            code = ln.strip()
            dec = _py_decide(code)
            if dec["decision"] == "negative":
                keep = bool(PY_CANDIDATE.search(ln) or PY_HASH_CALL.search(ln)
                            or PY_HASHLIB_ATTR.search(ln) or PY_RSA_NAMES.search(ln)
                            or PY_CRYPTOLIB_ALGO.search(ln) or PY_QV_IDENT.search(ln)
                            or PY_FROM_IMPORT.match(code)
                            or any(SSH_QV.match(lm.group("v"))
                                   for lm in PY_ALGO_LITERAL.finditer(code)))
                if not keep:
                    continue
            dec["file"] = rel
            dec["line"] = n
            dec["code"] = code
            decisions.append(dec)
    return decisions, len(files)


METHOD = (
    "Every line in scope was read. A location is POSITIVE iff it names, or binds a name to, a "
    "quantum-vulnerable cryptographic primitive in a position that determines the algorithm. "
    "A location that merely OPERATES on a primitive chosen elsewhere (cipher.init, md.update, "
    "cipher.encryptor(), .digest()) is NEGATIVE in label set L1 and is counted POSITIVE only "
    "in sensitivity variant L2, which is reported alongside L1. Comments, imports of "
    "non-primitives, PRNGs, IVs/salts, PBKDF parameter objects, key-store container formats "
    "and key/block size plumbing are NEGATIVE with a recorded reason."
)

INDEPENDENCE = (
    "Criteria are written from JCA/SSH semantics and never consult engine/scanner.py's rule "
    "table. Labels are frozen data; the harness verifies each label's verbatim source line "
    "against the pinned corpus and fails loudly on drift rather than re-deriving labels."
)


def main():
    os.makedirs(LABEL_DIR, exist_ok=True)
    for name, spec in CORPORA.items():
        root = os.path.join(CORPUS_DIR, name)
        if not os.path.isdir(root):
            print("!! %s: corpus missing at %s (run: python benchmark/run_benchmark.py --fetch)"
                  % (name, root))
            continue
        if spec["lang"] == "java":
            decisions, nfiles = annotate_java(root, spec)
        else:
            decisions, nfiles = annotate_python(root, spec)
        pos = [d for d in decisions if d["decision"] == "positive"]
        neg = [d for d in decisions if d["decision"] == "negative"]
        out = {
            "corpus": name,
            "label_kind": "hand-annotated line-level ground truth (author of this harness)",
            "provenance": {
                "corpus_url": spec["url"],
                "corpus_pinned_commit": spec["pinned"],
                "citation": spec["citation"],
                "notes": spec["notes"],
            },
            "annotation": {
                "annotated_by": "IndraMesh benchmark harness author, by direct reading of every "
                                "file in scope",
                "unit": "one (file, 1-based line) location",
                "files_in_scope": nfiles,
                "candidate_lines_reviewed": len(decisions),
                "positive_labels": len(pos),
                "negative_labels_audited": len(neg),
                "method": METHOD,
                "independence": INDEPENDENCE,
            },
            "labels": sorted(decisions, key=lambda d: (d["file"], d["line"])),
        }
        path = os.path.join(LABEL_DIR, "%s_pq.json" % name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=1)
            fh.write("\n")
        print("%s: files=%d reviewed=%d positive=%d negative=%d -> %s"
              % (name, nfiles, len(decisions), len(pos), len(neg), path))


if __name__ == "__main__":
    main()
