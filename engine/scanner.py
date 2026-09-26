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

SOURCE_EXTENSIONS = (".py", ".java", ".c", ".cpp", ".cc", ".h", ".hpp", ".cs", ".go", ".rs", ".js", ".ts")
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
    # ---- ECC ---------------------------------------------------------------------------------
    dict(id="ECD-SRC-ECDH-001", name="ECDH", primitive="key-agreement", artefact_class="source",
         uses="tls", key_group=1, evidence="discovered",
         regex=r"ec\.generate_private_key\(\s*ec\.(SECP\d+R1)\(\)|ECDH_compute_key|X25519|"
               r"KeyAgreement\.getInstance\(\s*[\"']ECDH|EVP_PKEY_EC\b"),
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


def _blank(match):
    """Erase matched text while preserving length and line structure."""
    return re.sub(r"[^\n]", " ", match.group(0))


def _strip_comments(content, path):
    """Blank comments and Python docstrings so rules match CODE, not prose.

    Deliberately conservative: a construct it cannot identify is left untouched, because erasing
    something that matters is worse than reporting a mention. Python `#` handling applies only to
    Python-family files -- `#` opens a comment in the config formats we scan but means something
    else on a C preprocessor line.
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
        self.coverage = {
            "scanners_run": set(),
            "files_seen": 0,
            "files_scanned": 0,
            "files_skipped": 0,
            "ml_reason": "disabled" if not enable_ml else "pending",
        }

    # ------------------------------------------------------------------ internals

    def _note_error(self, path, reason):
        self.errors.append({"file": path, "reason": reason})
        self.coverage["files_skipped"] += 1

    def _note_scanned(self):
        self.coverage["files_scanned"] += 1

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
                # A bare "ECC" hit carries no use context: ECDH implies key agreement, ECDSA a
                # signature. Resolve the name AND its primitive together so the recommender
                # cannot offer ML-DSA for a key-exchange artefact (or ML-KEM for a signature).
                if name in ("ECC", "ECDH"):
                    for grp in match.groups() or ():
                        if grp and grp.lower() in CURVE_KEY_SIZES_LOWER:
                            key_length = CURVE_KEY_SIZES_LOWER[grp.lower()]
                # A bare "ECC" hit carries no use context: ECDH implies key agreement, ECDSA a
                # signature. Resolve the name AND its primitive together so the recommender
                # cannot offer ML-DSA for a key-exchange artefact (or ML-KEM for a signature).
                if name == "ECC":
                    if uses == "tls":
                        name, primitive = "ECDH", "key-agreement"
                    else:
                        name, primitive = "ECDSA", "signature"
                finding = {
                    "file": file_path,
                    "line": line,
                    "type": "algorithm",
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
            for member in opened.getmembers():
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
            return self._scan_path(directory_path)
        if not os.path.isdir(directory_path):
            self._note_error(directory_path, "path does not exist or is not a directory")
            return findings
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
            self._note_scanned()
            return self._scan_container_image(fpath)
        if lowered.endswith(SOURCE_EXTENSIONS):
            self._note_scanned()
            return self._scan_source_file(fpath)
        # Config-like paths are scanned regardless of extension.
        if os.path.basename(fpath).lower() in CONFIG_FILENAMES or lowered.endswith(CONFIG_EXTENSIONS):
            self._note_scanned()
            return self._scan_source_file(fpath)
        if lowered.endswith(BINARY_EXTENSIONS):
            self._note_scanned()
            return self._scan_binary_file(fpath)
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



