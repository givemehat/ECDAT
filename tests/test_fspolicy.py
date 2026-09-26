"""Tests for the filesystem safety policy (competitive analysis, item C5 / rank 4).

The threat model, quoted from the competitor whose README we studied:
    "The tool takes a filesystem path and a list of hosts over HTTP and acts on both. That is a
     server-side request forgery primitive and an arbitrary file read unless something stands
     between the two."

We had the filesystem half of that hole and did not know it. These tests pin the behaviour that
closes it, because a security control with no test is a comment.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.fspolicy import (FilesystemPolicyError, check_root, is_credential_store,
                              resolve_within)
from engine.scanner import ECDATScanner


# ------------------------------------------------------------------ unit: containment
def test_path_inside_root_resolves(tmp_path):
    target = tmp_path / "a" / "b.py"
    target.parent.mkdir()
    target.write_text("x", encoding="utf-8")
    assert resolve_within(str(tmp_path), str(target)) is not None


def test_path_outside_root_is_refused(tmp_path):
    assert resolve_within(str(tmp_path), str(tmp_path.parent / "outside.py")) is None


def test_prefix_lookalike_path_is_refused(tmp_path):
    """`/root-evil` must not count as inside `/root`.

    A naive `str.startswith(root)` check accepts this, and it is the standard way a containment
    check gets bypassed.
    """
    root = tmp_path / "root"
    root.mkdir()
    evil = tmp_path / "root-evil"
    evil.mkdir()
    assert resolve_within(str(root), str(evil)) is None


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_symlink_escaping_the_root_is_refused(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("PRIVATE KEY", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "innocent.py"
    try:
        os.symlink(secret, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")
    assert resolve_within(str(root), str(link)) is None


# ------------------------------------------------------------------ unit: credential stores
@pytest.mark.parametrize("name", [
    "id_rsa", "id_ed25519", ".netrc", ".git-credentials", ".npmrc", ".env",
    "shadow", "service-account.json", "server_rsa", "deploy_ed25519", ".env.local",
])
def test_credential_stores_are_recognised(name):
    assert is_credential_store(name), f"{name} must never be read into a CBOM"


@pytest.mark.parametrize("name", [
    "index.js", "crypto.py", "main.go", "README.md", "hashlib_helper.py", "salt.txt",
])
def test_ordinary_files_are_not_treated_as_credential_stores(name):
    assert not is_credential_store(name), f"{name} is an ordinary file and must be scannable"


# ------------------------------------------------------------------ unit: root validation
def test_refuses_a_missing_root(tmp_path):
    with pytest.raises(FilesystemPolicyError):
        check_root(str(tmp_path / "nope"))


def test_refuses_a_file_as_root(tmp_path):
    f = tmp_path / "f.py"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(FilesystemPolicyError):
        check_root(str(f))


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_refuses_a_pseudo_filesystem_root():
    if not os.path.isdir("/proc"):
        pytest.skip("no /proc on this platform")
    with pytest.raises(FilesystemPolicyError):
        check_root("/proc")


# ------------------------------------------------------------------ integration: the scanner
@pytest.mark.skipif(not hasattr(os, "symlink"), reason="platform has no symlinks")
def test_scanner_does_not_read_a_symlinked_private_key(tmp_path):
    """The end-to-end case: a symlink named like source must not land in the report.

    A link named `config.py` pointing at a private key is the exact primitive described in the
    threat model. The scanner must skip it AND say it skipped it -- an unexplained skip is
    indistinguishable from a missed detection.
    """
    secret = tmp_path / "outside" / "id_secret.pem"
    secret.parent.mkdir()
    secret.write_text("-----BEGIN RSA PRIVATE KEY-----", encoding="utf-8")
    root = tmp_path / "project"
    root.mkdir()
    link = root / "config.py"
    try:
        os.symlink(secret, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")

    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(root))
    assert findings == [], "a symlinked file must not produce findings"
    assert scanner.errors, "an unexplained skip is indistinguishable from a missed detection"
    reasons = " ".join(e["reason"] for e in scanner.errors)
    assert "symlink" in reasons or "credential" in reasons, reasons


def test_scanner_never_reports_a_credential_store(tmp_path):
    root = tmp_path / "p"
    root.mkdir()
    (root / ".netrc").write_text("machine api login bob password hunter2\n", encoding="utf-8")
    (root / "v.py").write_text("key = rsa.newkeys(2048)\n", encoding="utf-8")
    scanner = ECDATScanner(enable_ml=False)
    findings = scanner.scan_directory(str(root))
    for f in findings:
        assert "netrc" not in os.path.basename(f["file"]).lower()
    assert any("credential" in e["reason"] for e in scanner.errors)
