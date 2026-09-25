import pytest
import os
from unittest.mock import patch, MagicMock
from engine.scanner import ECDATScanner

@pytest.fixture
def scanner():
    # Mock the ML Engine to avoid loading PyTorch models during scanner test
    with patch('engine.scanner.AdvancedCryptoInference') as mock_inf:
        mock_instance = MagicMock()
        # Default mock: return 'None', 0.0, 0.0 so RegEx is tested natively
        mock_instance.predict.return_value = (None, 0.0, 0.0)
        mock_inf.return_value = mock_instance
        return ECDATScanner()

def test_scanner_bad_path(scanner):
    # Pass a path that does not exist
    findings = scanner.scan_directory("/path/does/not/exist/123456")
    assert findings == []

def test_scanner_empty_file(scanner, tmpdir):
    p = tmpdir.mkdir("test").join("empty.py")
    p.write("")
    findings = scanner.scan_directory(str(tmpdir))
    assert findings == []

def test_scanner_binary_file_handled(scanner, tmpdir):
    # Scanner expects strings to return from compiled binary `strings` command
    p = tmpdir.mkdir("test").join("compiled.so")
    p.write_binary(b"\x7fELF\x02\x01\x01\x00")
    
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="some libcrypto string here")
        findings = scanner.scan_directory(str(tmpdir))
        
    assert len(findings) == 1
    assert findings[0]['type'] == 'library'
    assert findings[0]['name'] == 'OpenSSL/libcrypto'

def test_scanner_subprocess_error(scanner, tmpdir):
    p = tmpdir.mkdir("test").join("compiled.so")
    p.write_binary(b"\x7fELF")
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = Exception("Subprocess crashed")
        findings = scanner.scan_directory(str(tmpdir))
    assert findings == []

def test_scanner_unusual_encoding(scanner, tmpdir):
    p = tmpdir.mkdir("test").join("bad_encode.py")
    # Write some non-utf8 bytes that will throw UnicodeDecodeError when read as utf-8
    p.write_binary(b"\xff\xfe\x00\x00")
    # This should trigger the `except Exception:` block inside source code reading
    findings = scanner.scan_directory(str(tmpdir))
    assert findings == []

def test_scanner_aes_regex(scanner, tmpdir):
    p = tmpdir.mkdir("test").join("aes.py")
    p.write("Cipher.getInstance(\"AES/GCM\")")
    findings = scanner.scan_directory(str(tmpdir))
    assert len(findings) == 1
    assert findings[0]['name'] == 'AES'

def test_scanner_dl_fallback(scanner, tmpdir):
    p = tmpdir.mkdir("test").join("custom.py")
    p.write("def my_custom_crypto(): pass")
    
    # Configure the mocked ML engine to flag this as high-confidence RSA
    scanner.ml_engine.predict.return_value = ("RSA", 0.95, 10.0)
    
    findings = scanner.scan_directory(str(tmpdir))
    assert len(findings) == 1
    assert findings[0]['primitive'] == 'neural-detected'
    assert findings[0]['name'] == 'RSA'
    assert findings[0]['dl_confidence'] == 0.95
