import re

import pytest

from agentshield.secret_scanner import SecretScanner


def test_scan_api_key():
    text = "my api_key=ABCDEF1234567890"
    scanner = SecretScanner()
    results = scanner.scan(text)
    assert any(r.secret_type == "API_KEY" for r in results)


def test_entropy_detector():
    high = "this has ZzYyXxWwVvUuTtSsRrQqPpOo"  # high entropy-ish
    scanner = SecretScanner()
    results = scanner.scan(high)
    assert any(r.secret_type == "HIGH_ENTROPY" for r in results)


def test_additional_patterns():
    scanner = SecretScanner()
    # AWS access key format (16 characters after prefix)
    assert any(r.secret_type == "AWS_ACCESS_KEY" for r in scanner.scan("AKIA1234567890ABCDEF"))
    # JWT-like string
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.TJVA95OrM7E2cBab30RMHrHDcEfhlp"
    assert any(r.secret_type == "JWT" for r in scanner.scan(jwt))


def test_register_pattern():
    scanner = SecretScanner()
    scanner.register_pattern("FOO", re.compile(r"foo=\d+"))
    results = scanner.scan("foo=1234")
    assert any(r.secret_type == "FOO" for r in results)
    assert any(r.secret_type == "FOO" for r in results)
