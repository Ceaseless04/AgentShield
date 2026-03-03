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
