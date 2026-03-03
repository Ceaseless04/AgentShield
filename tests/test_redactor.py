from agentshield.redactor import Redactor
from agentshield.secret_scanner import SecretMatch


def test_redact_simple():
    text = "secret=abcd"
    match = SecretMatch(start=0, end=11, secret_type="API_KEY", value="secret=abcd")
    r = Redactor()
    assert r.redact(text, [match]) == "[REDACTED_SECRET]"
