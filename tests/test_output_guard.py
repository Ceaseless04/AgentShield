import pytest

from agentshield.output_guard import LeakageError, OutputGuard
from agentshield.policy import Policy


def test_output_guard_redact_default():
    guard = OutputGuard()
    out = "here is api_key=SECRET"
    cleaned = guard.inspect(out)
    # placeholder should appear, and raw secret value shouldn't be visible
    assert cleaned == "here is [REDACTED_SECRET]"


def test_output_guard_error_mode():
    policy = Policy(blocked=["API_KEY"], block_mode="error")
    guard = OutputGuard(policy=policy)
    with pytest.raises(LeakageError):
        guard.inspect("api_key=badstuff")


def test_output_guard_warn_mode(caplog):
    policy = Policy(blocked=["PASSWORD"], block_mode="warn")
    guard = OutputGuard(policy=policy)
    text = "password=hunter2"
    cleaned = guard.inspect(text)
    # warn mode still redacts but doesn't error
    assert "[REDACTED_SECRET]" in cleaned
    assert "hunter2" not in cleaned
    assert "blocked" in caplog.text.lower()
