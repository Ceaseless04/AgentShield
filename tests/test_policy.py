import os
from pathlib import Path

import pytest

from agentshield.policy import Policy


def test_load_default_policy(tmp_path):
    # write a temporary policy into the real policies folder so load_default
    # will find it.  We swap it back afterwards to avoid side effects.
    root = Path(__file__).parent.parent
    pol_dir = root / "policies"
    pol_dir.mkdir(exist_ok=True)
    target = pol_dir / "default_policy.yaml"
    backup = None
    if target.exists():
        backup = target.read_text()
    try:
        target.write_text("allowed: [FOO]\nblocked: [BAR]\nblock_mode: error\n")
        policy = Policy.load_default()
        assert policy.allowed == ["FOO"]
        assert policy.blocked == ["BAR"]
        assert policy.block_mode == "error"
    finally:
        if backup is not None:
            target.write_text(backup)
        else:
            target.unlink()


def test_is_allowed_blocked():
    policy = Policy(allowed=["A"], blocked=["B"], block_mode="redact")
    assert policy.is_allowed("A")
    assert not policy.is_allowed("X")
    assert policy.is_blocked("B")
    assert not policy.is_blocked("Y")
