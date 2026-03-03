import pytest

from agentshield.output_guard import LeakageError
from agentshield.policy import Policy
from agentshield.secure_fs import SecureFS


def test_read_file_redacts(tmp_path):
    content = "password=supersecret\nnormal=ok"
    f = tmp_path / "test.txt"
    f.write_text(content)
    # default policy redacts passwords
    fs = SecureFS()
    result = fs.read_file(f)
    assert "[REDACTED_SECRET]" in result
    assert "normal=ok" in result


def test_read_file_error_mode(tmp_path):
    content = "token=abc123"
    f = tmp_path / "t2.txt"
    f.write_text(content)
    policy = Policy(blocked=["TOKEN"], block_mode="error")
    fs = SecureFS(policy=policy)
    with pytest.raises(LeakageError):
        fs.read_file(f)
