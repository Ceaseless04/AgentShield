"""Secure filesystem access.

Wraps normal file operations and applies scanning, redaction and policy
checks before returning content to callers.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from .policy import Policy
from .redactor import Redactor
from .secret_scanner import SecretScanner


class SecureFS:
    """Replacement for direct filesystem reads which protects secrets."""

    def __init__(self, policy: Optional[Policy] = None) -> None:
        self.scanner = SecretScanner()
        self.redactor = Redactor()
        self.policy = policy or Policy.load_default()

    def read_file(self, path: Path | str, encoding: str = "utf-8") -> str:
        """Read a file, scan for secrets, and return a safe version.

        Raises ``LeakageError`` via underlying modules if blocked data is
        encountered and the policy demands an error.  Otherwise secrets are
        redacted according to the policy before returning the text.
        """
        p = Path(path)
        with open(p, "r", encoding=encoding) as f:
            data = f.read()
        secrets = self.scanner.scan(data)
        if secrets:
            # check for blocked
            blocked = [s for s in secrets if self.policy.is_blocked(s.secret_type)]
            if blocked and self.policy.block_mode == "error":
                from .output_guard import LeakageError

                raise LeakageError(
                    f"blocked secret types in file {path}: {[b.secret_type for b in blocked]}"
                )
            if self.policy.block_mode in ("redact", "warn"):
                data = self.redactor.redact(data, secrets)
        return data
