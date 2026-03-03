"""OutputGuard module.

Checks text produced by an agent before it is returned to a human or
external system. If secrets appear the guard can either redact them or
raise an exception depending on configured policy.
"""
from __future__ import annotations

from typing import List

from .policy import Policy
from .secret_scanner import SecretMatch, SecretScanner


class LeakageError(Exception):
    """Raised when an output is determined to contain disallowed data."""


class OutputGuard:
    """Inspects and optionally redacts agent output strings."""

    def __init__(self, policy: Policy | None = None) -> None:
        self.scanner = SecretScanner()
        self.policy = policy or Policy.load_default()

    def inspect(self, text: str) -> str:
        """Return a version of ``text`` that complies with the policy.

        If the policy outright blocks data types found in ``text`` an
        :class:`LeakageError` is raised.  Otherwise secrets are redacted
        before returning the string.
        """
        secrets = self.scanner.scan(text)
        blocked = [s for s in secrets if self.policy.is_blocked(s.secret_type)]
        if blocked and self.policy.block_mode == "error":
            raise LeakageError(f"blocked secret types in output: {[b.secret_type for b in blocked]}")
        # if not blocked by error, redact per policy
        if secrets and self.policy.block_mode in ("redact", "warn"):
            from .redactor import Redactor

            if self.policy.block_mode == "warn":
                import logging

                logging.warning(
                    "output contains blocked secret types: %s", [b.secret_type for b in blocked]
                )

            redactor = Redactor()
            text = redactor.redact(text, secrets)
        return text
