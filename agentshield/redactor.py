"""Redactor module.

Provides simple routines to take text and a set of ``SecretMatch``
objects (from :class:`SecretScanner`) and replace the sensitive
substrings with placeholders.  The underlying policy may influence
placeholder text.
"""
from __future__ import annotations

from typing import List

from .secret_scanner import SecretMatch


class Redactor:
    """Utility for redacting secrets from strings."""

    PLACEHOLDER = "[REDACTED_SECRET]"

    def redact(self, text: str, secrets: List[SecretMatch]) -> str:
        """Return ``text`` with each match replaced by a placeholder.

        The list ``secrets`` must be sorted by ``start``; the scanner
        returns results in sorted order so clients usually do not have to
        worry about overlapping matches.
        """
        if not secrets:
            return text
        parts: List[str] = []
        last_index = 0
        for sec in secrets:
            parts.append(text[last_index : sec.start])
            parts.append(self.PLACEHOLDER)
            last_index = sec.end
        parts.append(text[last_index:])
        return "".join(parts)
