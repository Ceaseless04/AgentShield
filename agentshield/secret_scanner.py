"""SecretScanner module.

Responsible for detecting sensitive strings in text using regex
and entropy heuristics. Architecture is extensible so new detectors
can be plugged in later.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Pattern


@dataclass
class SecretMatch:
    """Represents a span of text identified as a secret."""

    start: int
    end: int
    secret_type: str
    value: str


class SecretScanner:
    """Scan text for potential secrets.

    The scanner uses a list of named regex patterns and an optional
    entropy-based heuristic. Clients can extend or modify patterns.
    """

    # simple regex patterns for demonstration (loosely defined for MVP)
    DEFAULT_PATTERNS: List[tuple[str, Pattern]] = [
        ("API_KEY", re.compile(r"(?i)api[_-]?key\s*=\s*\S+")),
        ("ENV_VAR", re.compile(r"\b[A-Z0-9_]+=[^\n]+")),
        ("TOKEN", re.compile(r"(?i)token\s*=\s*\S+")),
        ("PASSWORD", re.compile(r"(?i)password\s*=\s*[^\s]+")),
        # common provider keys
        ("AWS_ACCESS_KEY", re.compile(r"AKIA[0-9A-Z]{16}")),
        ("AWS_SECRET_KEY", re.compile(r"(?i)aws_secret_access_key\s*=\s*\S+")),
        ("JWT", re.compile(r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+")),
    ]
    # entropy threshold for high-entropy strings
    ENTROPY_THRESHOLD: float = 4.5

    def __init__(self, patterns: List[tuple[str, Pattern]] | None = None) -> None:
        """Initialize scanner with optional custom patterns list.

        ``patterns`` should be a list of ``(name, regex)`` tuples.  If not
        provided, the built-in defaults are used.  Callers may also call
        :func:`register_pattern` on the instance to add detectors lazily.
        """
        self.patterns = patterns or list(self.DEFAULT_PATTERNS)

    def register_pattern(self, name: str, pattern: Pattern) -> None:
        """Add a new named regex pattern to this scanner instance.

        Useful for plugins or application-specific secrets.  Patterns are
        evaluated in insertion order during ``scan``.
        """
        self.patterns.append((name, pattern))

    def scan(self, text: str) -> List[SecretMatch]:
        """Return a list of secrets found in ``text``.

        Scanning is stateless; callers may reuse one scanner instance.
        """
        matches: List[SecretMatch] = []
        for name, pattern in self.patterns:
            for m in pattern.finditer(text):
                matches.append(
                    SecretMatch(start=m.start(), end=m.end(), secret_type=name, value=m.group())
                )
        # check for high entropy words
        for m in re.finditer(r"\b[A-Za-z0-9+/=]{20,}\b", text):
            candidate = m.group()
            if self._entropy(candidate) > self.ENTROPY_THRESHOLD:
                matches.append(
                    SecretMatch(start=m.start(), end=m.end(), secret_type="HIGH_ENTROPY", value=candidate)
                )
        # sort by start position so downstream logic can redact safely
        matches.sort(key=lambda s: s.start)
        return matches

    @staticmethod
    def _entropy(s: str) -> float:
        """Calculate Shannon entropy of ``s`` (per-character)."""
        from math import log2

        prob = {c: s.count(c) / len(s) for c in set(s)}
        return -sum(p * log2(p) for p in prob.values())
