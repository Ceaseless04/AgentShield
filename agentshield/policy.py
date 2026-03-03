"""Policy system for AgentShield.

Policies are defined via YAML files describing which data types are
allowed, blocked, and how redaction should behave.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar, List

import yaml


@dataclass
class Policy:
    """Represents behaviour for scanning and redaction."""

    allowed: List[str] = field(default_factory=list)
    blocked: List[str] = field(default_factory=list)
    block_mode: str = "redact"  # or 'error' or 'warn'

    DEFAULT_FILENAME: ClassVar[str] = "default_policy.yaml"

    @classmethod
    def load_from_file(cls, path: Path | str) -> "Policy":
        """Load a policy YAML from disk."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(
            allowed=data.get("allowed", []),
            blocked=data.get("blocked", []),
            block_mode=data.get("block_mode", "redact"),
        )

    @classmethod
    def load_default(cls) -> "Policy":
        root = Path(__file__).parent.parent
        default = root / "policies" / cls.DEFAULT_FILENAME
        if default.exists():
            return cls.load_from_file(default)
        # fallback
        return cls()

    def is_allowed(self, data_type: str) -> bool:
        return data_type in self.allowed

    def is_blocked(self, data_type: str) -> bool:
        return data_type in self.blocked
