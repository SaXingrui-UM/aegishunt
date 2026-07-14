"""Minimal Phase 0 configuration placeholder.

Validated YAML and environment-variable configuration belongs to Phase 1. This
module intentionally exposes only the environment label needed by the health
endpoint.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FoundationSettings:
    """Settings required by the Phase 0 application shells."""

    environment: str = "development"

    @classmethod
    def from_environment(cls) -> FoundationSettings:
        """Read the non-sensitive environment label with a safe default."""

        value = os.getenv("AEGISHUNT_ENV", "development").strip()
        return cls(environment=value or "development")
