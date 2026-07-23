"""Explicit Phase 1 schema version registration and compatibility checks."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegishunt.errors import SchemaVersionError
from aegishunt.storage.models.schema import SchemaVersionRecord

CURRENT_SCHEMA_VERSION = 4


def ensure_schema_version(session: Session) -> int:
    """Register an empty database or reject an incompatible existing version."""

    existing = session.scalar(select(func.max(SchemaVersionRecord.version)))
    if existing is None:
        session.add(SchemaVersionRecord(version=CURRENT_SCHEMA_VERSION))
        session.flush()
        return CURRENT_SCHEMA_VERSION
    if existing != CURRENT_SCHEMA_VERSION:
        raise SchemaVersionError(
            f"database schema version {existing} is incompatible with required "
            f"version {CURRENT_SCHEMA_VERSION}"
        )
    return existing
