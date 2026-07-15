"""Database schema-version ORM record."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.base import utc_now
from aegishunt.storage.base import Base, UTCDateTime


class SchemaVersionRecord(Base):
    __tablename__ = "schema_versions"

    version: Mapped[int] = mapped_column(primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
