"""Append-only audit-event ORM record."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.storage.base import Base, UTCDateTime


class AuditEventRecord(Base):
    __tablename__ = "audit_events"

    audit_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    actor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    object_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    object_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
