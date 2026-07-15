"""Append-only audit-log persistence."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegishunt.schemas.audit import AuditEvent
from aegishunt.schemas.base import JsonObject
from aegishunt.storage.models.audit import AuditEventRecord


class AuditLogRepository:
    """Record and read immutable audit events within the caller transaction."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def record(
        self,
        *,
        actor: str,
        action: str,
        object_type: str,
        object_id: str | None,
        details: JsonObject | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            actor=actor,
            action=action,
            object_type=object_type,
            object_id=object_id,
            details=details or {},
        )
        row = AuditEventRecord(**event.model_dump(mode="python"))
        self._session.add(row)
        self._session.flush()
        return AuditEvent.model_validate(row)

    def list(self) -> list[AuditEvent]:
        rows = self._session.scalars(
            select(AuditEventRecord).order_by(
                AuditEventRecord.created_at,
                AuditEventRecord.audit_id,
            )
        ).all()
        return [AuditEvent.model_validate(row) for row in rows]
