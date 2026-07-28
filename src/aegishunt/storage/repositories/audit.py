"""Append-only audit-log persistence."""

from __future__ import annotations

import builtins
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from aegishunt.schemas.audit import AuditEvent
from aegishunt.schemas.base import JsonObject
from aegishunt.storage.models.audit import AuditEventRecord
from aegishunt.storage.models.hunting import AnalystFeedbackRecord


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
        created_at: datetime | None = None,
    ) -> AuditEvent:
        values: dict[str, object] = {
            "actor": actor,
            "action": action,
            "object_type": object_type,
            "object_id": object_id,
            "details": details or {},
        }
        if created_at is not None:
            values["created_at"] = created_at
        event = AuditEvent.model_validate(values)
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

    def list_case_events(
        self,
        case_id: UUID,
        *,
        limit: int,
        offset: int,
        action: str | None = None,
        actor: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        descending: bool = True,
    ) -> tuple[builtins.list[AuditEvent], int]:
        """Read one case timeline through fixed, bounded identity relationships."""

        case_identity = str(case_id)
        feedback_ids = select(AnalystFeedbackRecord.feedback_id).where(
            AnalystFeedbackRecord.related_case_id == case_id
        )
        related = or_(
            AuditEventRecord.object_id == case_identity,
            (
                (AuditEventRecord.object_type == AnalystFeedbackRecord.__tablename__)
                & or_(
                    func.replace(AuditEventRecord.object_id, "-", "").in_(
                        feedback_ids
                    ),
                    (
                        AuditEventRecord.details["object_type"].as_string()
                        == "case"
                    )
                    & (
                        AuditEventRecord.details["object_id"].as_string()
                        == case_identity
                    ),
                )
            ),
            (
                (AuditEventRecord.object_type == "case_report")
                & (AuditEventRecord.details["case_id"].as_string() == case_identity)
            ),
        )
        conditions = [related]
        if action is not None:
            conditions.append(AuditEventRecord.action == action)
        if actor is not None:
            conditions.append(AuditEventRecord.actor == actor)
        if created_from is not None:
            conditions.append(AuditEventRecord.created_at >= created_from)
        if created_to is not None:
            conditions.append(AuditEventRecord.created_at <= created_to)
        ordering = (
            (
                AuditEventRecord.created_at.desc(),
                AuditEventRecord.audit_id.desc(),
            )
            if descending
            else (
                AuditEventRecord.created_at.asc(),
                AuditEventRecord.audit_id.asc(),
            )
        )
        query = (
            select(AuditEventRecord)
            .where(*conditions)
            .order_by(*ordering)
            .limit(limit)
            .offset(offset)
        )
        count = select(func.count(AuditEventRecord.audit_id)).where(*conditions)
        rows = self._session.scalars(query).all()
        total = int(self._session.scalar(count) or 0)
        return [AuditEvent.model_validate(row) for row in rows], total
