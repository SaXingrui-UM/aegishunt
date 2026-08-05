"""Transactional repository integration for Phase 9 alert correlation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

from sqlalchemy.orm import Session

from aegishunt.correlation.config import LoadedCorrelationPolicy
from aegishunt.correlation.errors import CorrelationPersistenceError
from aegishunt.correlation.grouping import correlate_alerts
from aegishunt.schemas import AlertGroup
from aegishunt.schemas.base import utc_now
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    SecurityAlertRepository,
)


class AlertCorrelationService:
    """Read immutable alerts and append deterministic groups idempotently."""

    def __init__(
        self,
        session: Session,
        loaded_policy: LoadedCorrelationPolicy,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        audit = AuditLogRepository(session)
        self._alerts = SecurityAlertRepository(session, audit)
        self._groups = AlertGroupRepository(session, audit)
        self._policy = loaded_policy
        self._clock = clock

    @staticmethod
    def _stable_evidence(group: AlertGroup) -> dict[str, object]:
        """Exclude lifecycle timestamps while comparing immutable correlation evidence."""

        payload = group.model_dump(exclude={"created_at"})
        evidence = dict(group.evidence)
        evidence.pop("generated_at", None)
        payload["evidence"] = evidence
        return payload

    def correlate(
        self,
        *,
        actor: str = "correlation-service",
        alert_ids: set[UUID] | None = None,
    ) -> tuple[AlertGroup, ...]:
        """Correlate all eligible alerts or one explicitly bounded alert set."""

        alerts = self._alerts.list()
        if alert_ids is not None:
            alerts = [item for item in alerts if item.alert_id in alert_ids]
        groups = correlate_alerts(
            alerts,
            self._policy,
            generated_at=self._clock(),
        )
        stored: list[AlertGroup] = []
        for group in groups:
            existing = self._groups.get(group.group_id)
            if existing is not None:
                if self._stable_evidence(existing) != self._stable_evidence(group):
                    raise CorrelationPersistenceError(
                        "stable group identity exists with different evidence"
                    )
                stored.append(existing)
                continue
            stored.append(self._groups.add(group, actor=actor))
        return tuple(stored)
