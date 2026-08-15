"""Read-only runtime-job lineage used by bounded evidence queries."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegishunt.storage.models import (
    AlertGroupRecord,
    RuntimeJobRecord,
    RuntimeOutputLedgerRecord,
    ThreatHypothesisRecord,
)


@dataclass(frozen=True, slots=True)
class RuntimeJobScope:
    """Validated identity of one runtime job selected by a read request."""

    job_id: UUID


class RuntimeJobLineageReader:
    """Resolve normalized and JSON-backed lineage without changing evidence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def read(self, job_id: UUID) -> RuntimeJobScope | None:
        if self._session.get(RuntimeJobRecord, job_id) is None:
            return None
        return RuntimeJobScope(job_id=job_id)

    def downstream_ids(
        self,
        job_id: UUID,
    ) -> tuple[frozenset[UUID], frozenset[UUID]]:
        """Resolve group and hypothesis identities only for endpoints that need them."""

        alert_ids = frozenset(
            alert_id
            for alert_id in self._session.scalars(
                select(RuntimeOutputLedgerRecord.alert_id).where(
                    RuntimeOutputLedgerRecord.job_id == job_id,
                    RuntimeOutputLedgerRecord.alert_id.is_not(None),
                )
            )
            if alert_id is not None
        )
        if not alert_ids:
            return frozenset(), frozenset()
        serialized_alert_ids = {str(alert_id) for alert_id in alert_ids}
        group_ids = frozenset(
            group_id
            for group_id, member_ids in self._session.execute(
                select(AlertGroupRecord.group_id, AlertGroupRecord.alert_ids).order_by(
                    AlertGroupRecord.group_id
                )
            ).yield_per(500)
            if not serialized_alert_ids.isdisjoint(member_ids)
        )
        hypothesis_ids = (
            frozenset(
                self._session.scalars(
                    select(ThreatHypothesisRecord.hypothesis_id).where(
                        ThreatHypothesisRecord.group_id.in_(group_ids)
                    )
                )
            )
            if group_ids
            else frozenset()
        )
        return group_ids, hypothesis_ids
