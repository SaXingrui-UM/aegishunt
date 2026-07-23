"""Idempotent runtime output-ledger persistence."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from aegishunt.runtime.contracts import RuntimeOutputLedger
from aegishunt.storage.models.runtime import RuntimeOutputLedgerRecord


class RuntimeOutputLedgerRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, entry: RuntimeOutputLedger) -> RuntimeOutputLedger:
        row = RuntimeOutputLedgerRecord(**entry.model_dump(mode="python"))
        self._session.add(row)
        self._session.flush()
        return RuntimeOutputLedger.model_validate(row)

    def get_for_flow(self, job_id: UUID, flow_id: UUID) -> RuntimeOutputLedger | None:
        row = self._session.scalar(
            select(RuntimeOutputLedgerRecord).where(
                RuntimeOutputLedgerRecord.job_id == job_id,
                RuntimeOutputLedgerRecord.flow_id == flow_id,
            )
        )
        return None if row is None else RuntimeOutputLedger.model_validate(row)

    def list_for_job(self, job_id: UUID) -> tuple[RuntimeOutputLedger, ...]:
        rows = self._session.scalars(
            select(RuntimeOutputLedgerRecord)
            .where(RuntimeOutputLedgerRecord.job_id == job_id)
            .order_by(RuntimeOutputLedgerRecord.flow_id)
        ).all()
        return tuple(RuntimeOutputLedger.model_validate(row) for row in rows)
