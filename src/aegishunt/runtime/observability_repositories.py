"""Runtime worker and resource observation repositories."""

from __future__ import annotations

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from aegishunt.runtime.contracts import RuntimeResourceSample, RuntimeWorker
from aegishunt.storage.models.runtime import (
    RuntimeResourceSampleRecord,
    RuntimeWorkerRecord,
)


class RuntimeWorkerRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def upsert(self, worker: RuntimeWorker) -> RuntimeWorker:
        row = self._session.get(RuntimeWorkerRecord, worker.worker_id)
        values = worker.model_dump(mode="python")
        if row is None:
            row = RuntimeWorkerRecord(**values)
            self._session.add(row)
        else:
            for name, value in values.items():
                setattr(row, name, value)
        self._session.flush()
        return RuntimeWorker.model_validate(row)

    def get(self, worker_id: str) -> RuntimeWorker | None:
        row = self._session.get(RuntimeWorkerRecord, worker_id)
        return None if row is None else RuntimeWorker.model_validate(row)

    def list(self, *, limit: int = 100, offset: int = 0) -> list[RuntimeWorker]:
        rows = self._session.scalars(
            select(RuntimeWorkerRecord)
            .order_by(RuntimeWorkerRecord.worker_id)
            .limit(limit)
            .offset(offset)
        ).all()
        return [RuntimeWorker.model_validate(row) for row in rows]


class RuntimeResourceRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add_and_prune(
        self,
        sample: RuntimeResourceSample,
        *,
        retain: int,
    ) -> RuntimeResourceSample:
        row = RuntimeResourceSampleRecord(**sample.model_dump(mode="python"))
        self._session.add(row)
        self._session.flush()
        keep = (
            select(RuntimeResourceSampleRecord.sample_id)
            .where(RuntimeResourceSampleRecord.worker_id == sample.worker_id)
            .order_by(
                RuntimeResourceSampleRecord.sampled_at.desc(),
                RuntimeResourceSampleRecord.sample_id.desc(),
            )
            .limit(retain)
        )
        self._session.execute(
            delete(RuntimeResourceSampleRecord).where(
                RuntimeResourceSampleRecord.worker_id == sample.worker_id,
                RuntimeResourceSampleRecord.sample_id.not_in(keep),
            )
        )
        return RuntimeResourceSample.model_validate(row)

    def latest(self) -> tuple[RuntimeResourceSample, ...]:
        latest_time = (
            select(
                RuntimeResourceSampleRecord.worker_id,
                func.max(RuntimeResourceSampleRecord.sampled_at).label("sampled_at"),
            )
            .group_by(RuntimeResourceSampleRecord.worker_id)
            .subquery()
        )
        rows = self._session.scalars(
            select(RuntimeResourceSampleRecord)
            .join(
                latest_time,
                (
                    RuntimeResourceSampleRecord.worker_id == latest_time.c.worker_id
                )
                & (
                    RuntimeResourceSampleRecord.sampled_at == latest_time.c.sampled_at
                ),
            )
            .order_by(RuntimeResourceSampleRecord.worker_id)
        ).all()
        return tuple(RuntimeResourceSample.model_validate(row) for row in rows)
