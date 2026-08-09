"""Read-only operational statistics isolated to one replay job."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Integer, case, cast, distinct, func, select
from sqlalchemy.orm import Session

from aegishunt.api.contracts import (
    ReplayScoreBucket,
    ReplayScoreDistribution,
    ReplayStatistics,
)
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.storage.models import (
    DetectionResultRecord,
    RuntimeOutputLedgerRecord,
    TelemetrySourceRecord,
)

_SCORE_COLUMNS = {
    "supervised": DetectionResultRecord.supervised_probability,
    "anomaly": DetectionResultRecord.normalized_anomaly_score,
    "fusion": DetectionResultRecord.fusion_score,
    "risk": DetectionResultRecord.risk_score,
}


class ReplayStatisticsReader:
    """Aggregate immutable output-ledger evidence for one stored source."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def read(self, source_id: UUID) -> ReplayStatistics | None:
        source = self._session.get(TelemetrySourceRecord, source_id)
        if source is None:
            return None
        job = RuntimeJobRepository(self._session).get_by_source(source_id)
        if job is None:
            return ReplayStatistics(
                status="unavailable",
                message="No replay job exists for this stored source.",
                source_id=source.source_id,
                source_name=source.filename_or_interface,
                runtime_job_id=None,
                runtime_status=None,
                flow_count=0,
                detection_count=0,
                alert_count=0,
                alert_rate=None,
                duration_ms=None,
                throughput_flows_per_second=None,
                score_distributions=(),
            )

        flow_count, detection_count, alert_count = self._session.execute(
            select(
                func.count(distinct(RuntimeOutputLedgerRecord.flow_id)),
                func.count(distinct(RuntimeOutputLedgerRecord.detection_id)),
                func.count(distinct(RuntimeOutputLedgerRecord.alert_id)),
            ).where(RuntimeOutputLedgerRecord.job_id == job.job_id)
        ).one()
        flows = int(flow_count)
        detections = int(detection_count)
        alerts = int(alert_count)
        duration_ms = self._duration_ms(job.started_at, job.completed_at)
        duration_seconds = None if duration_ms is None else duration_ms / 1_000.0
        throughput = (
            None
            if duration_seconds is None or duration_seconds <= 0.0
            else flows / duration_seconds
        )
        return ReplayStatistics(
            status="available",
            message="Statistics are isolated to the selected replay job.",
            source_id=source.source_id,
            source_name=source.filename_or_interface,
            runtime_job_id=job.job_id,
            runtime_status=job.status,
            flow_count=flows,
            detection_count=detections,
            alert_count=alerts,
            alert_rate=None if flows == 0 else alerts / flows,
            duration_ms=duration_ms,
            throughput_flows_per_second=throughput,
            score_distributions=tuple(
                self._distribution(
                    job.job_id,
                    score=score,
                    detection_count=detections,
                )
                for score in _SCORE_COLUMNS
            ),
        )

    @staticmethod
    def _duration_ms(
        started_at: datetime | None,
        completed_at: datetime | None,
    ) -> float | None:
        if started_at is None or completed_at is None:
            return None
        duration = completed_at - started_at
        return max(0.0, duration.total_seconds() * 1_000.0)

    def _distribution(
        self,
        job_id: UUID,
        *,
        score: str,
        detection_count: int,
    ) -> ReplayScoreDistribution:
        column = _SCORE_COLUMNS[score]
        condition = (
            RuntimeOutputLedgerRecord.job_id == job_id,
            column.is_not(None),
        )
        available, minimum, mean, maximum = self._session.execute(
            select(
                func.count(column),
                func.min(column),
                func.avg(column),
                func.max(column),
            )
            .select_from(RuntimeOutputLedgerRecord)
            .join(
                DetectionResultRecord,
                DetectionResultRecord.detection_id
                == RuntimeOutputLedgerRecord.detection_id,
            )
            .where(*condition)
        ).one()
        bucket_index = case(
            (column >= 1.0, 9),
            else_=cast(column * 10.0, Integer),
        )
        observed = {
            int(index): int(count)
            for index, count in self._session.execute(
                select(bucket_index.label("bucket"), func.count())
                .select_from(RuntimeOutputLedgerRecord)
                .join(
                    DetectionResultRecord,
                    DetectionResultRecord.detection_id
                    == RuntimeOutputLedgerRecord.detection_id,
                )
                .where(*condition)
                .group_by(bucket_index)
                .order_by(bucket_index)
            ).all()
        }
        available_count = int(available)
        return ReplayScoreDistribution(
            score=score,  # type: ignore[arg-type]
            available_count=available_count,
            missing_count=max(0, detection_count - available_count),
            minimum=None if minimum is None else float(minimum),
            mean=None if mean is None else float(mean),
            maximum=None if maximum is None else float(maximum),
            buckets=tuple(
                ReplayScoreBucket(
                    label=(
                        f"[{index / 10:.1f}, {(index + 1) / 10:.1f}]"
                        if index == 9
                        else f"[{index / 10:.1f}, {(index + 1) / 10:.1f})"
                    ),
                    lower_bound=index / 10,
                    upper_bound=(index + 1) / 10,
                    count=observed.get(index, 0),
                )
                for index in range(10)
            ),
        )
