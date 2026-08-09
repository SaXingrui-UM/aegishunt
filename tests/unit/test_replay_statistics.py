"""Replay statistics remain isolated to one source/job output ledger."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import UUID

from aegishunt.api.replay_statistics import ReplayStatisticsReader
from aegishunt.config import DatabaseSettings
from aegishunt.runtime.contracts import (
    RuntimeJobStatus,
    RuntimeOutputLedger,
    RuntimeStage,
)
from aegishunt.runtime.job_store import RuntimeJobStore
from aegishunt.runtime.output_repository import RuntimeOutputLedgerRepository
from aegishunt.schemas import DetectionResult, SecurityAlert, TelemetrySource
from aegishunt.schemas.enums import (
    AlertStatus,
    IngestionMode,
    LifecycleStatus,
    Severity,
    SourceType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
)
from tests.fixtures.detection import NOW, canonical_flow
from tests.fixtures.runtime import runtime_job


def _detection(identifier: int, flow_id: UUID, score: float) -> DetectionResult:
    return DetectionResult(
        detection_id=UUID(int=identifier),
        flow_id=flow_id,
        supervised_label="suspicious",
        supervised_probability=score,
        supervised_threshold=0.5,
        anomaly_raw_score=-0.2,
        normalized_anomaly_score=score,
        anomaly_threshold=0.6,
        fusion_score=score,
        fusion_threshold=0.5,
        risk_score=score,
        risk_source="fusion_score",
        severity=Severity.HIGH,
        alert_threshold=0.7,
        model_versions={"supervised": "1", "anomaly": "1"},
        policy_versions={"fusion": "1", "risk": "1"},
        policy_checksums={"fusion": "a" * 64, "risk": "b" * 64},
        feature_schema_version="1.0.0",
        reason_codes=["supervised_threshold_exceeded"],
        explanation={"summary": "controlled"},
        detected_at=NOW,
    )


def _alert(identifier: int, detection_id: UUID, score: float) -> SecurityAlert:
    return SecurityAlert(
        alert_id=UUID(int=identifier),
        detection_id=detection_id,
        alert_type="controlled",
        severity=Severity.HIGH,
        risk_score=score,
        title="Controlled alert",
        description="Controlled replay alert.",
        involved_entities=["ip:192.0.2.10"],
        evidence={"observed_facts": {"flow": "controlled"}},
        reason_codes=["supervised_threshold_exceeded"],
        explanation={"summary": "controlled"},
        model_versions={"supervised": "1"},
        policy_versions={"risk": "1"},
        status=AlertStatus.OPEN,
        created_at=NOW,
        updated_at=NOW,
    )


def test_replay_statistics_use_only_selected_job_ledger(tmp_path: Path) -> None:
    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'statistics.sqlite3'}")
    )
    database.initialize()
    source_id = UUID(int=9_001)
    completed_at = NOW + timedelta(seconds=2)
    job = runtime_job(source_id=source_id, created_at=NOW).model_copy(
        update={
            "status": RuntimeJobStatus.COMPLETED,
            "current_stage": RuntimeStage.COMPLETION,
            "progress": 1.0,
            "started_at": NOW,
            "updated_at": completed_at,
            "completed_at": completed_at,
        }
    )
    flows = tuple(
        canonical_flow().model_copy(
            update={"flow_id": UUID(int=9_100 + index), "source_id": source_id}
        )
        for index in range(2)
    )
    detections = (
        _detection(9_201, flows[0].flow_id, 0.05),
        _detection(9_202, flows[1].flow_id, 0.95),
    )
    alert = _alert(9_301, detections[1].detection_id, 0.95)
    with database.session() as session, session.begin():
        TelemetrySourceRepository(session).add(
            TelemetrySource(
                source_id=source_id,
                source_type=SourceType.PCAP,
                filename_or_interface="selected.pcap",
                ingestion_mode=IngestionMode.REPLAY,
                status=LifecycleStatus.COMPLETED,
                started_at=NOW,
                completed_at=completed_at,
                records_processed=2,
                checksum=job.snapshot.source_checksum,
            )
        )
        RuntimeJobStore(session).add(job, actor="unit-test")
        for flow, detection in zip(flows, detections, strict=True):
            NetworkFlowRepository(session).add(flow)
            DetectionResultRepository(session).add(detection)
        SecurityAlertRepository(session).add(alert)
        ledgers = RuntimeOutputLedgerRepository(session)
        for index, (flow, detection) in enumerate(
            zip(flows, detections, strict=True)
        ):
            ledgers.add(
                RuntimeOutputLedger(
                    job_id=job.job_id,
                    source_id=source_id,
                    flow_id=flow.flow_id,
                    detection_id=detection.detection_id,
                    alert_id=alert.alert_id if index == 1 else None,
                    output_checksum=f"{index + 1}" * 64,
                    created_at=NOW,
                )
            )

    with database.session() as session:
        result = ReplayStatisticsReader(session).read(source_id)

    assert result is not None
    assert result.status == "available"
    assert result.runtime_job_id == job.job_id
    assert result.flow_count == 2
    assert result.detection_count == 2
    assert result.alert_count == 1
    assert result.alert_rate == 0.5
    assert result.duration_ms == 2_000.0
    assert result.throughput_flows_per_second == 1.0
    for distribution in result.score_distributions:
        assert distribution.available_count == 2
        assert distribution.missing_count == 0
        assert distribution.minimum == 0.05
        assert distribution.mean == 0.5
        assert distribution.maximum == 0.95
        assert distribution.buckets[0].count == 1
        assert distribution.buckets[9].count == 1
