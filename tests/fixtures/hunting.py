"""Controlled Phase 9 alerts and groups; no network or external evidence."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from aegishunt.correlation.config import LoadedCorrelationPolicy, load_correlation_policy
from aegishunt.schemas import AlertGroup, DetectionResult, SecurityAlert, TelemetrySource
from aegishunt.schemas.enums import (
    AnalystVerdict,
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
from tests.fixtures.detection import canonical_flow

BASE_TIME = datetime(2026, 7, 22, 0, 0, tzinfo=UTC)
GROUP_GENERATED_AT = BASE_TIME + timedelta(days=1)
HYPOTHESIS_GENERATED_AT = BASE_TIME + timedelta(days=2)
STATUS_UPDATED_AT = BASE_TIME + timedelta(days=3)


def correlation_policy() -> LoadedCorrelationPolicy:
    return load_correlation_policy(Path(__file__).parents[2] / "configs/correlation.yaml")


def alert(
    index: int,
    *,
    source_ip: str = "192.0.2.10",
    destination_ip: str = "198.51.100.20",
    seconds: float = 0.0,
    risk_score: float = 0.8,
    alert_type: str = "multi_engine_suspicion",
    reason_codes: tuple[str, ...] = ("RISK_SCORE_ABOVE_ALERT_THRESHOLD",),
    verdict: AnalystVerdict | None = None,
) -> SecurityAlert:
    observed = BASE_TIME + timedelta(seconds=seconds)
    return SecurityAlert(
        alert_id=UUID(int=1_000 + index),
        detection_id=UUID(int=2_000 + index),
        alert_type=alert_type,
        severity=Severity.HIGH,
        risk_score=risk_score,
        title="Controlled suspicious behavior",
        description="Controlled Phase 9 test evidence; not attack confirmation.",
        involved_entities=[
            f"source_ip:{source_ip}",
            f"destination_ip:{destination_ip}",
            f"flow_id:{UUID(int=3_000 + index)}",
        ],
        evidence={
            "observed_facts": {
                "flow_id": str(UUID(int=3_000 + index)),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": "tcp",
                "first_seen": observed.isoformat(),
                "last_seen": (observed + timedelta(seconds=1)).isoformat(),
            },
            "top_local_contributions": [],
        },
        reason_codes=list(reason_codes),
        explanation={"limitations": ["controlled evidence only"]},
        model_versions={"supervised": "1.0.1", "anomaly": "1.0.0"},
        policy_versions={"fusion": "1.0.0", "risk": "1.0.0"},
        analyst_verdict=verdict,
        created_at=observed + timedelta(days=30),
        updated_at=observed + timedelta(days=30),
    )


def group(
    *,
    score: float = 0.8,
    rules: tuple[str, ...] = ("source_centered_reconnaissance",),
    reason_codes: tuple[str, ...] = ("RISK_SCORE_ABOVE_ALERT_THRESHOLD",),
) -> AlertGroup:
    loaded = correlation_policy()
    return AlertGroup(
        group_id=UUID(int=4_000),
        alert_ids=[str(UUID(int=1_001)), str(UUID(int=1_002))],
        entity_keys=["source_ip:192.0.2.10"],
        matched_rule_ids=sorted(rules),
        correlation_score=score,
        score_components={
            "risk": 0.8,
            "alert_count": 0.4,
            "evidence_diversity": 0.5,
            "temporal_density": 1.0,
        },
        first_seen=BASE_TIME,
        last_seen=BASE_TIME + timedelta(seconds=20),
        alert_count=2,
        severity=Severity.HIGH,
        summary="Controlled group requiring analyst review.",
        evidence={
            "member_alerts": [
                {"alert_id": "a", "reason_codes": list(reason_codes)},
                {"alert_id": "b", "reason_codes": list(reason_codes)},
            ],
            "rule_matches": [],
            "score_semantics": "not attack probability",
            "generated_at": GROUP_GENERATED_AT.isoformat(),
        },
        policy_id=loaded.policy.policy_id,
        policy_version=loaded.policy.policy_version,
        policy_checksum=loaded.configuration_checksum,
        status="open",
        group_schema_version="1.0.0",
        created_at=GROUP_GENERATED_AT,
    )


def seed_alerts(database: Database, alerts: list[SecurityAlert]) -> None:
    """Persist controlled FK-complete Phase 8 evidence for Phase 9 tests."""

    base_flow = canonical_flow()
    with database.session() as session, session.begin():
        TelemetrySourceRepository(session).add(
            TelemetrySource(
                source_id=base_flow.source_id,
                source_type=SourceType.PCAP,
                filename_or_interface="controlled-phase-09.pcap",
                ingestion_mode=IngestionMode.IMPORT,
                status=LifecycleStatus.COMPLETED,
            )
        )
        for source_alert in alerts:
            facts = source_alert.evidence["observed_facts"]
            assert isinstance(facts, dict)
            first_seen = datetime.fromisoformat(str(facts["first_seen"]))
            last_seen = datetime.fromisoformat(str(facts["last_seen"]))
            flow_id = UUID(str(facts["flow_id"]))
            flow = base_flow.model_copy(
                update={
                    "flow_id": flow_id,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "duration": (last_seen - first_seen).total_seconds(),
                    "source_ip": str(facts["source_ip"]),
                    "destination_ip": str(facts["destination_ip"]),
                }
            )
            NetworkFlowRepository(session).add(flow)
            DetectionResultRepository(session).add(
                DetectionResult(
                    detection_id=source_alert.detection_id,
                    flow_id=flow_id,
                    supervised_label="suspicious",
                    supervised_probability=0.8,
                    supervised_threshold=0.5,
                    anomaly_raw_score=-0.2,
                    normalized_anomaly_score=0.75,
                    anomaly_threshold=0.6,
                    fusion_score=source_alert.risk_score,
                    fusion_threshold=0.5,
                    risk_score=source_alert.risk_score,
                    risk_source="fusion_score",
                    severity=source_alert.severity,
                    alert_threshold=0.7,
                    model_versions=source_alert.model_versions,
                    policy_versions=source_alert.policy_versions,
                    policy_checksums={"fusion": "a" * 64, "risk": "b" * 64},
                    feature_schema_version="1.0.0",
                    reason_codes=source_alert.reason_codes,
                    explanation=source_alert.explanation,
                    detected_at=first_seen,
                )
            )
            SecurityAlertRepository(session).add(source_alert)
