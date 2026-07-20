"""Round-trip every core entity through repositories with transaction audit."""

from datetime import UTC, datetime
from pathlib import Path

from aegishunt.config import DatabaseSettings
from aegishunt.schemas import (
    AlertGroup,
    AnalystFeedback,
    DetectionResult,
    InvestigationCase,
    ModelVersion,
    NetworkFlow,
    SecurityAlert,
    TelemetrySource,
    ThreatHypothesis,
)
from aegishunt.schemas.enums import (
    AnalystVerdict,
    FeedbackObjectType,
    IngestionMode,
    ModelType,
    NetworkProtocol,
    Severity,
    SourceType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AnalystFeedbackRepository,
    AuditLogRepository,
    DetectionResultRepository,
    InvestigationCaseRepository,
    ModelVersionRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_core_entities_round_trip_without_business_sql(tmp_path: Path) -> None:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'repositories.db'}"))
    database.initialize()
    try:
        with database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            source_repository = TelemetrySourceRepository(session, audit)
            flow_repository = NetworkFlowRepository(session, audit)
            detection_repository = DetectionResultRepository(session, audit)
            alert_repository = SecurityAlertRepository(session, audit)
            group_repository = AlertGroupRepository(session, audit)
            hypothesis_repository = ThreatHypothesisRepository(session, audit)
            case_repository = InvestigationCaseRepository(session, audit)
            feedback_repository = AnalystFeedbackRepository(session, audit)
            model_repository = ModelVersionRepository(session, audit)

            source = source_repository.add(
                TelemetrySource(
                    source_type=SourceType.PCAP,
                    filename_or_interface="reviewed-sample.pcap",
                    ingestion_mode=IngestionMode.IMPORT,
                ),
                actor="integration-test",
            )
            flow = flow_repository.add(
                NetworkFlow(
                    source_id=source.source_id,
                    capture_session_id="session-1",
                    first_seen=NOW,
                    last_seen=NOW,
                    duration=0.0,
                    source_ip="192.0.2.1",
                    destination_ip="192.0.2.2",
                    source_port=12345,
                    destination_port=443,
                    protocol=NetworkProtocol.TCP,
                    forward_packet_count=1,
                    backward_packet_count=1,
                    forward_bytes=60,
                    backward_bytes=60,
                ),
                actor="integration-test",
            )
            detection = detection_repository.add(
                DetectionResult(
                    flow_id=flow.flow_id,
                    supervised_label="0",
                    supervised_probability=0.4,
                    supervised_threshold=0.5,
                    anomaly_raw_score=-0.2,
                    normalized_anomaly_score=0.3,
                    anomaly_threshold=0.6,
                    fusion_score=0.5,
                    fusion_threshold=0.5,
                    risk_score=0.5,
                    risk_source="fusion_score",
                    severity=Severity.MEDIUM,
                    alert_threshold=0.7,
                    model_versions={"supervised": "1", "anomaly": "1"},
                    policy_versions={"fusion": "1", "risk": "1"},
                    policy_checksums={"fusion": "a" * 64, "risk": "b" * 64},
                    feature_schema_version="1.0.0",
                    explanation={"limitations": ["repository fixture only"]},
                ),
                actor="integration-test",
            )
            alert = alert_repository.add(
                SecurityAlert(
                    detection_id=detection.detection_id,
                    alert_type="TEST_CONTRACT",
                    severity=Severity.MEDIUM,
                    risk_score=0.5,
                    title="Repository contract fixture",
                    description="Validates persistence only; it is not a detection claim.",
                    involved_entities=[f"flow_id:{flow.flow_id}"],
                    evidence={"risk_score": 0.5, "alert_threshold": 0.5},
                    reason_codes=["RISK_SCORE_ABOVE_ALERT_THRESHOLD"],
                    explanation={"limitations": ["not a confirmed attack"]},
                    model_versions={"supervised": "1", "anomaly": "1"},
                    policy_versions={"fusion": "1", "risk": "1"},
                    created_at=NOW,
                    updated_at=NOW,
                ),
                actor="integration-test",
            )
            group = group_repository.add(
                AlertGroup(
                    alert_ids=[str(alert.alert_id)],
                    correlation_score=0.5,
                    first_seen=NOW,
                    last_seen=NOW,
                    summary="Repository contract fixture",
                ),
                actor="integration-test",
            )
            hypothesis = hypothesis_repository.add(
                ThreatHypothesis(
                    title="Repository contract fixture",
                    description="No real threat assertion is made.",
                    confidence=0.5,
                    severity=Severity.MEDIUM,
                    supporting_alert_ids=group.alert_ids,
                    first_seen=NOW,
                    last_seen=NOW,
                ),
                actor="integration-test",
            )
            case = case_repository.add(
                InvestigationCase(
                    hypothesis_id=hypothesis.hypothesis_id,
                    title="Repository contract fixture",
                    description="Persistence lifecycle validation.",
                ),
                actor="integration-test",
            )
            feedback = feedback_repository.add(
                AnalystFeedback(
                    object_type=FeedbackObjectType.CASE,
                    object_id=str(case.case_id),
                    verdict=AnalystVerdict.NEEDS_MORE_INFORMATION,
                    confidence=0.5,
                ),
                actor="integration-test",
            )
            model = model_repository.add(
                ModelVersion(
                    model_type=ModelType.SUPERVISED,
                    version="repository-contract-v1",
                    algorithm="not-trained",
                    training_dataset="not-applicable",
                    artifact_path="artifacts/models/not-created",
                ),
                actor="integration-test",
            )

        with database.session() as session:
            audit = AuditLogRepository(session)
            source_repository = TelemetrySourceRepository(session, audit)
            flow_repository = NetworkFlowRepository(session, audit)
            detection_repository = DetectionResultRepository(session, audit)
            alert_repository = SecurityAlertRepository(session, audit)
            group_repository = AlertGroupRepository(session, audit)
            hypothesis_repository = ThreatHypothesisRepository(session, audit)
            case_repository = InvestigationCaseRepository(session, audit)
            feedback_repository = AnalystFeedbackRepository(session, audit)
            model_repository = ModelVersionRepository(session, audit)

            assert source_repository.get(source.source_id) == source
            assert source_repository.list() == [source]
            assert flow_repository.get(flow.flow_id) == flow
            assert detection_repository.get(detection.detection_id) == detection
            assert alert_repository.get(alert.alert_id) == alert
            assert group_repository.get(group.group_id) == group
            assert hypothesis_repository.get(hypothesis.hypothesis_id) == hypothesis
            assert case_repository.get(case.case_id) == case
            assert feedback_repository.get(feedback.feedback_id) == feedback
            assert model_repository.get(model.model_id) == model
            assert len(audit.list()) == 9
    finally:
        database.dispose()
