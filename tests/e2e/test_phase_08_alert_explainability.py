"""Offline Phase 8 flow-to-detection-to-alert-to-verdict E2E."""

from __future__ import annotations

from pathlib import Path

from aegishunt.config import DatabaseSettings
from aegishunt.detection.service import DetectionAlertService
from aegishunt.explainability.artifacts import (
    load_explanation_artifact,
    save_explanation_artifact,
)
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import (
    AnalystVerdict,
    IngestionMode,
    LifecycleStatus,
    SourceType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    DetectionResultRepository,
    InvestigationCaseRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.detection import (
    DeterministicScorer,
    canonical_flow,
    explanation_artifact,
    risk_policy,
)


def test_phase_08_offline_e2e_persists_explains_and_audits(tmp_path: Path) -> None:
    expected_artifact = explanation_artifact()
    artifact_path = save_explanation_artifact(
        root=tmp_path / "explanations",
        manifest=expected_artifact.manifest,
        reference_profile=expected_artifact.reference_profile,
        native_importance=expected_artifact.native_importance,
        permutation_importance=expected_artifact.permutation_importance,
        reason_catalog=expected_artifact.reason_catalog,
        protocol=expected_artifact.protocol,
    )
    artifact = load_explanation_artifact(
        artifact_path,
        root=tmp_path / "explanations",
    )
    database_path = tmp_path / "phase-08-e2e.sqlite3"
    database = Database(DatabaseSettings(url=f"sqlite:///{database_path}"))
    assert database.initialize() == 3
    flow = canonical_flow()
    try:
        with database.session() as session, session.begin():
            TelemetrySourceRepository(session).add(
                TelemetrySource(
                    source_id=flow.source_id,
                    source_type=SourceType.PCAP,
                    filename_or_interface="controlled-e2e.pcap",
                    ingestion_mode=IngestionMode.IMPORT,
                    status=LifecycleStatus.COMPLETED,
                )
            )
            NetworkFlowRepository(session).add(flow)
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=artifact,
            )
            detection, alert = service.evaluate_flow(
                flow,
                DeterministicScorer(),
                actor="phase-08-e2e",
            )
            assert alert is not None
            assert alert.reason_codes
            assert alert.evidence["alert_threshold"] == 0.7
            assert alert.evidence["flow_id"] == str(flow.flow_id)
            assert alert.evidence["scoring_mode"] == "fusion_score"
            assert alert.evidence["severity_band"] == alert.severity.value
            assert alert.evidence["model_versions"] == alert.model_versions
            assert alert.evidence["policy_versions"] == alert.policy_versions
            assert alert.evidence["reason_codes"] == alert.reason_codes
            assert alert.evidence["top_local_contributions"]
            assert alert.evidence["generated_at"] == alert.created_at.isoformat()
            assert alert.explanation["observed_facts"]
            assert alert.explanation["model_inferences"]

        database.dispose()
        database = Database(DatabaseSettings(url=f"sqlite:///{database_path}"))
        assert database.initialize() == 3
        with database.session() as session, session.begin():
            assert DetectionResultRepository(session).get(detection.detection_id) == detection
            reloaded = SecurityAlertRepository(session).get(alert.alert_id)
            assert reloaded == alert
            updated = SecurityAlertRepository(
                session,
                AuditLogRepository(session),
            ).update_verdict(
                alert.alert_id,
                AnalystVerdict.NEEDS_MORE_INFORMATION,
                actor="e2e-analyst",
            )
            assert updated.analyst_verdict is AnalystVerdict.NEEDS_MORE_INFORMATION
            assert updated.evidence == alert.evidence
            assert AlertGroupRepository(session).list() == []
            assert ThreatHypothesisRepository(session).list() == []
            assert InvestigationCaseRepository(session).list() == []

        with database.session() as session:
            assert any(
                event.action == "update_verdict"
                for event in AuditLogRepository(session).list()
            )
    finally:
        database.dispose()
