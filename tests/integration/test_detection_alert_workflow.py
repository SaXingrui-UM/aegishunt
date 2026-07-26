"""Phase 8 transactional detection, alert, reload, and verdict integration."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.config import DatabaseSettings
from aegishunt.detection.contracts import VerifiedScores
from aegishunt.detection.errors import DetectionContractError, DetectionPersistenceError
from aegishunt.detection.service import DetectionAlertService
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
    verified_scores,
)


class BelowThresholdScorer:
    def score(self, features: tuple[float, ...]) -> VerifiedScores:
        del features
        return verified_scores(fusion_score=0.6)


def _database(tmp_path: Path) -> Database:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase-08.sqlite3'}"))
    assert database.initialize() == 5
    return database


def _persist_flow(database: Database, *, flow_id: UUID | None = None) -> UUID:
    flow = canonical_flow()
    if flow_id is not None:
        flow = flow.model_copy(update={"flow_id": flow_id})
    with database.session() as session, session.begin():
        source = TelemetrySource(
            source_id=flow.source_id,
            source_type=SourceType.PCAP,
            filename_or_interface="controlled-phase-08.pcap",
            ingestion_mode=IngestionMode.IMPORT,
            status=LifecycleStatus.COMPLETED,
        )
        TelemetrySourceRepository(session).add(source)
        NetworkFlowRepository(session).add(flow)
    return flow.flow_id


def test_detection_alert_verdict_and_restart_persistence(tmp_path: Path) -> None:
    database = _database(tmp_path)
    flow_id = _persist_flow(database)
    try:
        with database.session() as session, session.begin():
            flow = NetworkFlowRepository(session).get(flow_id)
            assert flow is not None
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=explanation_artifact(),
            )
            detection, alert = service.evaluate_flow(
                flow,
                DeterministicScorer(),
                actor="phase-08-integration",
            )
            assert detection.risk_score == 0.8
            assert alert is not None
            assert alert.risk_score == detection.risk_score
            assert alert.reason_codes
            assert alert.analyst_verdict is None
            assert "ground_truth" not in str(detection.explanation)
            assert "ignored-by-phase-8" not in str(detection.explanation)

        database.dispose()
        database = _database(tmp_path)
        with database.session() as session, session.begin():
            stored_detection = DetectionResultRepository(session).get(detection.detection_id)
            stored_alert = SecurityAlertRepository(session).get(alert.alert_id)
            assert stored_detection == detection
            assert stored_alert == alert
            immutable = (
                stored_alert.evidence,
                stored_alert.risk_score,
                stored_alert.severity,
                stored_alert.reason_codes,
            )
            repository = SecurityAlertRepository(session, AuditLogRepository(session))
            updated = repository.update_verdict(
                alert.alert_id,
                AnalystVerdict.FALSE_POSITIVE,
                actor="analyst-1",
            )
            assert updated.analyst_verdict is AnalystVerdict.FALSE_POSITIVE
            assert (
                updated.evidence,
                updated.risk_score,
                updated.severity,
                updated.reason_codes,
            ) == immutable
            assert repository.update_verdict(
                alert.alert_id,
                AnalystVerdict.FALSE_POSITIVE,
                actor="analyst-1",
            ) == updated
            assert AlertGroupRepository(session).list() == []
            assert ThreatHypothesisRepository(session).list() == []
            assert InvestigationCaseRepository(session).list() == []

        with database.session() as session:
            actions = [event.action for event in AuditLogRepository(session).list()]
            assert actions.count("create") == 2
            assert actions.count("update_verdict") == 1
    finally:
        database.dispose()


def test_below_threshold_persists_detection_without_alert(tmp_path: Path) -> None:
    database = _database(tmp_path)
    flow_id = _persist_flow(database)
    try:
        with database.session() as session, session.begin():
            flow = NetworkFlowRepository(session).get(flow_id)
            assert flow is not None
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=explanation_artifact(),
            )
            detection, alert = service.evaluate_flow(flow, BelowThresholdScorer())
            assert detection.risk_score == 0.6
            assert alert is None
            assert SecurityAlertRepository(session).list() == []
    finally:
        database.dispose()


def test_duplicate_detection_is_rejected_without_overwrite(tmp_path: Path) -> None:
    database = _database(tmp_path)
    flow_id = _persist_flow(database)
    try:
        with database.session() as session, session.begin():
            flow = NetworkFlowRepository(session).get(flow_id)
            assert flow is not None
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=explanation_artifact(),
            )
            detection, _ = service.evaluate_flow(flow, DeterministicScorer())

        with database.session() as session, session.begin():
            flow = NetworkFlowRepository(session).get(flow_id)
            assert flow is not None
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=explanation_artifact(),
            )
            with pytest.raises(DetectionPersistenceError, match="already exists"):
                service.evaluate_flow(flow, DeterministicScorer())

        with database.session() as session:
            assert DetectionResultRepository(session).list() == [detection]
            assert len(SecurityAlertRepository(session).list()) == 1
    finally:
        database.dispose()


def test_explanation_identity_mismatch_fails_before_persistence(tmp_path: Path) -> None:
    database = _database(tmp_path)
    flow_id = _persist_flow(database)
    artifact = explanation_artifact()
    mismatched = artifact.model_copy(
        update={
            "manifest": artifact.manifest.model_copy(
                update={"anomaly_model_version": "unexpected-version"}
            )
        }
    )
    try:
        with database.session() as session, session.begin():
            flow = NetworkFlowRepository(session).get(flow_id)
            assert flow is not None
            service = DetectionAlertService(
                session,
                risk_policy=risk_policy(),
                explanation_artifact=mismatched,
            )
            with pytest.raises(DetectionContractError, match="artifact identities"):
                service.evaluate_flow(flow, DeterministicScorer())

        with database.session() as session:
            assert DetectionResultRepository(session).list() == []
            assert SecurityAlertRepository(session).list() == []
    finally:
        database.dispose()
