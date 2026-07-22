"""Phase 10 transactional case lifecycle, feedback, persistence, and audit tests."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.cases.errors import (
    CaseConflictError,
    CaseEligibilityError,
    CaseTransitionError,
)
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import DatabaseSettings
from aegishunt.feedback.errors import FeedbackConflictError
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
    FeedbackObjectType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AnalystFeedbackRepository,
    AuditLogRepository,
    CaseEvidenceReferenceRepository,
    CaseNoteRepository,
    DetectionResultRepository,
    InvestigationCaseRepository,
    SecurityAlertRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.cases import (
    CASE_CLOSED_AT,
    CASE_CREATED_AT,
    CASE_UPDATED_AT,
    case_policy,
    eligible_source_metadata,
    seed_reviewable_hypothesis,
)


def _database(path: Path) -> Database:
    database = Database(DatabaseSettings(url=f"sqlite:///{path}"))
    assert database.initialize() == 4
    return database


def test_case_feedback_lifecycle_is_idempotent_audited_and_restart_safe(
    tmp_path: Path,
) -> None:
    path = tmp_path / "phase-10.sqlite3"
    database = _database(path)
    hypothesis = seed_reviewable_hypothesis(
        database, source_metadata=eligible_source_metadata()
    )
    loaded = case_policy()
    try:
        with database.session() as session:
            original_hypothesis = ThreatHypothesisRepository(session).get(
                hypothesis.hypothesis_id
            )
            original_alerts = {
                str(item.alert_id): item.model_dump(exclude={"analyst_verdict", "updated_at"})
                for item in SecurityAlertRepository(session).list()
            }
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            )
            created = service.create_from_hypothesis(
                hypothesis.hypothesis_id, actor="case-analyst"
            )
            duplicate = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_CREATED_AT + timedelta(days=1),
            ).create_from_hypothesis(hypothesis.hypothesis_id, actor="case-analyst")
            assert duplicate == created
            assert created.created_at == CASE_CREATED_AT
            assert created.created_at != hypothesis.last_seen
            assert created.status is CaseStatus.OPEN
            assert created.priority is CasePriority.HIGH
            assert created.verdict is None
            assert "confirmed" not in created.description.lower()
            assert created.evidence_snapshot["uncertainty"]
            assert len(created.evidence_references) == 5
            case_id = created.case_id

        with database.session() as session, session.begin():
            status = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).update_status(
                case_id,
                CaseStatus.INVESTIGATING,
                actor="case-analyst",
                reason="triage started",
            )
            assert status.updated_at == CASE_UPDATED_AT

        with database.session() as session, session.begin():
            priority = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).set_priority(
                case_id,
                CasePriority.CRITICAL,
                actor="case-analyst",
                reason="manual triage priority only",
            )
            assert priority.priority is CasePriority.CRITICAL

        with database.session() as session, session.begin():
            assigned = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=2),
            ).assign(
                case_id,
                "analyst-local",
                actor="case-lead",
                reason="local assignment",
            )
            assert assigned.assigned_to == "analyst-local"

        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=3),
            )
            note = service.add_note(
                case_id,
                "Review source observations; do not treat the hypothesis as fact.",
                actor="analyst-local",
            )
            assert note.body.startswith("Review")

        first_alert_id = UUID(hypothesis.supporting_alert_ids[0])
        with database.session() as session:
            first_alert = SecurityAlertRepository(session).get(first_alert_id)
            assert first_alert is not None
            detection_id = first_alert.detection_id
            detection = DetectionResultRepository(session).get(detection_id)
            assert detection is not None
            flow_id = detection.flow_id
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=4),
            )
            detection_reference = service.add_evidence(
                case_id,
                CaseEvidenceObjectType.DETECTION_RESULT,
                str(detection_id),
                description="Detection record retained as model evidence, not ground truth.",
                actor="analyst-local",
            )
            duplicate_reference = service.add_evidence(
                case_id,
                CaseEvidenceObjectType.DETECTION_RESULT,
                str(detection_id),
                description="Duplicate request is idempotent.",
                actor="analyst-local",
            )
            assert duplicate_reference == detection_reference
        with database.session() as session, session.begin():
            flow_reference = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=5),
            ).add_evidence(
                case_id,
                CaseEvidenceObjectType.NETWORK_FLOW,
                str(flow_id),
                description="Canonical flow snapshot without ground-truth-only fields.",
                actor="analyst-local",
            )
            assert "ground_truth_label" not in flow_reference.snapshot
            assert "attack_family" not in flow_reference.snapshot

        with database.session() as session, session.begin():
            alert_feedback = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=6),
            ).record_alert(
                first_alert_id,
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="Analyst-reviewed alert-level judgment.",
                actor="analyst-local",
                related_case_id=case_id,
            )
            same_feedback = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=7),
            ).record_alert(
                first_alert_id,
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="Analyst-reviewed alert-level judgment.",
                actor="analyst-local",
                related_case_id=case_id,
            )
            assert same_feedback == alert_feedback

        with database.session() as session, session.begin():
            verdict_case = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=8),
            ).set_verdict(
                case_id,
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.85,
                reason="Current analyst judgment; evidence remains revisable.",
                actor="analyst-local",
            )
            assert verdict_case.verdict is AnalystVerdict.TRUE_POSITIVE

        with database.session() as session, session.begin():
            closed = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CLOSED_AT
            ).close(
                case_id,
                closure_note="Close after explicit analyst review; not automated response.",
                actor="analyst-local",
            )
            assert closed.status is CaseStatus.CLOSED
            assert closed.closed_at == CASE_CLOSED_AT
            assert closed.updated_at == CASE_CLOSED_AT

        database.dispose()
        database = _database(path)
        with database.session() as session:
            persisted = InvestigationCaseRepository(session).get(case_id)
            assert persisted is not None and persisted.status is CaseStatus.CLOSED
            assert persisted.hypothesis_id == hypothesis.hypothesis_id
            assert persisted.closed_at == CASE_CLOSED_AT
            notes = CaseNoteRepository(session).list_by_case(case_id)
            assert [item.note_type for item in notes] == ["investigation", "closure"]
            references = CaseEvidenceReferenceRepository(session).list_by_case(case_id)
            assert len(references) == 7
            assert all(len(item.snapshot_checksum) == 64 for item in references)
            feedback = AnalystFeedbackRepository(session).list()
            assert {item.object_type for item in feedback} == {
                FeedbackObjectType.ALERT,
                FeedbackObjectType.CASE,
            }
            assert len(feedback) == 2
            case_feedback = next(
                item for item in feedback if item.object_type is FeedbackObjectType.CASE
            )
            assert case_feedback.provenance["row_label_propagation"] == "prohibited"
            assert ThreatHypothesisRepository(session).get(hypothesis.hypothesis_id) == (
                original_hypothesis
            )
            assert {
                str(item.alert_id): item.model_dump(
                    exclude={"analyst_verdict", "updated_at"}
                )
                for item in SecurityAlertRepository(session).list()
            } == original_alerts
            events = AuditLogRepository(session).list()
            actions = {item.action for item in events}
            assert {
                "create_case_from_hypothesis",
                "update_case_status",
                "update_case_priority",
                "assign_case",
                "add_case_note",
                "add_evidence_reference",
                "set_case_verdict",
                "update_verdict",
                "close_case",
            } <= actions
            assert not any(
                "train" in action or "activate" in action for action in actions
            )
    finally:
        database.dispose()


def test_case_close_gates_conflicts_and_transaction_rollback(tmp_path: Path) -> None:
    database = _database(tmp_path / "rollback.sqlite3")
    hypothesis = seed_reviewable_hypothesis(database)
    loaded = case_policy()
    try:
        with (
            pytest.raises(RuntimeError, match="forced rollback"),
            database.session() as session,
            session.begin(),
        ):
            case = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            ).create_from_hypothesis(hypothesis.hypothesis_id, actor="analyst")
            assert case.evidence_references
            raise RuntimeError("forced rollback")
        with database.session() as session:
            assert InvestigationCaseRepository(session).list() == []
            assert CaseEvidenceReferenceRepository(session).list() == []

        with database.session() as session, session.begin():
            case = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            ).create_from_hypothesis(hypothesis.hypothesis_id, actor="analyst")
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            )
            with pytest.raises(CaseTransitionError, match="final verdict"):
                service.close(case.case_id, closure_note="not enough", actor="analyst")
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            )
            with pytest.raises(CaseTransitionError, match="explicit close"):
                service.update_status(
                    case.case_id,
                    CaseStatus.CLOSED,
                    actor="analyst",
                    reason="wrong command",
                )
            with pytest.raises(CaseEligibilityError, match="finite"):
                service.set_verdict(
                    case.case_id,
                    AnalystVerdict.TRUE_POSITIVE,
                    confidence=float("nan"),
                    reason="invalid confidence",
                    actor="analyst",
                )

        first_alert_id = UUID(hypothesis.supporting_alert_ids[0])
        with database.session() as session, session.begin():
            service = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            )
            service.record_alert(
                first_alert_id,
                AnalystVerdict.FALSE_POSITIVE,
                confidence=0.8,
                notes="Initial feedback.",
                actor="analyst",
            )
        with database.session() as session, session.begin():
            service = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=2),
            )
            with pytest.raises(FeedbackConflictError, match="explicit update"):
                service.record_alert(
                    first_alert_id,
                    AnalystVerdict.TRUE_POSITIVE,
                    confidence=0.9,
                    notes="Conflicting feedback.",
                    actor="analyst",
                )
        with database.session() as session:
            rows = AnalystFeedbackRepository(session).list()
            assert len(rows) == 1
            assert rows[0].verdict is AnalystVerdict.FALSE_POSITIVE
            alert = SecurityAlertRepository(session).get(first_alert_id)
            assert alert is not None
            assert alert.analyst_verdict is AnalystVerdict.FALSE_POSITIVE
    finally:
        database.dispose()


def test_missing_evidence_and_closed_case_mutations_fail_closed(tmp_path: Path) -> None:
    database = _database(tmp_path / "gates.sqlite3")
    hypothesis = seed_reviewable_hypothesis(database)
    loaded = case_policy()
    try:
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            )
            with pytest.raises(CaseEligibilityError, match="does not exist"):
                service.create_from_hypothesis(UUID(int=999_999), actor="analyst")
            case = service.create_from_hypothesis(
                hypothesis.hypothesis_id, actor="analyst"
            )
        with database.session() as session, session.begin():
            service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            )
            with pytest.raises(CaseEligibilityError, match="does not exist"):
                service.add_evidence(
                    case.case_id,
                    CaseEvidenceObjectType.NETWORK_FLOW,
                    str(UUID(int=999_999)),
                    description="missing",
                    actor="analyst",
                )
            with pytest.raises(CaseConflictError, match="explicit update"):
                service.set_verdict(
                    case.case_id,
                    AnalystVerdict.FALSE_POSITIVE,
                    confidence=0.8,
                    reason="first",
                    actor="analyst",
                )
                service.set_verdict(
                    case.case_id,
                    AnalystVerdict.TRUE_POSITIVE,
                    confidence=0.9,
                    reason="conflict",
                    actor="analyst",
                )
    finally:
        database.dispose()


def test_assignment_unassignment_feedback_filters_and_explicit_correction(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "query.sqlite3")
    hypothesis = seed_reviewable_hypothesis(database)
    loaded = case_policy()
    try:
        with database.session() as session, session.begin():
            case = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            ).create_from_hypothesis(hypothesis.hypothesis_id, actor="analyst-a")
        with database.session() as session, session.begin():
            assigned = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).assign(
                case.case_id,
                "analyst-a",
                actor="lead",
                reason="initial assignment",
            )
            assert assigned.assigned_to == "analyst-a"
        with database.session() as session, session.begin():
            reassigned = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).assign(
                case.case_id,
                "analyst-b",
                actor="lead",
                reason="explicit reassignment",
            )
            assert reassigned.assigned_to == "analyst-b"
        with database.session() as session, session.begin():
            unassigned = InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=2),
            ).assign(
                case.case_id,
                None,
                actor="lead",
                reason="return to queue",
            )
            assert unassigned.assigned_to is None
        alert_ids = [UUID(value) for value in hypothesis.supporting_alert_ids[:2]]
        with database.session() as session, session.begin():
            first = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=3),
            ).record_alert(
                alert_ids[0],
                AnalystVerdict.FALSE_POSITIVE,
                confidence=0.7,
                notes="Initial review.",
                actor="analyst-a",
            )
            AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=4),
            ).record_alert(
                alert_ids[1],
                AnalystVerdict.NEEDS_MORE_INFORMATION,
                confidence=0.6,
                notes="More context required.",
                actor="analyst-b",
            )
        with database.session() as session, session.begin():
            corrected = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=5),
            ).record_alert(
                alert_ids[0],
                AnalystVerdict.BENIGN_EXPECTED,
                confidence=0.9,
                notes="Expected local scanner activity.",
                actor="analyst-a",
                allow_update=True,
                correction_reason="New authorized-maintenance evidence.",
            )
            assert corrected.feedback_id == first.feedback_id
            assert corrected.correction_reason == "New authorized-maintenance evidence."
        with database.session() as session:
            service = AnalystFeedbackService(session, loaded)
            page, total = service.list(limit=1)
            assert len(page) == 1 and total == 2
            filtered, filtered_total = service.list(
                limit=10,
                verdict=AnalystVerdict.BENIGN_EXPECTED,
                actor="analyst-a",
            )
            assert filtered_total == 1
            assert filtered[0].feedback_id == first.feedback_id
            empty, empty_total = service.list(
                limit=10, object_type=FeedbackObjectType.CASE
            )
            assert empty == [] and empty_total == 0
            with pytest.raises(CaseEligibilityError, match="reason"):
                InvestigationCaseService(session, loaded).assign(
                    case.case_id,
                    "analyst-c",
                    actor="lead",
                    reason=" ",
                )
    finally:
        database.dispose()
