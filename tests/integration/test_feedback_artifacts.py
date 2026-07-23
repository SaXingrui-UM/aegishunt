"""Phase 10 feedback export, candidate leakage gates, and case-report integrity."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.cases.errors import CaseArtifactError
from aegishunt.cases.reports import CaseReportService
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import DatabaseSettings
from aegishunt.feedback.candidates import RetrainingCandidateService
from aegishunt.feedback.errors import FeedbackArtifactError
from aegishunt.feedback.export import FeedbackExportService
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas import DetectionResult, SecurityAlert, TelemetrySource
from aegishunt.schemas.enums import (
    AnalystVerdict,
    IngestionMode,
    LifecycleStatus,
    Severity,
    SourceType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
)
from tests.fixtures.cases import (
    CASE_CREATED_AT,
    CASE_UPDATED_AT,
    case_policy,
    eligible_source_metadata,
    seed_reviewable_hypothesis,
)
from tests.fixtures.detection import canonical_flow


def _database(path: Path) -> Database:
    database = Database(DatabaseSettings(url=f"sqlite:///{path}"))
    assert database.initialize() == 5
    return database


def _seed_evaluation_alert(database: Database) -> SecurityAlert:
    source_id = UUID(int=50_001)
    flow_id = UUID(int=50_002)
    detection_id = UUID(int=50_003)
    alert_id = UUID(int=50_004)
    flow = canonical_flow().model_copy(
        update={
            "source_id": source_id,
            "flow_id": flow_id,
            "capture_session_id": "frozen-evaluation-session",
        }
    )
    detection = DetectionResult(
        detection_id=detection_id,
        flow_id=flow_id,
        supervised_label="suspicious",
        supervised_probability=0.8,
        supervised_threshold=0.5,
        anomaly_raw_score=-0.2,
        normalized_anomaly_score=0.75,
        anomaly_threshold=0.6,
        fusion_score=0.8,
        fusion_threshold=0.5,
        risk_score=0.8,
        risk_source="fusion_score",
        severity=Severity.HIGH,
        alert_threshold=0.7,
        model_versions={"supervised": "1.0.1", "anomaly": "1.1.0"},
        policy_versions={"fusion": "1.0.0", "risk": "1.0.0"},
        policy_checksums={"fusion": "a" * 64, "risk": "b" * 64},
        feature_schema_version="1.0.0",
        reason_codes=["CONTROLLED_EVALUATION"],
        explanation={"limitations": ["controlled evidence only"]},
        detected_at=flow.first_seen,
    )
    alert = SecurityAlert(
        alert_id=alert_id,
        detection_id=detection_id,
        alert_type="controlled_evaluation_alert",
        severity=Severity.HIGH,
        risk_score=0.8,
        title="Controlled evaluation alert",
        description="Historical evaluation evidence; not candidate-eligible.",
        involved_entities=[f"flow_id:{flow_id}"],
        evidence={"flow_id": str(flow_id)},
        reason_codes=["CONTROLLED_EVALUATION"],
        explanation={"limitations": ["controlled evidence only"]},
        model_versions=detection.model_versions,
        policy_versions=detection.policy_versions,
        created_at=CASE_CREATED_AT - timedelta(days=1),
        updated_at=CASE_CREATED_AT - timedelta(days=1),
    )
    with database.session() as session, session.begin():
        TelemetrySourceRepository(session).add(
            TelemetrySource(
                source_id=source_id,
                source_type=SourceType.PCAP,
                filename_or_interface="controlled-evaluation.pcap",
                ingestion_mode=IngestionMode.IMPORT,
                status=LifecycleStatus.COMPLETED,
                source_metadata={
                    "provenance_partition": "frozen_test",
                    "provenance_type": "controlled_non_evaluation",
                    "dataset_id": "historical-evaluation",
                    "dataset_version": "1.0.0",
                    "scenario_id": "frozen-scenario",
                    "group_id": "frozen-group",
                },
            )
        )
        NetworkFlowRepository(session).add(flow)
        DetectionResultRepository(session).add(detection)
        SecurityAlertRepository(session).add(alert)
    return alert


def _artifact_json(path: Path, name: str) -> object:
    return json.loads((path / name).read_text(encoding="utf-8"))


def test_feedback_export_case_report_and_candidate_artifacts_are_audited_and_safe(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "artifacts.sqlite3")
    hypothesis = seed_reviewable_hypothesis(
        database, source_metadata=eligible_source_metadata()
    )
    evaluation_alert = _seed_evaluation_alert(database)
    loaded = case_policy()
    try:
        with database.session() as session, session.begin():
            case_service = InvestigationCaseService(
                session, loaded, clock=lambda: CASE_CREATED_AT
            )
            case = case_service.create_from_hypothesis(
                hypothesis.hypothesis_id, actor="artifact-analyst"
            )
        with database.session() as session, session.begin():
            InvestigationCaseService(
                session,
                loaded,
                clock=lambda: CASE_UPDATED_AT,
            ).add_note(
                case.case_id,
                "Observed evidence and inference remain distinct.",
                actor="artifact-analyst",
            )
        alert_ids = [UUID(value) for value in hypothesis.supporting_alert_ids]
        feedback_time = CASE_UPDATED_AT + timedelta(minutes=1)
        with database.session() as session, session.begin():
            feedback = AnalystFeedbackService(
                session, loaded, clock=lambda: feedback_time
            )
            first = feedback.record_alert(
                alert_ids[0],
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="First explicit row-level judgment.",
                actor="analyst-a",
                related_case_id=case.case_id,
            )
        with database.session() as session, session.begin():
            second = AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=1),
            ).record_alert(
                alert_ids[0],
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.8,
                notes="Independent consistent judgment.",
                actor="analyst-b",
                related_case_id=case.case_id,
            )
            assert first.feedback_id != second.feedback_id
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=2),
            ).record_alert(
                alert_ids[1],
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="Potentially malicious.",
                actor="analyst-a",
            )
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=3),
            ).record_alert(
                alert_ids[1],
                AnalystVerdict.FALSE_POSITIVE,
                confidence=0.95,
                notes="Conflicting analyst judgment.",
                actor="analyst-b",
                allow_update=True,
                correction_reason="Explicitly retain the conflict for review.",
            )
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=4),
            ).record_alert(
                alert_ids[2],
                AnalystVerdict.NEEDS_MORE_INFORMATION,
                confidence=0.9,
                notes="Insufficient evidence for a row label.",
                actor="analyst-a",
            )
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=5),
            ).record_alert(
                evaluation_alert.alert_id,
                AnalystVerdict.FALSE_POSITIVE,
                confidence=0.9,
                notes="Evaluation row must remain excluded.",
                actor="analyst-a",
            )
        with database.session() as session, session.begin():
            InvestigationCaseService(
                session,
                loaded,
                clock=lambda: feedback_time + timedelta(seconds=6),
            ).set_verdict(
                case.case_id,
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.85,
                reason="Case-level judgment must not label every member flow.",
                actor="artifact-analyst",
            )

        with database.session() as session, session.begin():
            export_path, export_manifest = FeedbackExportService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: feedback_time + timedelta(minutes=1),
            ).export("1.0.0", actor="artifact-analyst")
            assert export_manifest.record_count == 7
            assert export_manifest.limitations
        with database.session() as session:
            verified_export = FeedbackExportService(
                session, loaded, project_root=tmp_path
            ).verify("1.0.0")
            assert verified_export == export_manifest
        exported_rows = [
            json.loads(line)
            for line in (export_path / "feedback.jsonl").read_text().splitlines()
        ]
        assert [row["feedback_id"] for row in exported_rows] == list(
            export_manifest.source_feedback_ids
        )

        with database.session() as session, session.begin():
            candidate_path, candidate_manifest = RetrainingCandidateService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: feedback_time + timedelta(minutes=2),
            ).build("1.0.0", actor="artifact-analyst")
        assert candidate_manifest.status == "retraining_candidate"
        assert candidate_manifest.eligibility_status == "requires_manual_review"
        assert candidate_manifest.candidate_count == 1
        assert candidate_manifest.conflict_count == 1
        assert candidate_manifest.exclusion_count == 3
        candidates = [
            json.loads(line)
            for line in (candidate_path / "candidates.jsonl").read_text().splitlines()
        ]
        assert len(candidates) == 1
        assert candidates[0]["candidate_label"] == "malicious"
        assert candidates[0]["confidence"] == 0.8
        assert len(candidates[0]["supporting_feedback_ids"]) == 2
        assert "ground_truth_label" not in candidates[0]
        assert "attack_family" not in candidates[0]
        conflicts = _artifact_json(candidate_path, "conflicts.json")
        exclusions = _artifact_json(candidate_path, "exclusions.json")
        assert isinstance(conflicts, list) and conflicts[0]["labels"] == [
            "benign",
            "malicious",
        ]
        assert isinstance(exclusions, list)
        reasons = {item["reason"] for item in exclusions}
        assert "case-level feedback is not propagated to flow labels" in reasons
        assert any("needs_more_information" in reason for reason in reasons)
        assert any("frozen_test" in reason for reason in reasons)
        with database.session() as session:
            verified_candidates = RetrainingCandidateService(
                session, loaded, project_root=tmp_path
            ).verify("1.0.0")
            assert verified_candidates == candidate_manifest

        report_time = feedback_time + timedelta(minutes=3)
        with database.session() as session, session.begin():
            report_path, report_manifest = CaseReportService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: report_time,
            ).generate(case.case_id, "1.0.0", actor="artifact-analyst")
        report = _artifact_json(report_path, "case_report.json")
        assert isinstance(report, dict)
        assert report["source_event_window"]["last_seen"] != report["case_lifecycle"][
            "created_at"
        ]
        assert report["analyst_judgment"]["semantics"].endswith(
            "not absolute ground truth"
        )
        assert report["model_inference"]["recommended_queries_not_executed"]
        markdown = (report_path / "case_report.md").read_text(encoding="utf-8")
        assert "not proof of attack" in markdown
        assert "never executed" in markdown
        with database.session() as session:
            verified_report = CaseReportService(
                session, loaded, project_root=tmp_path
            ).verify(case.case_id, "1.0.0")
            assert verified_report == report_manifest
            events = AuditLogRepository(session).list()
            artifact_actions = {
                "export_feedback",
                "build_retraining_candidates",
                "export_case_report",
            }
            actions = {item.action for item in events}
            assert artifact_actions <= actions
            for event in events:
                if event.action not in artifact_actions:
                    continue
                assert event.details["operation_id"]
                assert event.details["before"] is None
                assert event.details["after"]
                assert event.details["reason"]
                assert event.details["source"]
            assert not any("train_model" in action for action in actions)

        with (
            pytest.raises(FeedbackArtifactError, match="already exists"),
            database.session() as session,
            session.begin(),
        ):
            FeedbackExportService(session, loaded, project_root=tmp_path).export(
                "1.0.0", actor="artifact-analyst"
            )
        (candidate_path / "unexpected.txt").write_text("extra", encoding="utf-8")
        with (
            database.session() as session,
            pytest.raises(FeedbackArtifactError, match="verification"),
        ):
            RetrainingCandidateService(session, loaded, project_root=tmp_path).verify(
                "1.0.0"
            )
        (report_path / "case_report.json").write_text("corrupt", encoding="utf-8")
        with (
            database.session() as session,
            pytest.raises(CaseArtifactError, match="verification"),
        ):
            CaseReportService(session, loaded, project_root=tmp_path).verify(
                case.case_id, "1.0.0"
            )
    finally:
        database.dispose()


@pytest.mark.parametrize(
    "partition",
    ["test", "holdout", "evaluation", "loao", "independent_holdout"],
)
def test_candidate_builder_excludes_every_declared_evaluation_partition(
    tmp_path: Path,
    partition: str,
) -> None:
    database = _database(tmp_path / f"{partition}.sqlite3")
    metadata = eligible_source_metadata() | {"provenance_partition": partition}
    hypothesis = seed_reviewable_hypothesis(database, source_metadata=metadata)
    loaded = case_policy()
    try:
        alert_id = UUID(hypothesis.supporting_alert_ids[0])
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).record_alert(
                alert_id,
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="Explicit evaluation feedback must remain excluded.",
                actor="evaluation-analyst",
            )
        with database.session() as session, session.begin():
            path, manifest = RetrainingCandidateService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).build("1.0.0", actor="evaluation-analyst")
        assert manifest.candidate_count == 0
        assert manifest.eligibility_status == "empty"
        exclusions = _artifact_json(path, "exclusions.json")
        assert isinstance(exclusions, list)
        assert partition in exclusions[0]["reason"]
    finally:
        database.dispose()


@pytest.mark.parametrize(
    ("verdict", "expected_label"),
    [
        (AnalystVerdict.FALSE_POSITIVE, "benign"),
        (AnalystVerdict.BENIGN_EXPECTED, "benign"),
    ],
)
def test_candidate_builder_applies_explicit_benign_label_mapping(
    tmp_path: Path,
    verdict: AnalystVerdict,
    expected_label: str,
) -> None:
    database = _database(tmp_path / f"{verdict.value}.sqlite3")
    hypothesis = seed_reviewable_hypothesis(
        database, source_metadata=eligible_source_metadata()
    )
    loaded = case_policy()
    try:
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).record_alert(
                UUID(hypothesis.supporting_alert_ids[0]),
                verdict,
                confidence=0.9,
                notes="Explicit row-level benign judgment.",
                actor="mapping-analyst",
            )
        with database.session() as session, session.begin():
            path, manifest = RetrainingCandidateService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).build("1.0.0", actor="mapping-analyst")
        assert manifest.candidate_count == 1
        rows = [
            json.loads(line)
            for line in (path / "candidates.jsonl").read_text().splitlines()
        ]
        assert rows[0]["candidate_label"] == expected_label
    finally:
        database.dispose()


def test_candidate_builder_excludes_unknown_provenance_without_guessing(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "unknown.sqlite3")
    incomplete = eligible_source_metadata()
    incomplete.pop("group_id")
    hypothesis = seed_reviewable_hypothesis(database, source_metadata=incomplete)
    loaded = case_policy()
    try:
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).record_alert(
                UUID(hypothesis.supporting_alert_ids[0]),
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="Provenance remains incomplete.",
                actor="mapping-analyst",
            )
        with database.session() as session, session.begin():
            path, manifest = RetrainingCandidateService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).build("1.0.0", actor="mapping-analyst")
        assert manifest.candidate_count == 0
        exclusions = _artifact_json(path, "exclusions.json")
        assert isinstance(exclusions, list)
        assert exclusions[0]["reason"] == "telemetry provenance is incomplete or unknown"
    finally:
        database.dispose()


def test_candidate_builder_records_configured_insufficient_record_status(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path / "minimum.sqlite3")
    hypothesis = seed_reviewable_hypothesis(
        database, source_metadata=eligible_source_metadata()
    )
    loaded = case_policy()
    loaded = loaded.model_copy(
        update={
            "policy": loaded.policy.model_copy(
                update={"candidate_dataset_minimum_records": 2}
            )
        }
    )
    try:
        with database.session() as session, session.begin():
            AnalystFeedbackService(
                session, loaded, clock=lambda: CASE_UPDATED_AT
            ).record_alert(
                UUID(hypothesis.supporting_alert_ids[0]),
                AnalystVerdict.TRUE_POSITIVE,
                confidence=0.9,
                notes="One eligible row is below the configured review minimum.",
                actor="minimum-analyst",
            )
        with database.session() as session, session.begin():
            _, manifest = RetrainingCandidateService(
                session,
                loaded,
                project_root=tmp_path,
                clock=lambda: CASE_UPDATED_AT + timedelta(minutes=1),
            ).build("1.0.0", actor="minimum-analyst")
        assert manifest.candidate_count == 1
        assert manifest.eligibility_status == "insufficient_records"
    finally:
        database.dispose()
