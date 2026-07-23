"""Offline Phase 10 CLI E2E from hypothesis through auditable candidate data."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.config import DatabaseSettings
from aegishunt.correlation.service import AlertCorrelationService
from aegishunt.hunting.service import ThreatHypothesisService
from aegishunt.schemas import SecurityAlert
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AnalystFeedbackRepository,
    AuditLogRepository,
    InvestigationCaseRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.cases import eligible_source_metadata
from tests.fixtures.hunting import alert, correlation_policy, seed_alerts


def _historical_alert(index: int, when: datetime, destination: str) -> SecurityAlert:
    source = alert(index, destination_ip=destination)
    evidence = dict(source.evidence)
    facts = dict(evidence["observed_facts"])
    facts["first_seen"] = when.isoformat()
    facts["last_seen"] = (when + timedelta(seconds=1)).isoformat()
    evidence["observed_facts"] = facts
    return source.model_copy(
        update={
            "evidence": evidence,
            "created_at": when + timedelta(days=1),
            "updated_at": when + timedelta(days=1),
        }
    )


def _config(tmp_path: Path, database_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    policy = Path(__file__).parents[2] / "configs" / "case_feedback.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{database_path}",
                "case_feedback:",
                f"  policy_path: {policy}",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_phase_ten_cli_end_to_end_is_offline_persistent_and_has_no_training(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "phase-10-e2e.sqlite3"
    database = Database(DatabaseSettings(url=f"sqlite:///{database_path}"))
    assert database.initialize() == 4
    now = datetime.now(UTC)
    alerts = [
        _historical_alert(1, now - timedelta(days=30), "198.51.100.10"),
        _historical_alert(2, now - timedelta(days=30, seconds=-10), "198.51.100.11"),
        _historical_alert(3, now - timedelta(days=30, seconds=-20), "198.51.100.12"),
    ]
    seed_alerts(database, alerts)
    with database.session() as session, session.begin():
        source_repository = TelemetrySourceRepository(session)
        source = source_repository.list()[0]
        source_repository.update(
            source.model_copy(update={"source_metadata": eligible_source_metadata()}),
            actor="e2e-fixture",
        )
        groups = AlertCorrelationService(
            session,
            correlation_policy(),
            clock=lambda: now - timedelta(days=10),
        ).correlate(actor="e2e-fixture")
        hypotheses = ThreatHypothesisService(
            session,
            correlation_policy(),
            clock=lambda: now - timedelta(days=9),
        ).generate(actor="e2e-fixture")
        assert len(groups) == len(hypotheses) == 1
        hypothesis_id = str(hypotheses[0].hypothesis_id)
        alert_id = hypotheses[0].supporting_alert_ids[0]
    database.dispose()

    config = _config(tmp_path, database_path)
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    for command in (["cases", "--help"], ["feedback", "--help"]):
        result = runner.invoke(cli.app, command)
        assert result.exit_code == 0
        assert "replay" not in result.stdout.lower()
        assert "worker" not in result.stdout.lower()

    created = runner.invoke(
        cli.app,
        [
            "cases",
            "create-from-hypothesis",
            hypothesis_id,
            "--actor",
            "e2e-analyst",
            "--config",
            str(config),
        ],
    )
    assert created.exit_code == 0, created.output
    case_id = json.loads(created.stdout)["case_id"]
    assert json.loads(created.stdout)["status"] == "open"

    commands = (
        [
            "cases",
            "update-status",
            case_id,
            "investigating",
            "--actor",
            "e2e-analyst",
            "--reason",
            "analysis started",
            "--config",
            str(config),
        ],
        [
            "cases",
            "set-priority",
            case_id,
            "critical",
            "--actor",
            "e2e-analyst",
            "--reason",
            "manual triage only",
            "--config",
            str(config),
        ],
        [
            "cases",
            "assign",
            case_id,
            "--assigned-to",
            "local-analyst",
            "--actor",
            "e2e-lead",
            "--reason",
            "explicit local assignment",
            "--config",
            str(config),
        ],
        [
            "cases",
            "add-note",
            case_id,
            "--body",
            "Append-only investigation note.",
            "--actor",
            "local-analyst",
            "--config",
            str(config),
        ],
        [
            "feedback",
            "record-alert",
            alert_id,
            "true_positive",
            "--confidence",
            "0.9",
            "--notes",
            "Explicit alert-level analyst judgment.",
            "--actor",
            "local-analyst",
            "--related-case-id",
            case_id,
            "--config",
            str(config),
        ],
        [
            "cases",
            "set-verdict",
            case_id,
            "true_positive",
            "--confidence",
            "0.85",
            "--reason",
            "Current analyst judgment, not benchmark truth.",
            "--actor",
            "local-analyst",
            "--config",
            str(config),
        ],
        [
            "cases",
            "close",
            case_id,
            "--closure-note",
            "Explicit closure after analyst review.",
            "--actor",
            "local-analyst",
            "--confirm",
            "--config",
            str(config),
        ],
    )
    for command in commands:
        result = runner.invoke(cli.app, command)
        assert result.exit_code == 0, result.output
        assert "Traceback" not in result.output

    exported = runner.invoke(
        cli.app,
        [
            "feedback",
            "export",
            "--version",
            "e2e-v1",
            "--actor",
            "local-analyst",
            "--config",
            str(config),
        ],
    )
    candidates = runner.invoke(
        cli.app,
        [
            "feedback",
            "build-retraining-candidates",
            "--version",
            "e2e-v1",
            "--actor",
            "local-analyst",
            "--confirm",
            "--config",
            str(config),
        ],
    )
    report = runner.invoke(
        cli.app,
        [
            "cases",
            "report",
            case_id,
            "--version",
            "e2e-v1",
            "--actor",
            "local-analyst",
            "--confirm",
            "--config",
            str(config),
        ],
    )
    assert exported.exit_code == candidates.exit_code == report.exit_code == 0
    assert json.loads(exported.stdout)["training_invoked"] is False
    candidate_payload = json.loads(candidates.stdout)
    assert candidate_payload["status"] == "retraining_candidate"
    assert candidate_payload["candidate_count"] == 1
    assert candidate_payload["training_invoked"] is False
    assert candidate_payload["model_activation_invoked"] is False

    verify_commands = (
        [
            "feedback",
            "verify-export",
            "--version",
            "e2e-v1",
            "--config",
            str(config),
        ],
        [
            "feedback",
            "verify-candidates",
            "--version",
            "e2e-v1",
            "--config",
            str(config),
        ],
        [
            "cases",
            "verify-report",
            case_id,
            "--version",
            "e2e-v1",
            "--config",
            str(config),
        ],
    )
    for command in verify_commands:
        result = runner.invoke(cli.app, command)
        assert result.exit_code == 0, result.output

    missing = runner.invoke(
        cli.app,
        [
            "cases",
            "add-evidence",
            case_id,
            "network_flow",
            str(UUID(int=999_999)),
            "--description",
            "missing object",
            "--actor",
            "local-analyst",
            "--config",
            str(config),
        ],
    )
    assert missing.exit_code != 0
    assert "Traceback" not in missing.output

    database = Database(DatabaseSettings(url=f"sqlite:///{database_path}"))
    assert database.initialize() == 4
    try:
        with database.session() as session:
            case = InvestigationCaseRepository(session).get(UUID(case_id))
            assert case is not None and case.status.value == "closed"
            assert len(AnalystFeedbackRepository(session).list()) == 2
            assert len(ThreatHypothesisRepository(session).list()) == 1
            actions = {item.action for item in AuditLogRepository(session).list()}
            assert "build_retraining_candidates" in actions
            assert "export_feedback" in actions
            assert "export_case_report" in actions
            assert not any(
                "train" in item and item != "build_retraining_candidates"
                for item in actions
            )
            assert not any("activate" in item for item in actions)
    finally:
        database.dispose()

    empty_database_path = tmp_path / "phase-10-empty.sqlite3"
    empty_database = Database(
        DatabaseSettings(url=f"sqlite:///{empty_database_path}")
    )
    assert empty_database.initialize() == 4
    empty_database.dispose()
    empty_config = tmp_path / "empty-application.yaml"
    policy = Path(__file__).parents[2] / "configs" / "case_feedback.yaml"
    empty_config.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{empty_database_path}",
                "case_feedback:",
                f"  policy_path: {policy}",
            )
        ),
        encoding="utf-8",
    )
    empty_result = runner.invoke(
        cli.app,
        [
            "feedback",
            "build-retraining-candidates",
            "--version",
            "empty-v1",
            "--actor",
            "e2e-analyst",
            "--confirm",
            "--config",
            str(empty_config),
        ],
    )
    assert empty_result.exit_code == 0, empty_result.output
    assert json.loads(empty_result.stdout)["eligibility_status"] == "empty"
    empty_database = Database(
        DatabaseSettings(url=f"sqlite:///{empty_database_path}")
    )
    try:
        with empty_database.session() as session:
            assert "build_retraining_candidates" in {
                event.action for event in AuditLogRepository(session).list()
            }
    finally:
        empty_database.dispose()
