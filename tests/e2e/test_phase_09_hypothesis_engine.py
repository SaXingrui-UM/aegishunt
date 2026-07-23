"""Offline CLI E2E for alert correlation and proposed hypothesis generation."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.config import DatabaseSettings
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AnalystFeedbackRepository,
    AuditLogRepository,
    InvestigationCaseRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.hunting import alert, seed_alerts


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    policy = Path(__file__).parents[2] / "configs/correlation.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{tmp_path / 'phase-09-cli.sqlite3'}",
                "correlation:",
                f"  policy_path: {policy}",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_phase_nine_cli_end_to_end_is_offline_and_restart_safe(tmp_path: Path) -> None:
    config = _config(tmp_path)
    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase-09-cli.sqlite3'}")
    )
    assert database.initialize() == 4
    seed_alerts(
        database,
        [
            alert(1, destination_ip="198.51.100.10", seconds=0),
            alert(2, destination_ip="198.51.100.11", seconds=10),
            alert(3, destination_ip="198.51.100.12", seconds=20),
            alert(
                4,
                source_ip="203.0.113.40",
                destination_ip="203.0.113.50",
                seconds=30,
                risk_score=0.2,
                alert_type="behavioral_pattern",
            ),
        ],
    )
    database.dispose()
    runner = CliRunner()

    help_commands = (
        ["hunt", "--help"],
        ["hunt", "alert-groups", "--help"],
        ["hunt", "hypotheses", "--help"],
    )
    for command in help_commands:
        assert runner.invoke(cli.app, command).exit_code == 0

    verified = runner.invoke(cli.app, ["hunt", "config", "verify", "--config", str(config)])
    correlated = runner.invoke(cli.app, ["hunt", "correlate", "--config", str(config)])
    generated = runner.invoke(
        cli.app,
        ["hunt", "generate-hypotheses", "--config", str(config)],
    )
    assert verified.exit_code == correlated.exit_code == generated.exit_code == 0
    assert json.loads(verified.stdout)["status"] == "verified"
    group_id = json.loads(correlated.stdout)["group_ids"][0]
    hypothesis_id = json.loads(generated.stdout)["hypothesis_ids"][0]

    group_detail = runner.invoke(
        cli.app,
        ["hunt", "alert-groups", "describe", group_id, "--config", str(config)],
    )
    hypothesis_detail = runner.invoke(
        cli.app,
        ["hunt", "hypotheses", "describe", hypothesis_id, "--config", str(config)],
    )
    assert group_detail.exit_code == hypothesis_detail.exit_code == 0
    assert json.loads(group_detail.stdout)["alert_count"] == 3
    hypothesis = json.loads(hypothesis_detail.stdout)
    assert hypothesis["status"] == "proposed"
    assert hypothesis["recommended_queries"][0]["execution"] == "not_executed"

    groups_page = runner.invoke(
        cli.app,
        ["hunt", "alert-groups", "list", "--limit", "1", "--config", str(config)],
    )
    hypotheses_page = runner.invoke(
        cli.app,
        ["hunt", "hypotheses", "list", "--limit", "1", "--config", str(config)],
    )
    assert groups_page.exit_code == hypotheses_page.exit_code == 0
    assert json.loads(groups_page.stdout)["total"] == 1
    assert json.loads(hypotheses_page.stdout)["total"] == 1

    reviewed = runner.invoke(
        cli.app,
        [
            "hunt",
            "hypotheses",
            "update-status",
            hypothesis_id,
            "under_review",
            "--actor",
            "e2e-analyst",
            "--config",
            str(config),
        ],
    )
    confirmed = runner.invoke(
        cli.app,
        [
            "hunt",
            "hypotheses",
            "update-status",
            hypothesis_id,
            "confirmed",
            "--actor",
            "e2e-analyst",
            "--config",
            str(config),
        ],
    )
    assert reviewed.exit_code == 0
    assert json.loads(reviewed.stdout)["status"] == "under_review"
    assert confirmed.exit_code == 2
    assert "confirmed" in confirmed.output
    assert "Traceback" not in confirmed.output

    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'phase-09-cli.sqlite3'}")
    )
    assert database.initialize() == 4
    try:
        with database.session() as session:
            groups = AlertGroupRepository(session).list()
            assert len(groups) == 1
            assert groups[0].created_at != groups[0].last_seen
            assert groups[0].evidence["generated_at"] == groups[0].created_at.isoformat()
            hypotheses = ThreatHypothesisRepository(session).list()
            assert len(hypotheses) == 1
            assert hypotheses[0].status.value == "under_review"
            assert hypotheses[0].created_at != hypotheses[0].last_seen
            assert hypotheses[0].updated_at is not None
            assert hypotheses[0].updated_at > hypotheses[0].created_at
            assert hypotheses[0].source_group_snapshot[
                "hypothesis_generated_at"
            ] == hypotheses[0].created_at.isoformat()
            assert InvestigationCaseRepository(session).list() == []
            assert AnalystFeedbackRepository(session).list() == []
            assert any(
                event.action == "update_status"
                for event in AuditLogRepository(session).list()
            )
    finally:
        database.dispose()
