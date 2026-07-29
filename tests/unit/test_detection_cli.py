"""CLI boundaries for Phase 8 detection, alerts, and explanation artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.explainability.artifacts import save_explanation_artifact
from tests.fixtures.detection import explanation_artifact


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    risk_policy = Path(__file__).parents[2] / "configs/models/detection.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{tmp_path / 'cli.sqlite3'}",
                "detection:",
                f"  risk_policy_path: {risk_policy}",
                f"  explanation_artifact_root: {tmp_path / 'explanations'}",
                "  local_explanation_top_k: 5",
                "  local_explanation_max_features: 43",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_phase_eight_command_groups_and_empty_lists(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _config(tmp_path)

    help_result = runner.invoke(cli.app, ["--help"])
    assert help_result.exit_code == 0
    assert all(
        command in help_result.stdout
        for command in ("detection", "alerts", "explainability")
    )

    for command in ("detection", "alerts"):
        result = runner.invoke(cli.app, [command, "list", "--config", str(config)])
        assert result.exit_code == 0
        assert json.loads(result.stdout) == []


def test_alert_verdict_rejects_missing_alert_and_invalid_enum(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _config(tmp_path)
    alert_id = str(UUID(int=999))

    missing = runner.invoke(
        cli.app,
        [
            "alerts",
            "verdict",
            alert_id,
            "false_positive",
            "--actor",
            "analyst",
            "--config",
            str(config),
        ],
    )
    assert missing.exit_code == 2
    assert "does not exist" in missing.output
    assert "Traceback" not in missing.output

    invalid = runner.invoke(
        cli.app,
        ["alerts", "verdict", alert_id, "confirmed_attack", "--actor", "analyst"],
    )
    assert invalid.exit_code == 2
    assert "confirmed_attack" in invalid.output


def test_detection_and_alert_describe_report_missing_records(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _config(tmp_path)
    missing_id = str(UUID(int=998))

    detection = runner.invoke(
        cli.app,
        ["detection", "describe", missing_id, "--config", str(config)],
    )
    alert = runner.invoke(
        cli.app,
        ["alerts", "describe", missing_id, "--config", str(config)],
    )

    assert detection.exit_code == alert.exit_code == 2
    assert "Detection does not exist" in detection.output
    assert "Alert does not exist" in alert.output
    assert "Traceback" not in detection.output + alert.output


def test_detection_and_alert_lists_cleanly_report_configuration_failure(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    invalid_config = tmp_path / "invalid.yaml"
    invalid_config.write_text("database:\n  url: not-a-database-url\n", encoding="utf-8")

    detection = runner.invoke(
        cli.app,
        ["detection", "list", "--config", str(invalid_config)],
    )
    alert = runner.invoke(
        cli.app,
        ["alerts", "list", "--config", str(invalid_config)],
    )

    assert detection.exit_code == alert.exit_code == 1
    assert "listing failed" in detection.output.lower()
    assert "listing failed" in alert.output.lower()
    assert "Traceback" not in detection.output + alert.output


def test_explanation_verify_and_describe_use_integrity_checked_artifact(
    tmp_path: Path,
) -> None:
    runner = CliRunner()
    config = _config(tmp_path)
    artifact = explanation_artifact()
    saved = save_explanation_artifact(
        root=tmp_path / "explanations",
        manifest=artifact.manifest,
        reference_profile=artifact.reference_profile,
        native_importance=artifact.native_importance,
        permutation_importance=artifact.permutation_importance,
        reason_catalog=artifact.reason_catalog,
        protocol=artifact.protocol,
    )

    verified = runner.invoke(
        cli.app,
        ["explainability", "verify", str(saved), "--config", str(config)],
    )
    described = runner.invoke(
        cli.app,
        ["explainability", "describe", str(saved), "--config", str(config)],
    )
    assert verified.exit_code == described.exit_code == 0
    assert json.loads(verified.stdout)["status"] == "verified"
    assert "non-causal" in verified.stdout
    assert json.loads(described.stdout)["artifact_version"] == "1.0.0"
