"""Phase 11 CLI discovery and safe operator output."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegishunt.cli import app

PROJECT_ROOT = Path(__file__).parents[2]
runner = CliRunner()


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{tmp_path / 'runtime-cli.sqlite3'}",
                "runtime:",
                f"  policy_path: {PROJECT_ROOT / 'configs' / 'runtime.yaml'}",
                f"  fusion_policy_root: {tmp_path / 'fusion'}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_runtime_cli_help_discovers_lifecycle_commands() -> None:
    result = runner.invoke(app, ["runtime", "--help"])

    assert result.exit_code == 0
    for command in ("config", "replay", "jobs", "worker", "workers", "status"):
        assert command in result.stdout
    assert "live-capture" in result.stdout


def test_runtime_config_verify_and_live_capture_disabled() -> None:
    verified = runner.invoke(app, ["runtime", "config", "verify"])
    disabled = runner.invoke(app, ["runtime", "live-capture"])

    assert verified.exit_code == 0
    verify_payload = json.loads(verified.stdout)
    assert verify_payload["execution_mode"] == "single_node_sqlite"
    assert verify_payload["automatic_recovery"] is False
    assert verify_payload["live_capture_enabled"] is False
    assert disabled.exit_code == 0
    disabled_payload = json.loads(disabled.stdout)
    assert disabled_payload["status"] == "disabled"
    assert disabled_payload["live_capture_enabled"] is False


def test_runtime_status_and_empty_lists_are_machine_readable(tmp_path: Path) -> None:
    config = _config(tmp_path)
    status = runner.invoke(app, ["runtime", "status", "--config", str(config)])
    jobs = runner.invoke(
        app,
        ["runtime", "jobs", "list", "--config", str(config)],
    )
    workers = runner.invoke(
        app,
        ["runtime", "workers", "list", "--config", str(config)],
    )

    assert status.exit_code == jobs.exit_code == workers.exit_code == 0
    status_payload = json.loads(status.stdout)
    assert status_payload["queue_length"] == 0
    assert status_payload["model_loading_state"] == "verified_per_job_preflight"
    assert status_payload["automatic_recovery"] is False
    assert json.loads(jobs.stdout) == {"items": [], "total": 0}
    assert json.loads(workers.stdout) == []


def test_runtime_config_failure_is_sanitized_without_traceback(tmp_path: Path) -> None:
    policy = tmp_path / "invalid-runtime.yaml"
    policy.write_text("live_capture_enabled: true\n", encoding="utf-8")
    config = tmp_path / "invalid-application.yaml"
    config.write_text(
        "\n".join(
            (
                "runtime:",
                f"  policy_path: {policy}",
                f"  fusion_policy_root: {tmp_path / 'fusion'}",
                "",
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["runtime", "config", "verify", "--config", str(config)],
    )

    assert result.exit_code == 1
    assert "Runtime command failed" in result.stdout
    assert "Traceback" not in result.stdout
    assert str(tmp_path) not in result.stdout
