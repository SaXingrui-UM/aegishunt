"""Phase 9 CLI help, pagination, and sanitized failure coverage."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from uuid import UUID

from typer.testing import CliRunner

from aegishunt import cli


def _config(tmp_path: Path) -> Path:
    policy = Path(__file__).parents[2] / "configs/correlation.yaml"
    path = tmp_path / "application.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{tmp_path / 'hunt.sqlite3'}",
                "correlation:",
                f"  policy_path: {policy}",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_hunt_help_and_empty_paginated_lists(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _config(tmp_path)
    help_result = runner.invoke(cli.app, ["hunt", "--help"])
    assert help_result.exit_code == 0
    assert "correlate" in help_result.stdout
    assert "generate-hypotheses" in help_result.stdout
    assert "case" not in help_result.stdout.casefold()

    for resource in ("alert-groups", "hypotheses"):
        result = runner.invoke(
            cli.app,
            ["hunt", resource, "list", "--limit", "5", "--config", str(config)],
        )
        assert result.exit_code == 0
        assert json.loads(result.stdout) == {
            "items": [],
            "limit": 5,
            "offset": 0,
            "total": 0,
        }


def test_fresh_cli_import_has_no_schema_cycle(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
    completed = subprocess.run(
        [sys.executable, "-c", "from aegishunt.cli import app; print(app.info.name)"],
        cwd=tmp_path,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "aegishunt"


def test_hunt_missing_records_and_confirmation_are_sanitized(tmp_path: Path) -> None:
    runner = CliRunner()
    config = _config(tmp_path)
    identifier = str(UUID(int=999))

    missing = runner.invoke(
        cli.app,
        ["hunt", "alert-groups", "describe", identifier, "--config", str(config)],
    )
    assert missing.exit_code == 2
    assert "does not exist" in missing.output
    assert "Traceback" not in missing.output

    missing_hypothesis = runner.invoke(
        cli.app,
        [
            "hunt",
            "hypotheses",
            "update-status",
            identifier,
            "under_review",
            "--actor",
            "analyst",
            "--config",
            str(config),
        ],
    )
    assert missing_hypothesis.exit_code == 1
    assert "does not exist" in missing_hypothesis.output
    assert "Traceback" not in missing_hypothesis.output

    confirmed = runner.invoke(
        cli.app,
        [
            "hunt",
            "hypotheses",
            "update-status",
            identifier,
            "confirmed",
            "--actor",
            "analyst",
            "--config",
            str(config),
        ],
    )
    assert confirmed.exit_code == 2
    assert "confirmed" in confirmed.output
    assert "Traceback" not in confirmed.output
