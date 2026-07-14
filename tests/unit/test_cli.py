"""Tests for the Phase 0 CLI commands and process launchers."""

from __future__ import annotations

import subprocess
from pathlib import Path

from pytest import MonkeyPatch
from typer.testing import CliRunner

from aegishunt import cli

runner = CliRunner()


def test_help_lists_foundation_commands() -> None:
    result = runner.invoke(cli.app, ["--help"])

    assert result.exit_code == 0
    assert "doctor" in result.stdout
    assert "api" in result.stdout
    assert "frontend" in result.stdout


def test_doctor_succeeds_when_foundation_directories_exist(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    for directory in cli.REQUIRED_DIRECTORIES:
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["doctor"])

    assert result.exit_code == 0
    assert '"healthy": true' in result.stdout


def test_doctor_report_detects_missing_directory(tmp_path: Path) -> None:
    report = cli.collect_doctor_report(tmp_path)

    assert report.healthy is False
    assert report.directories == {name: False for name in cli.REQUIRED_DIRECTORIES}


def test_api_command_delegates_to_uvicorn(monkeypatch: MonkeyPatch) -> None:
    calls: list[tuple[str, int, bool]] = []
    monkeypatch.setattr(
        cli,
        "run_api",
        lambda host, port, reload: calls.append((host, port, reload)),
    )

    result = runner.invoke(cli.app, ["api", "--port", "8123", "--reload"])

    assert result.exit_code == 0
    assert calls == [("127.0.0.1", 8123, True)]


def test_run_api_calls_uvicorn(monkeypatch: MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(
        cli.uvicorn,
        "run",
        lambda target, **kwargs: calls.append((target, kwargs)),
    )

    cli.run_api(host="127.0.0.1", port=8123, reload=False)

    assert calls == [
        (
            "aegishunt.api.app:app",
            {"host": "127.0.0.1", "port": 8123, "reload": False},
        )
    ]


def test_frontend_command_propagates_failure(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "run_frontend", lambda address, port, headless: 7)

    result = runner.invoke(cli.app, ["frontend"])

    assert result.exit_code == 7


def test_run_frontend_uses_current_python(monkeypatch: MonkeyPatch) -> None:
    captured: list[list[str]] = []

    def fake_run(command: list[str], *, check: bool) -> subprocess.CompletedProcess[str]:
        assert check is False
        captured.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    result = cli.run_frontend(address="127.0.0.1", port=8600, headless=True)

    assert result == 0
    assert captured[0][:4] == [cli.sys.executable, "-m", "streamlit", "run"]
    assert captured[0][-2:] == ["--server.headless", "true"]
