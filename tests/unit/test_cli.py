"""Tests for the Phase 0 CLI commands and process launchers."""

from __future__ import annotations

import json
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
    assert "init-db" in result.stdout
    assert "ingest" in result.stdout


def test_ingest_help_lists_only_phase_2_file_commands() -> None:
    result = runner.invoke(cli.app, ["ingest", "--help"])

    assert result.exit_code == 0
    assert all(command in result.stdout for command in ("pcap", "csv", "json", "sample"))
    assert "replay" not in result.stdout


def test_doctor_succeeds_when_foundation_directories_exist(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    database_path = tmp_path / "doctor.db"
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        f"database:\n  url: sqlite:///{database_path}\n",
        encoding="utf-8",
    )
    for directory in cli.REQUIRED_DIRECTORIES:
        (tmp_path / directory).mkdir()
    cli.initialize_database(config_path)
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["doctor", "--config", str(config_path)])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["configuration_status"] == "loaded"
    assert payload["database_status"] == "available"
    assert payload["diagnostics"] == [
        "configuration loaded",
        "database connection succeeded",
    ]
    assert payload["healthy"] is True
    assert "project_root" not in payload
    assert str(tmp_path) not in result.stdout


def test_doctor_report_detects_missing_directory(tmp_path: Path) -> None:
    report = cli.collect_doctor_report(tmp_path, tmp_path / "missing.yaml")

    assert report.healthy is False
    assert report.directories == {name: False for name in cli.REQUIRED_DIRECTORIES}
    assert report.configuration_status == "error"
    assert report.database_status == "not_checked"


def test_doctor_fails_safely_when_configuration_is_unavailable(tmp_path: Path) -> None:
    missing_config = tmp_path / "missing.yaml"

    result = runner.invoke(cli.app, ["doctor", "--config", str(missing_config)])
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload["configuration_status"] == "error"
    assert payload["database_status"] == "not_checked"
    assert payload["diagnostics"] == ["configuration could not be loaded or validated"]
    assert str(tmp_path) not in result.stdout
    assert "Traceback" not in result.stdout


def test_doctor_fails_safely_when_database_is_unavailable(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    database_path = tmp_path / "missing.db"
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        f"database:\n  url: sqlite:///{database_path}\n",
        encoding="utf-8",
    )
    for directory in cli.REQUIRED_DIRECTORIES:
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["doctor", "--config", str(config_path)])
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload["configuration_status"] == "loaded"
    assert payload["database_status"] == "unavailable"
    assert payload["diagnostics"] == [
        "configuration loaded",
        "database is not initialized",
    ]
    assert payload["healthy"] is False
    assert not database_path.exists()
    assert str(tmp_path) not in result.stdout
    assert "sqlite:///" not in result.stdout
    assert "Traceback" not in result.stdout


def test_doctor_redacts_credentials_when_database_driver_is_unavailable(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    secret = "doctor-secret-value"
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        f"database:\n  url: postgresql+missingdoctor://analyst:{secret}@localhost/aegis\n",
        encoding="utf-8",
    )
    for directory in cli.REQUIRED_DIRECTORIES:
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path)

    result = runner.invoke(cli.app, ["doctor", "--config", str(config_path)])
    payload = json.loads(result.stdout)

    assert result.exit_code == 1
    assert payload["configuration_status"] == "loaded"
    assert payload["database_status"] == "unavailable"
    assert payload["diagnostics"][-1] == "database connection is unavailable"
    assert secret not in result.stdout
    assert "analyst" not in result.stdout
    assert "localhost" not in result.stdout
    assert str(tmp_path) not in result.stdout
    assert "Traceback" not in result.stdout


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


def test_init_db_is_repeatable_and_does_not_expose_database_url(tmp_path: Path) -> None:
    database_path = tmp_path / "cli.db"
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        f"database:\n  url: sqlite:///{database_path}\n",
        encoding="utf-8",
    )

    first = runner.invoke(cli.app, ["init-db", "--config", str(config_path)])
    second = runner.invoke(cli.app, ["init-db", "--config", str(config_path)])

    assert first.exit_code == 0
    assert second.exit_code == 0
    payload = json.loads(first.stdout)
    assert payload == {
        "dialect": "sqlite",
        "journal_mode": "wal",
        "schema_version": 1,
        "status": "initialized",
    }
    assert str(database_path) not in first.stdout


def test_init_db_reports_configuration_failure(tmp_path: Path) -> None:
    missing = tmp_path / "missing.yaml"

    result = runner.invoke(cli.app, ["init-db", "--config", str(missing)])

    assert result.exit_code != 0


def test_ingest_pcap_command_runs_against_explicit_local_configuration(
    tmp_path: Path,
) -> None:
    sample = Path(__file__).parents[2] / "data" / "sample" / "phase2-benign.pcap"
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        f"""
database:
  url: sqlite:///{tmp_path / "cli-ingestion.db"}
ingestion:
  storage_root: {tmp_path / "raw"}
  sample_root: {sample.parent}
  max_upload_bytes: 1024
  chunk_size_bytes: 16
  max_records: 10
""".strip(),
        encoding="utf-8",
    )

    result = runner.invoke(
        cli.app,
        ["ingest", "pcap", str(sample), "--config", str(config_path)],
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "completed"
    assert payload["records_processed"] == 1


def test_ingest_reports_configuration_failure_without_traceback(tmp_path: Path) -> None:
    sample = Path(__file__).parents[2] / "data" / "sample" / "phase2-benign.pcap"

    result = runner.invoke(
        cli.app,
        ["ingest", "pcap", str(sample), "--config", str(tmp_path / "missing.yaml")],
    )

    assert result.exit_code == 1
    assert "Ingestion failed" in result.output
    assert "Traceback" not in result.output
