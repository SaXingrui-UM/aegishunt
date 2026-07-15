"""Cross-phase configuration, database, repository, and startup verification."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSettings, DatabaseSettings, IngestionSettings, load_settings
from aegishunt.errors import ConfigurationError
from aegishunt.frontend.app import main as frontend_main
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.schemas.telemetry import TelemetrySource
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository, TelemetrySourceRepository

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"
EXPECTED_TABLES = {
    "alert_groups",
    "analyst_feedback",
    "audit_events",
    "detection_results",
    "investigation_cases",
    "model_versions",
    "network_flows",
    "schema_versions",
    "security_alerts",
    "telemetry_sources",
    "threat_hypotheses",
}


def _write_config(path: Path, database_path: Path, storage_root: Path) -> None:
    path.write_text(
        f"""
application:
  environment: yaml-environment
database:
  url: sqlite:///{database_path}
  busy_timeout_ms: 7000
ingestion:
  storage_root: {storage_root}
  sample_root: {SAMPLE_ROOT}
  max_upload_bytes: 2048
  chunk_size_bytes: 32
  max_records: 20
""".strip(),
        encoding="utf-8",
    )


def test_configuration_defaults_yaml_environment_and_rejections(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path = tmp_path / "application.yaml"
    _write_config(config_path, tmp_path / "yaml.sqlite3", Path("relative/raw"))
    empty_root = tmp_path / "empty-root"
    empty_root.mkdir()
    monkeypatch.chdir(empty_root)

    defaults = load_settings(environ={})
    yaml_settings = load_settings(config_path, environ={})
    overridden = load_settings(
        config_path,
        environ={
            "AEGISHUNT_APPLICATION__ENVIRONMENT": "environment-override",
            "AEGISHUNT_DATABASE__BUSY_TIMEOUT_MS": "9000",
        },
    )

    assert defaults == ApplicationSettings()
    assert yaml_settings.environment == "yaml-environment"
    assert yaml_settings.ingestion.storage_root == Path("relative/raw")
    assert overridden.environment == "environment-override"
    assert overridden.database.busy_timeout_ms == 9000

    with pytest.raises(ConfigurationError, match="database URL"):
        load_settings(environ={"AEGISHUNT_DATABASE__URL": "invalid"})
    with pytest.raises(ConfigurationError, match="log_level"):
        load_settings(environ={"AEGISHUNT_APPLICATION__LOG_LEVEL": "INVALID"})


def test_doctor_reports_supported_runtime_and_required_directories(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for directory in cli.REQUIRED_DIRECTORIES:
        (tmp_path / directory).mkdir()
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(cli.app, ["doctor"], catch_exceptions=False)
    report = json.loads(result.stdout)

    assert result.exit_code == 0
    assert report["python_supported"] is True
    assert report["operating_system"]
    assert report["machine"]
    assert report["project_root"] == str(tmp_path.resolve())
    assert report["directories"] == {directory: True for directory in cli.REQUIRED_DIRECTORIES}
    assert "password" not in result.stdout.lower()


def test_repeatable_init_db_and_connection_pragmas(tmp_path: Path) -> None:
    database_path = tmp_path / "foundation.sqlite3"
    config_path = tmp_path / "application.yaml"
    _write_config(config_path, database_path, tmp_path / "raw")
    runner = CliRunner()

    first = runner.invoke(cli.app, ["init-db", "--config", str(config_path)])
    second = runner.invoke(cli.app, ["init-db", "--config", str(config_path)])

    assert first.exit_code == second.exit_code == 0
    assert json.loads(first.stdout)["schema_version"] == 1
    database = Database(DatabaseSettings(url=f"sqlite:///{database_path}", busy_timeout_ms=7000))
    try:
        assert database.initialize() == 1
        assert database.journal_mode() == "wal"
        assert set(inspect(database.engine).get_table_names()) == EXPECTED_TABLES
        with database.engine.connect() as connection:
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1
            assert connection.scalar(text("PRAGMA busy_timeout")) == 7000
            assert connection.scalar(text("SELECT version FROM schema_versions")) == 1
    finally:
        database.dispose()


def test_repository_commit_rollback_pagination_update_and_audit(tmp_path: Path) -> None:
    database = Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'repositories.sqlite3'}"))
    database.initialize()
    committed: list[TelemetrySource] = []
    try:
        with database.session() as session, session.begin():
            repository = TelemetrySourceRepository(session, AuditLogRepository(session))
            for index in range(1, 5):
                committed.append(
                    repository.add(
                        TelemetrySource(
                            source_id=UUID(int=index),
                            source_type=SourceType.JSON_EVENT,
                            filename_or_interface=f"event-{index}.json",
                            ingestion_mode=IngestionMode.IMPORT,
                        ),
                        actor="integration-verification",
                    )
                )

        with database.session() as session:
            transaction = session.begin()
            repository = TelemetrySourceRepository(session, AuditLogRepository(session))
            rolled_back = repository.add(
                TelemetrySource(
                    source_id=UUID(int=99),
                    source_type=SourceType.PCAP,
                    filename_or_interface="rolled-back.pcap",
                    ingestion_mode=IngestionMode.IMPORT,
                ),
                actor="integration-verification",
            )
            transaction.rollback()

        with database.session() as session, session.begin():
            repository = TelemetrySourceRepository(session, AuditLogRepository(session))
            stored = repository.get(committed[0].source_id)
            assert stored == committed[0]
            assert repository.get(rolled_back.source_id) is None
            first_page, total = repository.list_page(limit=2, offset=0)
            second_page, _ = repository.list_page(limit=2, offset=2)
            assert total == 4
            assert first_page + second_page == committed
            updated = TelemetrySource.model_validate(
                {**stored.model_dump(), "status": LifecycleStatus.RUNNING}
            )
            repository.update(updated, actor="integration-verification")

        with database.session() as session:
            repository = TelemetrySourceRepository(session)
            assert repository.get(committed[0].source_id) is not None
            assert repository.get(committed[0].source_id).status is LifecycleStatus.RUNNING
            assert repository.get(UUID(int=1000)) is None
            assert len(AuditLogRepository(session).list()) == 5
    finally:
        database.dispose()


def test_empty_database_api_and_frontend_import(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'empty.sqlite3'}"),
        ingestion=IngestionSettings(storage_root=tmp_path / "raw", sample_root=SAMPLE_ROOT),
    )

    with TestClient(create_app(settings)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200

    assert callable(frontend_main)
