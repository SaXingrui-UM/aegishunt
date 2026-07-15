"""Tests for repeatable SQLite initialization, WAL, and schema compatibility."""

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

from aegishunt.config import DatabaseSettings
from aegishunt.errors import SchemaVersionError
from aegishunt.storage import Database
from aegishunt.storage.models.schema import SchemaVersionRecord


def database_for(tmp_path: Path) -> Database:
    return Database(DatabaseSettings(url=f"sqlite:///{tmp_path / 'foundation.db'}"))


def test_database_initialization_is_repeatable_and_enables_wal(tmp_path: Path) -> None:
    database = database_for(tmp_path)
    try:
        assert database.initialize() == 1
        assert database.initialize() == 1
        assert database.journal_mode() == "wal"
        tables = set(inspect(database.engine).get_table_names())
        assert {
            "telemetry_sources",
            "network_flows",
            "detection_results",
            "security_alerts",
            "alert_groups",
            "threat_hypotheses",
            "investigation_cases",
            "analyst_feedback",
            "model_versions",
            "audit_events",
            "schema_versions",
        } <= tables
    finally:
        database.dispose()


def test_incompatible_schema_version_is_rejected(tmp_path: Path) -> None:
    database = database_for(tmp_path)
    try:
        database.initialize()
        with database.session() as session, session.begin():
            session.add(SchemaVersionRecord(version=2))

        with pytest.raises(SchemaVersionError, match="incompatible"):
            database.initialize()
    finally:
        database.dispose()


def test_nonempty_unversioned_database_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "unversioned.db"
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as connection:
            connection.execute(text("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)"))
    finally:
        engine.dispose()

    database = Database(DatabaseSettings(url=f"sqlite:///{path}"))
    try:
        with pytest.raises(SchemaVersionError, match="non-empty"):
            database.initialize()
    finally:
        database.dispose()
