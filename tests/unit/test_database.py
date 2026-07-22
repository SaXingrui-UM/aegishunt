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
        assert database.initialize() == 3
        assert database.initialize() == 3
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
            session.add(SchemaVersionRecord(version=4))

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


def test_schema_version_one_is_additively_migrated_without_deleting_rows(
    tmp_path: Path,
) -> None:
    path = tmp_path / "version-one.db"
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "CREATE TABLE schema_versions ("
                    "version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE alert_groups ("
                    "group_id CHAR(32) PRIMARY KEY, alert_ids JSON NOT NULL, "
                    "entity_keys JSON NOT NULL, correlation_score FLOAT NOT NULL, "
                    "first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, "
                    "summary TEXT NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE threat_hypotheses ("
                    "hypothesis_id CHAR(32) PRIMARY KEY, title VARCHAR(255) NOT NULL, "
                    "description TEXT NOT NULL, confidence FLOAT NOT NULL, "
                    "severity VARCHAR(32) NOT NULL, involved_entities JSON NOT NULL, "
                    "supporting_alert_ids JSON NOT NULL, supporting_features JSON NOT NULL, "
                    "first_seen DATETIME NOT NULL, last_seen DATETIME NOT NULL, "
                    "possible_attack_category VARCHAR(255), possible_mitre_mappings JSON NOT NULL, "
                    "assumptions JSON NOT NULL, alternative_explanations JSON NOT NULL, "
                    "recommended_queries JSON NOT NULL, recommended_steps JSON NOT NULL, "
                    "status VARCHAR(32) NOT NULL, created_at DATETIME NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO schema_versions VALUES "
                    "(1, '2026-01-01T00:00:00+00:00')"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE detection_results ("
                    "detection_id CHAR(32) PRIMARY KEY, flow_id CHAR(32) NOT NULL, "
                    "supervised_label VARCHAR(255), supervised_probability FLOAT, "
                    "anomaly_score FLOAT, normalized_anomaly_score FLOAT, "
                    "behavioral_rule_score FLOAT, combined_risk_score FLOAT NOT NULL, "
                    "severity VARCHAR(32) NOT NULL, model_versions JSON NOT NULL, "
                    "explanation JSON NOT NULL, detected_at DATETIME NOT NULL)"
                )
            )
            connection.execute(
                text(
                    "INSERT INTO detection_results VALUES ("
                    "'00000000000000000000000000000001', "
                    "'00000000000000000000000000000002', NULL, NULL, NULL, NULL, NULL, "
                    "0.5, 'medium', '{}', '{}', '2026-01-01T00:00:00+00:00')"
                )
            )
            connection.execute(
                text(
                    "CREATE TABLE security_alerts ("
                    "alert_id CHAR(32) PRIMARY KEY, detection_id CHAR(32) NOT NULL, "
                    "alert_type VARCHAR(255) NOT NULL, severity VARCHAR(32) NOT NULL, "
                    "title VARCHAR(255) NOT NULL, description TEXT NOT NULL, "
                    "involved_entities JSON NOT NULL, evidence JSON NOT NULL, "
                    "reason_codes JSON NOT NULL, status VARCHAR(32) NOT NULL, "
                    "created_at DATETIME NOT NULL)"
                )
            )
    finally:
        engine.dispose()

    database = Database(DatabaseSettings(url=f"sqlite:///{path}"))
    try:
        assert database.initialize() == 3
        assert database.initialize() == 3
        columns = {
            column["name"]
            for column in inspect(database.engine).get_columns("detection_results")
        }
        assert {"fusion_score", "risk_source", "policy_versions", "reason_codes"} <= columns
        group_columns = {
            column["name"]
            for column in inspect(database.engine).get_columns("alert_groups")
        }
        assert {
            "matched_rule_ids",
            "score_components",
            "policy_checksum",
            "group_schema_version",
        } <= group_columns
        hypothesis_columns = {
            column["name"]
            for column in inspect(database.engine).get_columns("threat_hypotheses")
        }
        assert {
            "group_id",
            "confidence_components",
            "source_group_snapshot",
            "template_catalog_version",
            "hypothesis_schema_version",
        } <= hypothesis_columns
        with database.engine.connect() as connection:
            assert connection.scalar(text("SELECT COUNT(*) FROM detection_results")) == 1
            versions = connection.execute(
                text("SELECT version FROM schema_versions ORDER BY version")
            ).scalars()
            assert tuple(versions) == (1, 2, 3)
    finally:
        database.dispose()
