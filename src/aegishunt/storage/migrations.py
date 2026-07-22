"""Ordered, additive database migrations for persisted AegisHunt evidence."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Engine, inspect, text

from aegishunt.errors import SchemaVersionError

_V1_TO_V2_COLUMNS: dict[str, tuple[str, ...]] = {
    "detection_results": (
        "supervised_threshold FLOAT",
        "anomaly_threshold FLOAT",
        "fusion_score FLOAT",
        "fusion_threshold FLOAT",
        "risk_source VARCHAR(64)",
        "alert_threshold FLOAT",
        "policy_versions JSON DEFAULT '{}'",
        "policy_checksums JSON DEFAULT '{}'",
        "feature_schema_version VARCHAR(64)",
        "reason_codes JSON DEFAULT '[]'",
    ),
    "security_alerts": (
        "risk_score FLOAT",
        "explanation JSON DEFAULT '{}'",
        "model_versions JSON DEFAULT '{}'",
        "policy_versions JSON DEFAULT '{}'",
        "analyst_verdict VARCHAR(64)",
        "updated_at DATETIME",
    ),
}

_V2_TO_V3_COLUMNS: dict[str, tuple[str, ...]] = {
    "alert_groups": (
        "matched_rule_ids JSON DEFAULT '[]'",
        "score_components JSON DEFAULT '{}'",
        "alert_count INTEGER",
        "severity VARCHAR(32)",
        "evidence JSON DEFAULT '{}'",
        "policy_id VARCHAR(255)",
        "policy_version VARCHAR(64)",
        "policy_checksum VARCHAR(64)",
        "status VARCHAR(64) DEFAULT 'open'",
        "group_schema_version VARCHAR(64)",
        "created_at DATETIME",
    ),
    "threat_hypotheses": (
        "group_id CHAR(32)",
        "confidence_components JSON DEFAULT '{}'",
        "observed_facts JSON DEFAULT '[]'",
        "derived_inferences JSON DEFAULT '[]'",
        "primary_template_id VARCHAR(255)",
        "template_catalog_version VARCHAR(64)",
        "candidate_template_ids JSON DEFAULT '[]'",
        "source_group_snapshot JSON DEFAULT '{}'",
        "policy_id VARCHAR(255)",
        "policy_version VARCHAR(64)",
        "policy_checksum VARCHAR(64)",
        "hypothesis_schema_version VARCHAR(64)",
        "updated_at DATETIME",
    ),
}


def _add_columns(engine: Engine, columns: dict[str, tuple[str, ...]]) -> None:
    table_names = set(inspect(engine).get_table_names())
    if not set(columns).issubset(table_names):
        raise SchemaVersionError("database schema is missing required migration tables")
    with engine.begin() as connection:
        for table_name, declarations in columns.items():
            existing_columns = {
                item["name"] for item in inspect(connection).get_columns(table_name)
            }
            for declaration in declarations:
                column_name = declaration.split(maxsplit=1)[0]
                if column_name not in existing_columns:
                    connection.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {declaration}")
                    )


def migrate_existing_schema(engine: Engine, *, current_version: int) -> None:
    """Upgrade a versioned database without overwriting existing evidence."""

    with engine.connect() as connection:
        existing = connection.scalar(text("SELECT MAX(version) FROM schema_versions"))
    if existing is None or int(existing) == current_version:
        return
    version = int(existing)
    if current_version != 3 or version not in {1, 2}:
        raise SchemaVersionError(
            f"database schema version {existing} is incompatible with required "
            f"version {current_version}"
        )
    if engine.dialect.name != "sqlite":
        raise SchemaVersionError("additive schema migration is supported only for SQLite")
    migrations = ((1, 2, _V1_TO_V2_COLUMNS), (2, 3, _V2_TO_V3_COLUMNS))
    for source, target, columns in migrations:
        if version != source:
            continue
        _add_columns(engine, columns)
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO schema_versions (version, applied_at) "
                    "VALUES (:version, :applied_at)"
                ),
                {"version": target, "applied_at": datetime.now(UTC).isoformat()},
            )
        version = target
    if version != current_version:
        raise SchemaVersionError("database schema migration did not reach required version")
