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


def migrate_existing_schema(engine: Engine, *, current_version: int) -> None:
    """Upgrade a versioned database without overwriting existing evidence."""

    with engine.connect() as connection:
        existing = connection.scalar(text("SELECT MAX(version) FROM schema_versions"))
    if existing is None or int(existing) == current_version:
        return
    if int(existing) != 1 or current_version != 2:
        raise SchemaVersionError(
            f"database schema version {existing} is incompatible with required "
            f"version {current_version}"
        )
    if engine.dialect.name != "sqlite":
        raise SchemaVersionError("schema version 1 migration is supported only for SQLite")

    inspector = inspect(engine)
    table_names = set(inspector.get_table_names())
    if not set(_V1_TO_V2_COLUMNS).issubset(table_names):
        raise SchemaVersionError("schema version 1 is missing required detection tables")

    with engine.begin() as connection:
        for table_name, declarations in _V1_TO_V2_COLUMNS.items():
            existing_columns = {
                item["name"] for item in inspect(connection).get_columns(table_name)
            }
            for declaration in declarations:
                column_name = declaration.split(maxsplit=1)[0]
                if column_name not in existing_columns:
                    connection.execute(
                        text(f"ALTER TABLE {table_name} ADD COLUMN {declaration}")
                    )
        connection.execute(
            text(
                "INSERT INTO schema_versions (version, applied_at) "
                "VALUES (:version, :applied_at)"
            ),
            {"version": current_version, "applied_at": datetime.now(UTC).isoformat()},
        )
