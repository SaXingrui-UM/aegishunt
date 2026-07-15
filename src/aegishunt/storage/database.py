"""SQLAlchemy engine lifecycle and repeatable SQLite initialization."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event, inspect, make_url, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from aegishunt.config import DatabaseSettings
from aegishunt.errors import DatabaseInitializationError, SchemaVersionError
from aegishunt.storage import models as _models
from aegishunt.storage.base import Base
from aegishunt.storage.schema_version import ensure_schema_version


def _prepare_sqlite_parent(database_url: str) -> None:
    """Create only the configured parent directory for a file-backed SQLite URL."""

    url = make_url(database_url)
    if url.get_backend_name() != "sqlite" or not url.database or url.database == ":memory:":
        return
    Path(url.database).expanduser().parent.mkdir(parents=True, exist_ok=True)


def _configure_sqlite(engine: Engine, settings: DatabaseSettings) -> None:
    """Install connection-level integrity and concurrency pragmas."""

    if engine.dialect.name != "sqlite":
        return

    @event.listens_for(engine, "connect")
    def set_sqlite_pragmas(dbapi_connection: Any, connection_record: Any) -> None:
        del connection_record
        cursor = dbapi_connection.cursor()
        try:
            if settings.enable_foreign_keys:
                cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={settings.busy_timeout_ms}")
            if settings.enable_wal:
                cursor.execute("PRAGMA journal_mode=WAL")
        finally:
            cursor.close()


class Database:
    """Own one engine and provide explicit transaction/session boundaries."""

    def __init__(self, settings: DatabaseSettings) -> None:
        try:
            _prepare_sqlite_parent(settings.url)
            url = make_url(settings.url)
            connect_args: dict[str, Any] = {}
            if url.get_backend_name() == "sqlite":
                connect_args = {
                    "check_same_thread": False,
                    "timeout": settings.busy_timeout_ms / 1_000,
                }
            self.engine = create_engine(
                settings.url,
                echo=settings.echo,
                future=True,
                pool_pre_ping=True,
                connect_args=connect_args,
            )
        except (OSError, SQLAlchemyError, ValueError) as exc:
            raise DatabaseInitializationError("database engine configuration failed") from exc
        _configure_sqlite(self.engine, settings)
        self._session_factory = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )

    def initialize(self) -> int:
        """Create missing tables and register the current schema idempotently."""

        try:
            existing_tables = set(inspect(self.engine).get_table_names())
            if existing_tables and "schema_versions" not in existing_tables:
                raise SchemaVersionError(
                    "refusing to initialize a non-empty database without a schema version"
                )
            if "schema_versions" in existing_tables:
                with self.session() as session, session.begin():
                    ensure_schema_version(session)
            Base.metadata.create_all(self.engine)
            with self.session() as session, session.begin():
                return ensure_schema_version(session)
        except SQLAlchemyError as exc:
            raise DatabaseInitializationError("database initialization failed") from exc

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Yield a session; callers explicitly select transaction boundaries."""

        with self._session_factory() as session:
            yield session

    def journal_mode(self) -> str:
        """Return the active SQLite journal mode for diagnostics."""

        if self.engine.dialect.name != "sqlite":
            return "not-applicable"
        with self.engine.connect() as connection:
            value = connection.scalar(text("PRAGMA journal_mode"))
        return str(value).lower()

    def dispose(self) -> None:
        """Release pooled connections."""

        self.engine.dispose()


assert _models
