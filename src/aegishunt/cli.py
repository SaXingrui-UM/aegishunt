"""Command-line entry point for application shells and data-foundation setup."""

from __future__ import annotations

import json
import platform
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from sqlalchemy import make_url, text
from sqlalchemy.exc import SQLAlchemyError

from aegishunt.config import DatabaseSettings, load_settings
from aegishunt.datasets.cli import dataset_app
from aegishunt.errors import AegisHuntError
from aegishunt.ingestion.cli import ingest_app
from aegishunt.metadata import APPLICATION_DESCRIPTION, APPLICATION_NAME
from aegishunt.ml.anomaly.cli import anomaly_app
from aegishunt.ml.fusion.cli import fusion_app
from aegishunt.ml.supervised.cli import model_app
from aegishunt.storage import Database

app = typer.Typer(
    name="aegishunt",
    help=f"{APPLICATION_NAME}: {APPLICATION_DESCRIPTION}",
    no_args_is_help=True,
)
app.add_typer(ingest_app)
app.add_typer(dataset_app)
app.add_typer(model_app)
app.add_typer(anomaly_app)
app.add_typer(fusion_app)

REQUIRED_DIRECTORIES = ("configs", "data", "artifacts", "reports")


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Structured result from the local foundation checks."""

    python_version: str
    python_supported: bool
    operating_system: str
    machine: str
    directories: dict[str, bool]
    configuration_status: str
    database_status: str
    diagnostics: tuple[str, ...]

    @property
    def healthy(self) -> bool:
        """Return whether all Phase 0 prerequisites are present."""

        return (
            self.python_supported
            and all(self.directories.values())
            and self.configuration_status == "loaded"
            and self.database_status == "available"
        )

    def to_json(self) -> str:
        """Serialize the report for readable CLI output."""

        return json.dumps({**asdict(self), "healthy": self.healthy}, indent=2, sort_keys=True)


@dataclass(frozen=True, slots=True)
class DatabaseInitializationReport:
    """Safe operator-facing result of repeatable database initialization."""

    status: str
    dialect: str
    schema_version: int
    journal_mode: str

    def to_json(self) -> str:
        """Serialize the result without exposing a database URL or credentials."""

        return json.dumps(asdict(self), indent=2, sort_keys=True)


def _database_availability(settings: DatabaseSettings) -> tuple[str, str]:
    """Check one configured database without exposing or creating its location."""

    try:
        url = make_url(settings.url)
    except (SQLAlchemyError, ValueError):
        return "unavailable", "database configuration is invalid"

    if url.get_backend_name() == "sqlite" and url.database and url.database != ":memory:":
        database_path = Path(url.database).expanduser()
        if not database_path.is_absolute():
            database_path = Path.cwd() / database_path
        if not database_path.is_file():
            return "unavailable", "database is not initialized"

    try:
        database = Database(settings)
        try:
            with database.engine.connect() as connection:
                available = connection.scalar(text("SELECT 1")) == 1
        finally:
            database.dispose()
    except (AegisHuntError, ImportError, OSError, SQLAlchemyError, ValueError):
        return "unavailable", "database connection is unavailable"
    if not available:
        return "unavailable", "database connection check failed"
    return "available", "database connection succeeded"


def collect_doctor_report(
    project_root: Path | None = None,
    config_path: Path | None = None,
) -> DoctorReport:
    """Inspect runtime, directories, configuration, and database availability."""

    root = (project_root or Path.cwd()).resolve()
    diagnostics: tuple[str, ...]
    try:
        settings = load_settings(config_path)
    except AegisHuntError:
        configuration_status = "error"
        database_status = "not_checked"
        diagnostics = ("configuration could not be loaded or validated",)
    else:
        configuration_status = "loaded"
        database_status, database_diagnostic = _database_availability(settings.database)
        diagnostics = ("configuration loaded", database_diagnostic)
    return DoctorReport(
        python_version=platform.python_version(),
        python_supported=sys.version_info >= (3, 11),
        operating_system=platform.system(),
        machine=platform.machine(),
        directories={name: (root / name).is_dir() for name in REQUIRED_DIRECTORIES},
        configuration_status=configuration_status,
        database_status=database_status,
        diagnostics=diagnostics,
    )


def run_api(host: str, port: int, reload: bool) -> None:
    """Run the minimal FastAPI application."""

    uvicorn.run("aegishunt.api.app:app", host=host, port=port, reload=reload)


def run_frontend(address: str, port: int, headless: bool) -> int:
    """Run the minimal Streamlit page in a child Python process."""

    script = Path(__file__).resolve().parent / "frontend" / "app.py"
    command = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(script),
        "--server.address",
        address,
        "--server.port",
        str(port),
        "--server.headless",
        str(headless).lower(),
    ]
    return subprocess.run(command, check=False).returncode


def initialize_database(config_path: Path | None = None) -> DatabaseInitializationReport:
    """Load validated settings and initialize the configured database."""

    settings = load_settings(config_path)
    database = Database(settings.database)
    try:
        schema_version = database.initialize()
        return DatabaseInitializationReport(
            status="initialized",
            dialect=database.engine.dialect.name,
            schema_version=schema_version,
            journal_mode=database.journal_mode(),
        )
    finally:
        database.dispose()


@app.command()
def doctor(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            help="YAML configuration file; environment variables override its values.",
        ),
    ] = None,
) -> None:
    """Check runtime, directories, configuration, and database availability."""

    report = collect_doctor_report(config_path=config)
    typer.echo(report.to_json())
    if not report.healthy:
        raise typer.Exit(code=1)


@app.command("init-db")
def init_db(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            dir_okay=False,
            readable=True,
            help="YAML configuration file; environment variables override its values.",
        ),
    ] = None,
) -> None:
    """Initialize or verify the configured database schema."""

    try:
        report = initialize_database(config)
    except AegisHuntError as exc:
        typer.echo(f"Database initialization failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(report.to_json())


@app.command()
def api(
    host: Annotated[str, typer.Option(help="Interface on which the API listens.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="API TCP port.")] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload/--no-reload", help="Reload when source files change."),
    ] = False,
) -> None:
    """Start the minimal FastAPI application."""

    run_api(host=host, port=port, reload=reload)


@app.command()
def frontend(
    address: Annotated[
        str,
        typer.Option(help="Interface on which Streamlit listens."),
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option(min=1, max=65535, help="Streamlit TCP port.")] = 8501,
    headless: Annotated[
        bool,
        typer.Option("--headless/--no-headless", help="Run without opening a browser."),
    ] = True,
) -> None:
    """Start the minimal Streamlit research-prototype page."""

    exit_code = run_frontend(address=address, port=port, headless=headless)
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
