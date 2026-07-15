"""Typer commands for explicit local telemetry and sample ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.ingestion.service import IngestionService
from aegishunt.schemas.enums import SourceType
from aegishunt.storage import Database

ingest_app = typer.Typer(
    name="ingest",
    help="Validate and safely import telemetry without packet-to-flow processing.",
    no_args_is_help=True,
)

TelemetryPath = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
]
ConfigPath = Annotated[
    Path | None,
    typer.Option(
        "--config",
        dir_okay=False,
        readable=True,
        help="YAML configuration file; environment variables override its values.",
    ),
]


def _run_path(path: Path, source_type: SourceType, config: Path | None) -> None:
    database: Database | None = None
    try:
        settings = load_settings(config)
        database = Database(settings.database)
        database.initialize()
        job = IngestionService(database, settings.ingestion).ingest_path(
            path,
            source_type=source_type,
            actor="cli",
        )
    except AegisHuntError as exc:
        typer.echo(f"Ingestion failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if database is not None:
            database.dispose()
    typer.echo(json.dumps(job.model_dump(mode="json"), indent=2, sort_keys=True))


@ingest_app.command("pcap")
def ingest_pcap(path: TelemetryPath, config: ConfigPath = None) -> None:
    """Import and validate one PCAP or PCAPNG container."""

    _run_path(path, SourceType.PCAP, config)


@ingest_app.command("csv")
def ingest_csv(path: TelemetryPath, config: ConfigPath = None) -> None:
    """Import and validate one canonical flow CSV."""

    _run_path(path, SourceType.FLOW_CSV, config)


@ingest_app.command("json")
def ingest_json(path: TelemetryPath, config: ConfigPath = None) -> None:
    """Import and validate structured JSON events."""

    _run_path(path, SourceType.JSON_EVENT, config)


@ingest_app.command("sample")
def ingest_sample(
    sample_id: Annotated[str, typer.Argument(help="Allowlisted sample identifier.")],
    config: ConfigPath = None,
) -> None:
    """Import one checksum-verified local demonstration sample."""

    database: Database | None = None
    try:
        settings = load_settings(config)
        database = Database(settings.database)
        database.initialize()
        job = IngestionService(database, settings.ingestion).ingest_sample(
            sample_id,
            actor="cli",
        )
    except AegisHuntError as exc:
        typer.echo(f"Ingestion failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        if database is not None:
            database.dispose()
    typer.echo(json.dumps(job.model_dump(mode="json"), indent=2, sort_keys=True))
