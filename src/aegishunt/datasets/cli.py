"""Typer commands for explicit Phase 4 dataset workflows."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Annotated

import typer

from aegishunt.config import load_settings
from aegishunt.datasets.artifacts import write_json_model
from aegishunt.datasets.errors import DatasetError
from aegishunt.datasets.reports import DatasetManifest
from aegishunt.datasets.service import DatasetService
from aegishunt.errors import AegisHuntError

dataset_app = typer.Typer(
    name="dataset",
    help="Register, validate, transform, and quality-check datasets without model training.",
    no_args_is_help=True,
)

ConfigPath = Annotated[
    Path | None,
    typer.Option(
        "--config",
        dir_okay=False,
        readable=True,
        help="YAML configuration file; environment variables override its values.",
    ),
]
CanonicalPath = Annotated[
    Path,
    typer.Argument(exists=True, file_okay=True, dir_okay=False, readable=True),
]


def _service(config: Path | None) -> DatasetService:
    return DatasetService(load_settings(config).datasets)


def _fail(exc: AegisHuntError | ValueError) -> None:
    typer.echo(f"Dataset operation failed: {exc}", err=True)
    raise typer.Exit(code=1) from exc


@dataset_app.command("list")
def list_datasets(config: ConfigPath = None) -> None:
    """List stable registered dataset IDs and declared readiness."""

    try:
        entries = _service(config).list()
    except AegisHuntError as exc:
        _fail(exc)
    payload = [
        {
            "dataset_id": entry.dataset_id,
            "name": entry.name,
            "version": entry.version,
            "download_status": entry.download_status,
            "conversion_status": entry.conversion_status,
        }
        for entry in entries
    ]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@dataset_app.command("describe")
def describe_dataset(dataset_id: str, config: ConfigPath = None) -> None:
    """Describe one static definition without exposing local runtime paths."""

    try:
        entry = _service(config).describe(dataset_id)
    except AegisHuntError as exc:
        _fail(exc)
    typer.echo(entry.model_dump_json(indent=2))


@dataset_app.command("download")
def download_dataset(
    dataset_id: str,
    local_file: Annotated[
        Path | None,
        typer.Option("--local-file", dir_okay=False, readable=True),
    ] = None,
    config: ConfigPath = None,
) -> None:
    """Acquire one explicitly automatic dataset; never accepts licenses for users."""

    try:
        service = _service(config)
        if local_file is None:
            path, checksum = service.download(dataset_id)
            payload: dict[str, object] = {"filename": path.name, "sha256": checksum}
        else:
            checksum, size = service.verify_manual_file(dataset_id, local_file)
            payload = {
                "filename": local_file.name,
                "sha256": checksum,
                "size_bytes": size,
                "status": "verified_local_file",
            }
    except AegisHuntError as exc:
        _fail(exc)
    typer.echo(json.dumps(payload, sort_keys=True))


@dataset_app.command("validate")
def validate_dataset(path: CanonicalPath, config: ConfigPath = None) -> None:
    """Validate canonical schema, feature order, finite values, labels, and provenance."""

    try:
        rows = _service(config).validate(path)
    except AegisHuntError as exc:
        _fail(exc)
    typer.echo(json.dumps({"status": "valid", "rows": len(rows)}, sort_keys=True))


@dataset_app.command("convert")
def convert_dataset(
    dataset_id: str,
    raw_path: CanonicalPath,
    output: Annotated[Path, typer.Option("--output", dir_okay=False)],
    access_date: Annotated[
        str,
        typer.Option(
            "--access-date",
            help="Operator-recorded source access date in YYYY-MM-DD format.",
        ),
    ],
    config: ConfigPath = None,
) -> None:
    """Convert an exact Phase 3 feature CSV to canonical JSON Lines."""

    try:
        source_access_date = date.fromisoformat(access_date)
        count, checksum = _service(config).convert_csv(
            dataset_id,
            raw_path,
            output,
            source_access_date=source_access_date,
        )
    except (AegisHuntError, ValueError) as exc:
        _fail(exc)
    typer.echo(json.dumps({"rows": count, "sha256": checksum}, sort_keys=True))


@dataset_app.command("build-demo")
def build_demo(
    data_dir: Annotated[Path | None, typer.Option("--data-dir", file_okay=False)] = None,
    report_dir: Annotated[Path | None, typer.Option("--report-dir", file_okay=False)] = None,
    seed: Annotated[int | None, typer.Option()] = None,
    config: ConfigPath = None,
) -> None:
    """Build the controlled synthetic dataset and all required reports entirely offline."""

    try:
        result = _service(config).build_demo(
            data_root=data_dir,
            report_root=report_dir,
            seed=seed,
        )
    except (AegisHuntError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "dataset_id": result.dataset_id,
                "rows": result.row_count,
                "groups": result.group_count,
                "quality_status": result.quality_report.status,
                "leakage_status": result.leakage_report.status,
                "frozen_test": result.split_manifest.frozen_test,
            },
            indent=2,
            sort_keys=True,
        )
    )


@dataset_app.command("quality")
def quality_dataset(
    path: CanonicalPath,
    output: Annotated[Path | None, typer.Option("--output", dir_okay=False)] = None,
    config: ConfigPath = None,
) -> None:
    """Analyze missingness, duplicates, class balance, and feature quality."""

    try:
        report = _service(config).quality(path)
        if output is not None:
            write_json_model(report, output)
    except AegisHuntError as exc:
        _fail(exc)
    typer.echo(report.model_dump_json(indent=2))


@dataset_app.command("split")
def split_dataset(
    path: CanonicalPath,
    data_dir: Annotated[Path, typer.Option("--data-dir", file_okay=False)],
    report_dir: Annotated[Path, typer.Option("--report-dir", file_okay=False)],
    seed: Annotated[int | None, typer.Option()] = None,
    config: ConfigPath = None,
) -> None:
    """Persist deterministic group-exclusive splits and fail-closed leakage reports."""

    try:
        result = _service(config).split_existing(
            path,
            data_root=data_dir,
            report_root=report_dir,
            seed=seed,
        )
    except (AegisHuntError, ValueError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "status": "split",
                "rows": result.row_count,
                "groups": result.group_count,
                "frozen_test": result.split_manifest.frozen_test,
                "leakage_status": result.leakage_report.status,
            },
            sort_keys=True,
        )
    )


@dataset_app.command("manifest")
def inspect_manifest(path: CanonicalPath) -> None:
    """Read one generated manifest as JSON without contacting a provider."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        manifest = DatasetManifest.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValueError):
        _fail(DatasetError("unable to read dataset manifest"))
    typer.echo(manifest.model_dump_json(indent=2))
