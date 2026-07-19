"""Explicit Phase 6 train, frozen-test, verification, and scoring commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.ml.anomaly.errors import AnomalyError
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch
from aegishunt.ml.anomaly.service import AnomalyTrainingService

anomaly_app = typer.Typer(
    name="anomaly",
    help="Train and score a benign-baseline anomaly model without fusion or alerts.",
    no_args_is_help=True,
)

ConfigPath = Annotated[
    Path | None,
    typer.Option(
        "--config",
        dir_okay=False,
        readable=True,
        help="YAML application configuration; environment variables override it.",
    ),
]
DataDirectory = Annotated[
    Path,
    typer.Option("--data-dir", exists=True, file_okay=False, readable=True),
]
DatasetReportDirectory = Annotated[
    Path,
    typer.Option("--dataset-report-dir", exists=True, file_okay=False, readable=True),
]


def _service(
    config: Path | None,
    data_dir: Path | None = None,
    dataset_report_dir: Path | None = None,
) -> AnomalyTrainingService:
    settings = load_settings(config)
    return AnomalyTrainingService(
        data_root=data_dir or settings.datasets.processed_root,
        dataset_report_root=dataset_report_dir or settings.datasets.reports_root,
        training_config_path=settings.anomaly.training_config_path,
        artifact_root=settings.anomaly.artifact_root,
        reports_root=settings.anomaly.reports_root,
    )


def _fail(exc: AegisHuntError | OSError | ValidationError) -> None:
    message = str(exc) if isinstance(exc, AnomalyError) else "configuration or input was rejected"
    typer.echo(f"Anomaly operation failed: {message}", err=True)
    raise typer.Exit(code=1) from exc


@anomaly_app.command("train")
def train_anomaly(
    data_dir: DataDirectory,
    dataset_report_dir: DatasetReportDirectory,
    allow_controlled_demo: Annotated[
        bool,
        typer.Option(
            "--allow-controlled-demo",
            help="Explicitly permit pipeline-only controlled synthetic evidence.",
        ),
    ] = False,
    config: ConfigPath = None,
) -> None:
    """Fit benign-only candidates and freeze validation selection without test access."""

    try:
        result = _service(config, data_dir, dataset_report_dir).train(
            allow_controlled_demo=allow_controlled_demo
        )
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "experiment_id": result.experiment_id,
                "model_id": result.model_id,
                "model_version": result.model_version,
                "selected_algorithm": result.selected_algorithm,
                "selected_candidate_id": result.selected_candidate_id,
                "pipeline_verification_only": result.pipeline_verification_only,
                "status": result.status,
                "candidate_smoke_passed": result.candidate_smoke_passed,
                "test_data_accessed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@anomaly_app.command("test")
def test_anomaly(
    data_dir: DataDirectory,
    dataset_report_dir: DatasetReportDirectory,
    allow_controlled_demo: Annotated[
        bool,
        typer.Option(
            "--allow-controlled-demo",
            help="Explicitly permit the one-time controlled-demo frozen evaluation.",
        ),
    ] = False,
    config: ConfigPath = None,
) -> None:
    """Evaluate frozen test once and finalize the anomaly model bundle."""

    try:
        result = _service(config, data_dir, dataset_report_dir).evaluate_test(
            allow_controlled_demo=allow_controlled_demo
        )
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "model_version": result.bundle_version,
                "pipeline_verification_only": result.pipeline_verification_only,
                "status": "anomaly_frozen_test_evaluated_once",
                "test_affected_selection": False,
                "metrics": result.report.metrics.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@anomaly_app.command("list")
def list_anomaly_models(config: ConfigPath = None) -> None:
    """List integrity-validated anomaly bundles from configured storage."""

    try:
        models = _service(config).list_models()
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            [
                {
                    "model_id": model.model_id,
                    "model_version": model.model_version,
                    "algorithm": model.algorithm,
                    "status": model.status,
                    "pipeline_verification_only": model.pipeline_verification_only,
                }
                for model in models
            ],
            indent=2,
            sort_keys=True,
        )
    )


@anomaly_app.command("describe")
def describe_anomaly_model(model_version: str, config: ConfigPath = None) -> None:
    """Show the verified bundle manifest without exposing filesystem paths."""

    try:
        payload = _service(config).describe(model_version)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(payload)


@anomaly_app.command("verify")
def verify_anomaly_model(model_version: str, config: ConfigPath = None) -> None:
    """Verify exact inventory, checksums, types, schema, normalizer, and threshold."""

    try:
        manifest = _service(config).verify(model_version)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "model_id": manifest.model_id,
                "model_version": manifest.model_version,
                "status": "verified",
                "artifact_checksum": manifest.artifact_checksum,
                "score_semantics": "higher normalized score means more anomalous; not probability",
            },
            sort_keys=True,
        )
    )


@anomaly_app.command("predict")
def predict_anomaly(
    model_version: str,
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=True, dir_okay=False, readable=True),
    ],
    config: ConfigPath = None,
) -> None:
    """Score a strict feature batch without creating alerts, risk, or fusion output."""

    try:
        batch = AnomalyPredictionBatch.model_validate_json(
            input_path.read_text(encoding="utf-8")
        )
        results = _service(config).predict(model_version, batch)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            [result.model_dump(mode="json") for result in results],
            indent=2,
            sort_keys=True,
        )
    )
