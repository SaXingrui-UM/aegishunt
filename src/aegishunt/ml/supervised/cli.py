"""Explicit Phase 5 training, frozen-test, bundle, and prediction commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.ml.supervised.errors import SupervisedError
from aegishunt.ml.supervised.prediction import PredictionBatch
from aegishunt.ml.supervised.service import SupervisedTrainingService

model_app = typer.Typer(
    name="model",
    help="Train, freeze, verify, and use supervised research models without anomaly detection.",
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
) -> SupervisedTrainingService:
    settings = load_settings(config)
    return SupervisedTrainingService(
        data_root=data_dir or settings.datasets.processed_root,
        dataset_report_root=dataset_report_dir or settings.datasets.reports_root,
        training_config_path=settings.supervised.training_config_path,
        artifact_root=settings.supervised.artifact_root,
        reports_root=settings.supervised.reports_root,
    )


def _fail(exc: AegisHuntError | OSError | ValidationError) -> None:
    message = (
        str(exc) if isinstance(exc, SupervisedError) else "configuration or input was rejected"
    )
    typer.echo(f"Model operation failed: {message}", err=True)
    raise typer.Exit(code=1) from exc


@model_app.command("train")
def train_model(
    data_dir: DataDirectory,
    dataset_report_dir: DatasetReportDirectory,
    allow_controlled_demo: Annotated[
        bool,
        typer.Option(
            "--allow-controlled-demo",
            help="Explicitly permit pipeline-only metrics from the synthetic controlled demo.",
        ),
    ] = False,
    config: ConfigPath = None,
) -> None:
    """Tune candidates and freeze validation selection without reading frozen test rows."""

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
                "pipeline_verification_only": result.pipeline_verification_only,
                "status": "selection_frozen",
                "test_data_accessed": False,
            },
            indent=2,
            sort_keys=True,
        )
    )


@model_app.command("test")
def test_model(
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
    """Run the explicit one-time frozen test and finalize the secure model bundle."""

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
                "status": "frozen_test_evaluated_once",
                "test_affected_selection": False,
                "metrics": result.report.metrics.model_dump(mode="json"),
            },
            indent=2,
            sort_keys=True,
        )
    )


@model_app.command("list")
def list_models(config: ConfigPath = None) -> None:
    """List validated supervised bundles from configured local storage."""

    try:
        models = _service(config).list_models()
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    payload = [
        {
            "model_id": model.model_id,
            "model_version": model.model_version,
            "algorithm": model.algorithm,
            "status": model.status,
            "pipeline_verification_only": model.pipeline_verification_only,
        }
        for model in models
    ]
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


@model_app.command("describe")
def describe_model(model_version: str, config: ConfigPath = None) -> None:
    """Show one bundle manifest without loading its estimator."""

    try:
        payload = _service(config).describe(model_version)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(payload)


@model_app.command("verify")
def verify_model(model_version: str, config: ConfigPath = None) -> None:
    """Verify path, manifest, checksum, type inventory, and inference components."""

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
            },
            sort_keys=True,
        )
    )


@model_app.command("predict")
def predict_model(
    model_version: str,
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=True, dir_okay=False, readable=True),
    ],
    config: ConfigPath = None,
) -> None:
    """Predict one strict canonical feature batch; never create alerts or risk scores."""

    try:
        batch = PredictionBatch.model_validate_json(input_path.read_text(encoding="utf-8"))
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
