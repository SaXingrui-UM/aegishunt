"""Typer anomaly command boundary tests."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from aegishunt.cli import app
from aegishunt.datasets.io import read_canonical_jsonl
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch
from tests.fixtures.anomaly import ANOMALY_CONFIG_PATH
from tests.fixtures.supervised import build_phase4_bundle

runner = CliRunner()


def _application_config(tmp_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    path.write_text(
        "\n".join(
            (
                "anomaly:",
                f"  training_config_path: {ANOMALY_CONFIG_PATH}",
                f"  artifact_root: {tmp_path / 'models'}",
                f"  reports_root: {tmp_path / 'experiments'}",
            )
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_anomaly_help_lists_explicit_commands_without_phase7_output() -> None:
    result = runner.invoke(app, ["anomaly", "--help"])

    assert result.exit_code == 0
    assert all(
        command in result.stdout
        for command in ("train", "test", "list", "describe", "predict", "verify")
    )
    assert "fusion" in result.stdout
    assert "alert" in result.stdout
    assert "combined-risk" not in result.stdout


def test_anomaly_cli_train_test_verify_and_predict_offline(tmp_path: Path) -> None:
    data_root, dataset_report_root = build_phase4_bundle(tmp_path)
    config = _application_config(tmp_path)
    common = [
        "--data-dir",
        str(data_root),
        "--dataset-report-dir",
        str(dataset_report_root),
        "--allow-controlled-demo",
        "--config",
        str(config),
    ]
    training = runner.invoke(app, ["anomaly", "train", *common])
    frozen = runner.invoke(app, ["anomaly", "test", *common])
    listing = runner.invoke(app, ["anomaly", "list", "--config", str(config)])
    verification = runner.invoke(
        app, ["anomaly", "verify", "1.0.0", "--config", str(config)]
    )

    assert training.exit_code == 0
    assert json.loads(training.stdout)["test_data_accessed"] is False
    assert frozen.exit_code == 0
    assert json.loads(frozen.stdout)["test_affected_selection"] is False
    assert json.loads(listing.stdout)[0]["algorithm"] == "isolation_forest"
    assert json.loads(verification.stdout)["status"] == "verified"
    assert "not probability" in verification.stdout

    row = read_canonical_jsonl(data_root / "test.jsonl")[0]
    batch = AnomalyPredictionBatch(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=feature_names(),
        dtype="float64",
        rows=(row.features.values,),
    )
    input_path = tmp_path / "prediction.json"
    input_path.write_text(batch.model_dump_json(), encoding="utf-8")
    prediction = runner.invoke(
        app,
        [
            "anomaly",
            "predict",
            "1.0.0",
            "--input",
            str(input_path),
            "--config",
            str(config),
        ],
    )
    payload = json.loads(prediction.stdout)[0]
    assert prediction.exit_code == 0
    assert "normalized_anomaly_score" in payload
    assert "is_anomaly" in payload
    assert not any(key in payload for key in ("probability", "alert", "risk", "severity"))


def test_anomaly_cli_fails_safely_without_controlled_permission(tmp_path: Path) -> None:
    data_root, dataset_report_root = build_phase4_bundle(tmp_path)
    config = _application_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "anomaly",
            "train",
            "--data-dir",
            str(data_root),
            "--dataset-report-dir",
            str(dataset_report_root),
            "--config",
            str(config),
        ],
    )

    assert result.exit_code == 1
    assert "explicit pipeline-verification permission" in result.output
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output
