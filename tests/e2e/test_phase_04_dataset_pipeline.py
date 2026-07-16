"""CLI-driven Phase 4 controlled dataset pipeline with no network or root requirement."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from aegishunt import cli
from aegishunt.datasets.conversion import METADATA_COLUMNS
from aegishunt.datasets.io import read_canonical_jsonl
from aegishunt.flows.registry import feature_names

runner = CliRunner()


def test_dataset_cli_help_registry_and_manual_download_boundary(tmp_path: Path) -> None:
    help_result = runner.invoke(cli.app, ["dataset", "--help"])
    list_result = runner.invoke(cli.app, ["dataset", "list"])
    describe_result = runner.invoke(
        cli.app,
        ["dataset", "describe", "cse-cic-ids2018"],
    )
    download_result = runner.invoke(
        cli.app,
        ["dataset", "download", "cse-cic-ids2018"],
    )

    assert help_result.exit_code == 0
    assert all(
        command in help_result.stdout
        for command in (
            "list",
            "describe",
            "download",
            "validate",
            "convert",
            "build-demo",
            "quality",
            "split",
            "manifest",
        )
    )
    assert list_result.exit_code == 0
    assert "aegishunt-controlled-demo" in list_result.stdout
    assert describe_result.exit_code == 0
    assert '"download_status": "manual_required"' in describe_result.stdout
    assert download_result.exit_code == 1
    assert "manual acquisition" in download_result.output
    assert str(tmp_path) not in download_result.output
    assert "Traceback" not in download_result.output


def test_dataset_cli_build_validate_quality_manifest_and_resplit(tmp_path: Path) -> None:
    data = tmp_path / "data"
    reports = tmp_path / "reports"
    build = runner.invoke(
        cli.app,
        [
            "dataset",
            "build-demo",
            "--data-dir",
            str(data),
            "--report-dir",
            str(reports),
            "--seed",
            "4204",
        ],
    )

    assert build.exit_code == 0, build.output
    build_payload = json.loads(build.stdout)
    assert build_payload == {
        "dataset_id": "aegishunt-controlled-demo",
        "frozen_test": True,
        "groups": 24,
        "leakage_status": "pass",
        "quality_status": "pass",
        "rows": 48,
    }
    assert str(tmp_path) not in build.stdout

    canonical = data / "canonical.jsonl"
    validate = runner.invoke(cli.app, ["dataset", "validate", str(canonical)])
    quality = runner.invoke(cli.app, ["dataset", "quality", str(canonical)])
    manifest = runner.invoke(
        cli.app,
        ["dataset", "manifest", str(reports / "dataset_manifest.json")],
    )
    resplit = runner.invoke(
        cli.app,
        [
            "dataset",
            "split",
            str(canonical),
            "--data-dir",
            str(tmp_path / "resplit-data"),
            "--report-dir",
            str(tmp_path / "resplit-reports"),
            "--seed",
            "4205",
        ],
    )

    assert validate.exit_code == 0
    assert json.loads(validate.stdout) == {"rows": 48, "status": "valid"}
    assert quality.exit_code == 0
    assert json.loads(quality.stdout)["status"] == "pass"
    assert manifest.exit_code == 0
    assert json.loads(manifest.stdout)["dataset_id"] == "aegishunt-controlled-demo"
    assert resplit.exit_code == 0, resplit.output
    assert json.loads(resplit.stdout)["leakage_status"] == "pass"


def test_dataset_cli_rejects_unknown_dataset_without_traceback() -> None:
    result = runner.invoke(cli.app, ["dataset", "describe", "missing-dataset"])

    assert result.exit_code == 1
    assert "not registered" in result.output
    assert "Traceback" not in result.output


def test_dataset_cli_converts_exact_phase3_feature_csv(tmp_path: Path) -> None:
    data = tmp_path / "demo-data"
    reports = tmp_path / "demo-reports"
    build = runner.invoke(
        cli.app,
        [
            "dataset",
            "build-demo",
            "--data-dir",
            str(data),
            "--report-dir",
            str(reports),
        ],
    )
    assert build.exit_code == 0
    row = read_canonical_jsonl(data / "canonical.jsonl")[0]
    raw = tmp_path / "raw.csv"
    header = (*METADATA_COLUMNS, *feature_names())
    payload = {
        "record_id": "converted-1",
        "capture_session_id": "capture-convert",
        "scenario_id": "scenario-convert",
        "group_id": "group-convert",
        "original_row_id": "1",
        "observed_at": row.metadata.observed_at.isoformat()
        if row.metadata.observed_at is not None
        else "",
        "original_label": "normal",
        **{
            name: row.features.values[index]
            for index, name in enumerate(feature_names())
        },
    }
    with raw.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        writer.writerow(payload)
    output = tmp_path / "converted.jsonl"

    result = runner.invoke(
        cli.app,
        [
            "dataset",
            "convert",
            "aegishunt-controlled-demo",
            str(raw),
            "--output",
            str(output),
            "--access-date",
            "2026-01-01",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["rows"] == 1
    assert read_canonical_jsonl(output)[0].labels.original_label == "normal"
