"""Offline Phase 4-to-supervised-bundle E2E with frozen-test isolation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aegishunt.ml.supervised.bundle import load_bundle
from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.errors import ArtifactError, PredictionError
from aegishunt.ml.supervised.prediction import PredictionBatch
from aegishunt.ml.supervised.service import SupervisedTrainingService
from tests.fixtures.supervised import TRAINING_CONFIG_PATH, build_phase4_bundle


def _service(root: Path) -> tuple[SupervisedTrainingService, Path, Path, Path, Path]:
    data_root, dataset_reports = build_phase4_bundle(root / "phase4")
    model_root = root / "models"
    experiment_root = root / "experiments"
    service = SupervisedTrainingService(
        data_root=data_root,
        dataset_report_root=dataset_reports,
        training_config_path=TRAINING_CONFIG_PATH,
        artifact_root=model_root,
        reports_root=experiment_root,
    )
    return service, data_root, dataset_reports, model_root, experiment_root


def test_phase_05_selection_test_bundle_and_independent_reload(tmp_path: Path) -> None:
    service, data_root, dataset_reports, model_root, experiment_root = _service(tmp_path)

    training = service.train(allow_controlled_demo=True)
    experiment_dir = experiment_root / training.experiment_id

    assert training.pipeline_verification_only is True
    assert training.selection.test_data_accessed is False
    assert not (experiment_dir / "frozen_test_metrics.json").exists()
    comparison = (experiment_dir / "model_comparison.csv").read_text(encoding="utf-8")
    assert all(
        algorithm in comparison
        for algorithm in (
            "dummy",
            "logistic_regression",
            "decision_tree",
            "random_forest",
            "hist_gradient_boosting",
        )
    )

    frozen = service.evaluate_test(allow_controlled_demo=True)
    manifest = service.verify(training.model_version)
    validation = SupervisedDatasetGate(
        data_root,
        dataset_reports,
    ).load_training_validation(cv_folds=3).validation
    batch = PredictionBatch(
        feature_schema_version=training.selection.feature_schema_version,
        feature_names=training.selection.feature_names,
        dtype="float64",
        rows=(tuple(validation.features[0]), tuple(validation.features[1])),
    )
    first = service.predict(training.model_version, batch)
    second = service.predict(training.model_version, batch)

    assert frozen.report.evaluation_count == 1
    assert frozen.report.test_affected_selection is False
    assert frozen.report.pipeline_verification_only is True
    assert len(frozen.report.confidence_intervals) >= 11
    assert manifest.frozen_test_metrics == frozen.report.metrics
    assert [
        result.model_dump(exclude={"prediction_timestamp"}) for result in first
    ] == [result.model_dump(exclude={"prediction_timestamp"}) for result in second]
    assert all(0.0 <= result.calibrated_probability <= 1.0 for result in first)
    assert all(result.selected_threshold == training.selection.threshold for result in first)
    assert "PIPELINE VERIFICATION ONLY" in (experiment_dir / "model_card.md").read_text(
        encoding="utf-8"
    )
    with pytest.raises(ArtifactError, match="already exists"):
        service.evaluate_test(allow_controlled_demo=True)

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
    code = (
        "from pathlib import Path; "
        "from aegishunt.ml.supervised.bundle import load_bundle; "
        f"m=load_bundle(Path({str(model_root / training.model_version)!r}), "
        f"artifact_root=Path({str(model_root)!r})); "
        "print(m.manifest.model_id)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", code],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == training.model_id

    incompatible = batch.model_copy(update={"feature_schema_version": "incompatible"})
    with pytest.raises(PredictionError, match="schema version"):
        service.predict(training.model_version, incompatible)

    corrupt = model_root / "corrupt"
    shutil.copytree(model_root / training.model_version, corrupt)
    artifact = corrupt / "model.skops"
    artifact.write_bytes(artifact.read_bytes() + b"corrupt")
    with pytest.raises(ArtifactError, match="checksum"):
        load_bundle(corrupt, artifact_root=model_root)

    arbitrary = model_root / "arbitrary.pkl"
    arbitrary.write_bytes(b"not a model")
    with pytest.raises(ArtifactError, match="system-generated directory"):
        load_bundle(arbitrary, artifact_root=model_root)
    with pytest.raises(ArtifactError, match="outside configured storage"):
        load_bundle(tmp_path / "outside", artifact_root=model_root)

    report = json.loads((experiment_dir / "frozen_test_metrics.json").read_text())
    assert report["evaluation_count"] == 1
    assert report["test_affected_selection"] is False
