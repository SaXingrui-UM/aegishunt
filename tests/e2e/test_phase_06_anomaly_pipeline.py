"""Offline Phase 6 benign-fit through independent bundle reload."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from math import isfinite
from pathlib import Path

from aegishunt.datasets.io import read_canonical_jsonl, sha256_file
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.anomaly.bundle import load_bundle
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch
from tests.fixtures.anomaly import (
    anomaly_lof_candidate_service,
    anomaly_service,
    predefined_sample_anomaly,
)

PROJECT_ROOT = Path(__file__).parents[2]


def test_offline_anomaly_e2e_freezes_reloads_and_scores_identically(tmp_path: Path) -> None:
    service, data_root, _, model_root, experiment_root = anomaly_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    experiment = experiment_root / training.experiment_id
    selection_path = experiment / "anomaly_model_selection.json"
    selection_checksum = sha256_file(selection_path)
    frozen = service.evaluate_test(allow_controlled_demo=True)

    assert sha256_file(selection_path) == selection_checksum
    assert frozen.report.test_affected_selection is False
    assert frozen.report.pipeline_verification_only is True
    assert frozen.report.row_count == 10
    assert frozen.report.group_count == 5
    assert set(frozen.report.class_distribution) == {"0", "1"}

    row = read_canonical_jsonl(data_root / "test.jsonl")[0]
    batch = AnomalyPredictionBatch(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=feature_names(),
        dtype="float64",
        rows=(row.features.values, predefined_sample_anomaly()),
    )
    expected = service.predict("1.0.0", batch)
    loaded = load_bundle(model_root / "1.0.0", artifact_root=model_root)
    assert loaded.manifest.hyperparameters == training.selection.hyperparameters
    assert loaded.manifest.anomaly_threshold == training.selection.threshold
    batch_path = tmp_path / "batch.json"
    batch_path.write_text(batch.model_dump_json(), encoding="utf-8")
    script = """
import json
from pathlib import Path
import sys
from aegishunt.ml.anomaly.bundle import load_bundle
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
root = Path(sys.argv[1])
batch = AnomalyPredictionBatch.model_validate_json(Path(sys.argv[2]).read_text())
result = score_batch(load_bundle(root / '1.0.0', artifact_root=root), batch)
print(json.dumps([item.model_dump(mode='json') for item in result], sort_keys=True))
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_root), str(batch_path)],
        cwd=PROJECT_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    reloaded = json.loads(completed.stdout)

    assert len(reloaded) == 2
    for actual, local in zip(reloaded, expected, strict=True):
        assert actual["raw_model_score"] == local.raw_model_score
        assert actual["canonical_anomaly_score"] == local.canonical_anomaly_score
        assert actual["normalized_anomaly_score"] == local.normalized_anomaly_score
        assert actual["is_anomaly"] == local.is_anomaly
        assert not any(
            key in actual
            for key in (
                "probability",
                "alert",
                "risk",
                "severity",
                "fusion_score",
                "hypothesis",
            )
        )
    smoke = reloaded[1]
    assert isfinite(smoke["raw_model_score"])
    assert isfinite(smoke["canonical_anomaly_score"])
    assert isfinite(smoke["normalized_anomaly_score"])
    assert smoke["canonical_anomaly_score"] == -smoke["raw_model_score"]
    assert 0.0 <= smoke["normalized_anomaly_score"] <= 1.0
    assert smoke["selected_threshold"] == training.selection.threshold
    assert smoke["is_anomaly"] is (
        smoke["normalized_anomaly_score"] >= smoke["selected_threshold"]
    )
    assert {path.name for path in (model_root / "1.0.0").iterdir()} == {
        "model.skops",
        "manifest.json",
        "checksums.json",
        "model_card.md",
    }
    assert {
        "anomaly_frozen_test_metrics.json",
        "anomaly_confusion_matrix.csv",
        "anomaly_classification_report.json",
        "anomaly_bundle_manifest.json",
        "model_card.md",
    } <= {path.name for path in experiment.iterdir()}


def test_direction_b_lof_candidate_reloads_in_an_independent_process(
    tmp_path: Path,
) -> None:
    service, _, _, model_root, _ = anomaly_lof_candidate_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    assert training.selected_algorithm == "local_outlier_factor"
    assert training.candidate_smoke_passed is True

    batch = AnomalyPredictionBatch(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=feature_names(),
        dtype="float64",
        rows=(predefined_sample_anomaly(),),
    )
    expected = service.predict("1.1.0-candidate", batch)[0]
    batch_path = tmp_path / "lof-batch.json"
    batch_path.write_text(batch.model_dump_json(), encoding="utf-8")
    script = """
import json
from pathlib import Path
import sys
from aegishunt.ml.anomaly.bundle import load_bundle
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
root = Path(sys.argv[1])
batch = AnomalyPredictionBatch.model_validate_json(Path(sys.argv[2]).read_text())
loaded = load_bundle(root / '1.1.0-candidate', artifact_root=root)
result = score_batch(loaded, batch)[0]
print(json.dumps({
    'algorithm': loaded.manifest.algorithm,
    'novelty': loaded.estimator.named_steps['model'].novelty,
    'prediction': result.model_dump(mode='json'),
}, sort_keys=True))
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")
    completed = subprocess.run(
        [sys.executable, "-c", script, str(model_root), str(batch_path)],
        cwd=PROJECT_ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )
    actual = json.loads(completed.stdout)

    assert actual["algorithm"] == "local_outlier_factor"
    assert actual["novelty"] is True
    prediction = actual["prediction"]
    assert prediction["raw_model_score"] == expected.raw_model_score
    assert prediction["canonical_anomaly_score"] == expected.canonical_anomaly_score
    assert prediction["normalized_anomaly_score"] == expected.normalized_anomaly_score
    assert prediction["selected_threshold"] == expected.selected_threshold
    assert prediction["is_anomaly"] is True
