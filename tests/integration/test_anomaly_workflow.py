"""Phase 4-to-Phase 6 integration boundaries."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegishunt.ml.anomaly.errors import AnomalyArtifactError, AnomalyDatasetError
from tests.fixtures.anomaly import anomaly_service


def test_training_freezes_selection_without_reading_frozen_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _, experiment_root = anomaly_service(tmp_path)
    from aegishunt.ml.supervised import data as supervised_data

    original = supervised_data.read_canonical_jsonl
    opened: list[str] = []

    def tracked(path: Path) -> tuple[object, ...]:
        opened.append(path.name)
        return original(path)  # type: ignore[return-value]

    monkeypatch.setattr(supervised_data, "read_canonical_jsonl", tracked)
    result = service.train(allow_controlled_demo=True)

    assert result.selection.test_data_accessed is False
    assert "test.jsonl" not in opened
    assert set(opened) == {"train.jsonl", "validation.jsonl"}
    frozen_report = experiment_root / result.experiment_id / "anomaly_frozen_test_metrics.json"
    assert not frozen_report.exists()
    assert result.selection.benign_training_rows == 10
    assert len(result.selection.benign_training_groups) == 5


def test_controlled_demo_requires_explicit_permission(tmp_path: Path) -> None:
    service, _, _, _, _ = anomaly_service(tmp_path)

    with pytest.raises(AnomalyDatasetError, match="explicit"):
        service.train()


def test_frozen_test_requires_selection_and_rejects_repeat(tmp_path: Path) -> None:
    service, _, _, _, _ = anomaly_service(tmp_path)

    with pytest.raises(AnomalyArtifactError, match="does not exist"):
        service.evaluate_test(allow_controlled_demo=True)
    training = service.train(allow_controlled_demo=True)
    frozen = service.evaluate_test(allow_controlled_demo=True)

    assert frozen.report.evaluation_count == 1
    assert frozen.report.test_affected_selection is False
    assert frozen.report.model_version == training.model_version
    with pytest.raises(AnomalyArtifactError, match="already exists"):
        service.evaluate_test(allow_controlled_demo=True)


def test_training_artifact_inventory_is_complete_and_has_no_test_metrics(tmp_path: Path) -> None:
    service, _, _, _, experiment_root = anomaly_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    directory = experiment_root / training.experiment_id

    expected = {
        "anomaly_training_config.json",
        "benign_training_manifest.json",
        "isolation_forest_candidates.json",
        "anomaly_hyperparameter_results.csv",
        "validation_anomaly_metrics.json",
        "score_normalization.json",
        "threshold_results.csv",
        "threshold_sensitivity.csv",
        "anomaly_model_comparison.csv",
        "lof_comparison.json",
        "one_class_svm_comparison.json",
        "score_distribution.csv",
        "latency_results.csv",
        "selection.skops",
        "anomaly_model_selection.json",
    }
    assert {path.name for path in directory.iterdir()} == expected
    assert not (directory / "anomaly_frozen_test_metrics.json").exists()
