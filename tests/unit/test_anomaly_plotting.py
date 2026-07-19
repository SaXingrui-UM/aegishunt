"""Validation-only anomaly plot generation tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pytest

from aegishunt.ml.anomaly.artifacts import AnomalyExperimentStore
from aegishunt.ml.anomaly.errors import AnomalyArtifactError
from aegishunt.ml.anomaly.plotting import write_validation_plots
from aegishunt.ml.anomaly.thresholding import evaluate_thresholds

DATASET_SHA = "1" * 64
SPLIT_SHA = "2" * 64


def _evidence() -> tuple[
    np.ndarray[tuple[int], np.dtype[np.int64]],
    np.ndarray[tuple[int], np.dtype[np.float64]],
    np.ndarray[tuple[int], np.dtype[np.float64]],
]:
    return (
        np.asarray([0, 0, 1, 1], dtype=np.int64),
        np.asarray([-0.30, -0.25, -0.45, -0.50], dtype=np.float64),
        np.asarray([0.1, 0.4, 0.8, 0.9], dtype=np.float64),
    )


def _write(store: AnomalyExperimentStore, *, selected_threshold: float) -> dict[str, object]:
    labels, raw, normalized = _evidence()
    thresholds = evaluate_thresholds(
        labels,
        normalized,
        np.asarray(["b1", "b2", "a1", "a2"], dtype=np.str_),
        candidates=(0.5, 0.8),
        false_positive_rate_limit=0.25,
    )
    return write_validation_plots(
        store,
        experiment_id="phase-06-plot-test",
        feature_schema_version="1.0.0",
        selected_threshold=selected_threshold,
        selected_candidate_id="iforest-test",
        dataset_manifest_checksum=DATASET_SHA,
        split_manifest_checksum=SPLIT_SHA,
        false_positive_rate_limit=0.25,
        labels=labels,
        raw_scores=raw,
        normalized_scores=normalized,
        threshold_results=thresholds,
    )


def test_validation_plot_generation_writes_safe_real_pngs_and_checksums(
    tmp_path: Path,
) -> None:
    first_store = AnomalyExperimentStore.create(tmp_path / "reports", "first")
    first = _write(first_store, selected_threshold=0.5)
    second_store = AnomalyExperimentStore.create(tmp_path / "reports", "second")
    second = _write(second_store, selected_threshold=0.8)

    expected = {
        "raw_score_distribution.png",
        "normalized_score_distribution.png",
        "threshold_sensitivity.png",
        "benign_fpr_vs_threshold.png",
        "anomaly_utility_vs_threshold.png",
    }
    assert first["selected_threshold"] == 0.5
    assert first["frozen_test_accessed"] is False
    assert first["dataset_manifest_checksum"] == DATASET_SHA
    assert first["split_manifest_checksum"] == SPLIT_SHA
    assert first["selected_candidate_id"] == "iforest-test"
    artifacts = first["artifacts"]
    assert isinstance(artifacts, list)
    assert {item["filename"] for item in artifacts} == expected
    for item in artifacts:
        path = first_store.path(item["filename"])
        assert path.resolve().is_relative_to(first_store.directory.resolve())
        assert path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]

    first_threshold_sha = next(
        item["sha256"] for item in artifacts if item["filename"] == "threshold_sensitivity.png"
    )
    second_artifacts = second["artifacts"]
    assert isinstance(second_artifacts, list)
    second_threshold_sha = next(
        item["sha256"]
        for item in second_artifacts
        if item["filename"] == "threshold_sensitivity.png"
    )
    assert first_threshold_sha != second_threshold_sha


def test_validation_plot_generation_rejects_empty_scores(tmp_path: Path) -> None:
    store = AnomalyExperimentStore.create(tmp_path, "empty")
    with pytest.raises(AnomalyArtifactError, match="aligned"):
        write_validation_plots(
            store,
            experiment_id="phase-06-plot-test",
            feature_schema_version="1.0.0",
            selected_threshold=0.5,
            selected_candidate_id="iforest-test",
            dataset_manifest_checksum=DATASET_SHA,
            split_manifest_checksum=SPLIT_SHA,
            false_positive_rate_limit=0.25,
            labels=np.asarray([], dtype=np.int64),
            raw_scores=np.asarray([], dtype=np.float64),
            normalized_scores=np.asarray([], dtype=np.float64),
            threshold_results=(),
        )


@pytest.mark.parametrize("score_type", ("raw", "normalized"))
def test_validation_plot_generation_rejects_nonfinite_scores(
    tmp_path: Path,
    score_type: str,
) -> None:
    store = AnomalyExperimentStore.create(tmp_path, score_type)
    labels, raw, normalized = _evidence()
    if score_type == "raw":
        raw[0] = np.nan
    else:
        normalized[0] = np.inf

    with pytest.raises(AnomalyArtifactError, match="finite"):
        write_validation_plots(
            store,
            experiment_id="phase-06-plot-test",
            feature_schema_version="1.0.0",
            selected_threshold=0.5,
            selected_candidate_id="iforest-test",
            dataset_manifest_checksum=DATASET_SHA,
            split_manifest_checksum=SPLIT_SHA,
            false_positive_rate_limit=0.25,
            labels=labels,
            raw_scores=raw,
            normalized_scores=normalized,
            threshold_results=(),
        )
