"""Benign-only data, score direction, normalization, and metric contracts."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aegishunt.ml.anomaly.data import AnomalyDatasetGate
from aegishunt.ml.anomaly.errors import (
    AnomalyDatasetError,
    AnomalyEvaluationError,
    AnomalyTrainingError,
)
from aegishunt.ml.anomaly.metrics import evaluate_anomaly_metrics, summarize_scores
from aegishunt.ml.anomaly.normalization import fit_score_normalizer, normalize_scores
from aegishunt.ml.anomaly.scoring import canonical_anomaly_scores, score_pipeline
from tests.fixtures.supervised import build_phase4_bundle


def test_gate_extracts_only_training_benign_and_keeps_validation_labels(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    data = AnomalyDatasetGate(data_root, report_root).load_training_validation(
        minimum_benign_groups=3
    )

    assert len(data.benign_train.rows) == 10
    assert set(data.benign_train.labels.tolist()) == {0}
    assert len(set(data.benign_train.groups.tolist())) == 5
    assert len(data.validation.rows) == 10
    assert set(data.validation.labels.tolist()) == {0, 1}
    assert data.manifest.excluded_malicious_rows == 18
    assert data.manifest.metadata_used_as_features is False
    assert data.manifest.test_data_accessed is False


def test_gate_rejects_insufficient_benign_groups(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)

    with pytest.raises(AnomalyDatasetError, match="benign training groups"):
        AnomalyDatasetGate(data_root, report_root).load_training_validation(
            minimum_benign_groups=6
        )


def test_gate_rejects_dataset_checksum_tampering(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    with (data_root / "train.jsonl").open("ab") as destination:
        destination.write(b" ")

    with pytest.raises(AnomalyDatasetError, match="checksum"):
        AnomalyDatasetGate(data_root, report_root)


def test_canonical_score_reverses_sklearn_direction_and_orders_outlier() -> None:
    random = np.random.default_rng(61)
    normal = random.normal(0.0, 0.2, size=(40, 3)).astype(np.float64)
    estimator = Pipeline(
        (
            ("scale", StandardScaler()),
            ("model", IsolationForest(n_estimators=64, random_state=61, n_jobs=1)),
        )
    ).fit(normal)
    raw, canonical = score_pipeline(
        estimator,
        np.vstack((normal[:4], np.asarray([[8.0, 8.0, 8.0]], dtype=np.float64))),
    )

    assert np.array_equal(canonical, -raw)
    assert canonical[-1] > float(np.median(canonical[:-1]))
    assert np.isfinite(canonical).all()


@pytest.mark.parametrize(
    "scores",
    (
        np.asarray([], dtype=np.float64),
        np.asarray([np.nan], dtype=np.float64),
        np.asarray([np.inf], dtype=np.float64),
        np.asarray([-np.inf], dtype=np.float64),
    ),
)
def test_score_direction_rejects_empty_or_non_finite(scores: np.ndarray) -> None:
    with pytest.raises(AnomalyTrainingError):
        canonical_anomaly_scores(scores)


def test_quantile_normalizer_is_bounded_deterministic_and_clips_tails() -> None:
    reference = np.asarray([1.0, 2.0, 3.0, 4.0], dtype=np.float64)
    normalizer = fit_score_normalizer(reference, version="1.0.0", quantile_count=101)
    scores = np.asarray([-100.0, 1.0, 2.5, 4.0, 100.0], dtype=np.float64)

    first = normalize_scores(scores, normalizer)
    second = normalize_scores(scores, normalizer)

    assert np.array_equal(first, second)
    assert first.tolist() == [0.0, 0.0, 0.5, 1.0, 1.0]
    assert np.all((first >= 0.0) & (first <= 1.0))
    assert normalizer.reference_partition == "benign_training"


def test_constant_score_normalization_has_explicit_semantics() -> None:
    normalizer = fit_score_normalizer(
        np.asarray([2.0, 2.0, 2.0], dtype=np.float64),
        version="1.0.0",
        quantile_count=5,
    )

    assert normalize_scores(
        np.asarray([1.0, 2.0, 3.0], dtype=np.float64), normalizer
    ).tolist() == [0.0, 0.5, 1.0]


def test_metrics_record_one_class_and_zero_division_unavailability() -> None:
    metrics = evaluate_anomaly_metrics([0, 0], [0, 0], [0.1, 0.2])

    assert metrics.roc_auc is None
    assert metrics.pr_auc is None
    assert "precision" in metrics.unavailable_metrics
    assert "recall" in metrics.unavailable_metrics
    assert metrics.confusion_matrix == ((2, 0), (0, 0))


def test_metrics_reject_malformed_scores_and_summary_rejects_empty() -> None:
    with pytest.raises(AnomalyEvaluationError, match="within zero and one"):
        evaluate_anomaly_metrics([0, 1], [0, 1], [-0.1, 1.1])
    with pytest.raises(AnomalyEvaluationError, match="finite"):
        summarize_scores([])
