"""One-way frozen anomaly evaluation after selection is immutable."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
from sklearn.pipeline import Pipeline

from aegishunt.ml.anomaly.bootstrap import group_bootstrap_intervals
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import (
    AnomalyFrozenTestReport,
    AnomalySelectionRecord,
)
from aegishunt.ml.anomaly.metrics import evaluate_anomaly_metrics, summarize_scores
from aegishunt.ml.anomaly.normalization import normalize_scores
from aegishunt.ml.anomaly.scoring import score_pipeline
from aegishunt.ml.supervised.data import PartitionData


def evaluate_frozen_test(
    estimator: Pipeline,
    selection: AnomalySelectionRecord,
    test: PartitionData,
    config: AnomalyTrainingConfig,
    *,
    selection_record_checksum: str,
) -> AnomalyFrozenTestReport:
    raw, canonical = score_pipeline(estimator, test.features)
    normalized = normalize_scores(canonical, selection.normalizer)
    predictions = (normalized >= selection.threshold).astype(np.int64)
    metrics = evaluate_anomaly_metrics(test.labels, predictions, normalized)
    intervals = group_bootstrap_intervals(
        test.labels,
        predictions,
        normalized,
        test.groups,
        iterations=config.bootstrap_iterations,
        random_seed=config.random_seed,
    )
    benign = test.labels == 0
    anomaly = test.labels == 1
    return AnomalyFrozenTestReport(
        report_schema_version="1.0.0",
        experiment_id=selection.experiment_id,
        model_id=selection.model_id,
        model_version=selection.model_version,
        selection_record_checksum=selection_record_checksum,
        evaluation_count=1,
        metrics=metrics,
        confidence_intervals=intervals,
        benign_raw_distribution=summarize_scores(raw[benign]),
        anomaly_raw_distribution=summarize_scores(raw[anomaly]),
        benign_normalized_distribution=summarize_scores(normalized[benign]),
        anomaly_normalized_distribution=summarize_scores(normalized[anomaly]),
        row_count=len(test.rows),
        group_count=len(set(test.groups.tolist())),
        class_distribution=test.class_distribution,
        test_affected_selection=False,
        pipeline_verification_only=selection.pipeline_verification_only,
        evaluated_at=datetime.now(UTC),
    )
