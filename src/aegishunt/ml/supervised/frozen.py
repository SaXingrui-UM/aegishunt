"""One-way frozen-test evaluation after validation selection is immutable."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np
from sklearn.pipeline import Pipeline

from aegishunt.ml.supervised.bootstrap import group_bootstrap_intervals
from aegishunt.ml.supervised.calibration import ProbabilityCalibrator
from aegishunt.ml.supervised.candidates import raw_positive_scores
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import FrozenTestReport, ModelSelectionRecord
from aegishunt.ml.supervised.data import PartitionData
from aegishunt.ml.supervised.metrics import evaluate_binary_classification


def evaluate_frozen_test(
    estimator: Pipeline,
    calibrator: ProbabilityCalibrator,
    selection: ModelSelectionRecord,
    test: PartitionData,
    config: SupervisedTrainingConfig,
    *,
    selection_record_checksum: str,
) -> FrozenTestReport:
    """Evaluate exactly the frozen model, calibration, and threshold contract."""

    raw_scores = raw_positive_scores(estimator, test.features)
    probabilities = calibrator.transform(raw_scores)
    predictions = (probabilities >= selection.threshold).astype(np.int64)
    metrics = evaluate_binary_classification(test.labels, predictions, probabilities)
    intervals = group_bootstrap_intervals(
        test.labels,
        predictions,
        probabilities,
        test.groups,
        iterations=config.bootstrap_iterations,
        random_seed=config.random_seed,
    )
    return FrozenTestReport(
        report_schema_version="1.0.0",
        experiment_id=selection.experiment_id,
        model_id=selection.model_id,
        model_version=selection.model_version,
        selection_record_checksum=selection_record_checksum,
        evaluation_count=1,
        metrics=metrics,
        confidence_intervals=intervals,
        row_count=len(test.rows),
        group_count=len(set(test.groups.tolist())),
        class_distribution=test.class_distribution,
        test_affected_selection=False,
        pipeline_verification_only=selection.pipeline_verification_only,
        evaluated_at=datetime.now(UTC),
    )
