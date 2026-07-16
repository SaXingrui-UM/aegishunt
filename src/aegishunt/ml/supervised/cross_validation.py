"""Deterministic train-only GroupKFold evidence and bounded tuning."""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from sklearn.model_selection import GroupKFold
from sklearn.pipeline import Pipeline

from aegishunt.ml.supervised.candidates import build_candidate, raw_positive_scores
from aegishunt.ml.supervised.config import CandidateConfig, SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import (
    FoldEvidence,
    FoldResult,
    HyperparameterResult,
)
from aegishunt.ml.supervised.data import PartitionData
from aegishunt.ml.supervised.errors import TrainingError
from aegishunt.ml.supervised.metrics import evaluate_binary_classification, metric_summary


@dataclass(frozen=True, slots=True)
class FoldIndices:
    train: NDArray[np.int64]
    validation: NDArray[np.int64]
    evidence: FoldEvidence


def _stable_row_order(partition: PartitionData, seed: int) -> NDArray[np.int64]:
    order = np.asarray(
        sorted(
            range(len(partition.rows)),
            key=lambda index: (
                hashlib.sha256(
                    f"{seed}:{partition.rows[index].metadata.group_id}".encode()
                ).hexdigest(),
                partition.rows[index].metadata.record_id,
            ),
        ),
        dtype=np.int64,
    )
    return order


def _values(
    partition: PartitionData,
    indices: NDArray[np.int64],
    attribute: str,
) -> set[str]:
    return {str(getattr(partition.rows[int(index)].metadata, attribute)) for index in indices}


def build_group_folds(
    partition: PartitionData,
    *,
    fold_count: int,
    random_seed: int,
) -> tuple[FoldIndices, ...]:
    """Create deterministic folds and refuse any identifier or class leakage."""

    if len(set(partition.groups.tolist())) < fold_count:
        raise TrainingError("training groups are insufficient for GroupKFold")
    order = _stable_row_order(partition, random_seed)
    features = partition.features[order]
    labels = partition.labels[order]
    groups = partition.groups[order]
    splitter = GroupKFold(n_splits=fold_count)
    folds: list[FoldIndices] = []
    for fold_index, (train_ordered, validation_ordered) in enumerate(
        splitter.split(features, labels, groups)
    ):
        train_indices = order[train_ordered]
        validation_indices = order[validation_ordered]
        train_groups = _values(partition, train_indices, "group_id")
        validation_groups = _values(partition, validation_indices, "group_id")
        overlaps = {
            attribute: _values(partition, train_indices, attribute)
            & _values(partition, validation_indices, attribute)
            for attribute in (
                "group_id",
                "source_file",
                "capture_session_id",
                "scenario_id",
            )
        }
        if any(overlaps.values()):
            raise TrainingError("GroupKFold produced identifier overlap")
        train_distribution = Counter(str(value) for value in partition.labels[train_indices])
        validation_distribution = Counter(
            str(value) for value in partition.labels[validation_indices]
        )
        if set(train_distribution) != {"0", "1"} or set(validation_distribution) != {"0", "1"}:
            raise TrainingError("GroupKFold produced a single-class fold")
        evidence = FoldEvidence(
            fold_index=fold_index,
            train_groups=tuple(sorted(train_groups)),
            validation_groups=tuple(sorted(validation_groups)),
            train_rows=len(train_indices),
            validation_rows=len(validation_indices),
            train_class_distribution=dict(sorted(train_distribution.items())),
            validation_class_distribution=dict(sorted(validation_distribution.items())),
            group_overlap=tuple(sorted(overlaps["group_id"])),
            source_overlap=tuple(sorted(overlaps["source_file"])),
            session_overlap=tuple(sorted(overlaps["capture_session_id"])),
            scenario_overlap=tuple(sorted(overlaps["scenario_id"])),
        )
        folds.append(FoldIndices(train_indices, validation_indices, evidence))
    return tuple(folds)


def tune_candidate(
    candidate: CandidateConfig,
    partition: PartitionData,
    config: SupervisedTrainingConfig,
) -> tuple[HyperparameterResult, tuple[HyperparameterResult, ...]]:
    """Evaluate every finite configuration on train-only group folds."""

    folds = build_group_folds(
        partition,
        fold_count=config.cv_folds,
        random_seed=config.random_seed,
    )
    results: list[HyperparameterResult] = []
    for parameters in candidate.combinations():
        started = time.perf_counter()
        fold_results: list[FoldResult] = []
        failure_code: str | None = None
        try:
            for fold in folds:
                estimator = build_candidate(
                    candidate.algorithm,
                    parameters,
                    random_seed=config.random_seed,
                )
                estimator.fit(
                    partition.features[fold.train],
                    partition.labels[fold.train],
                )
                probabilities = raw_positive_scores(
                    estimator,
                    partition.features[fold.validation],
                )
                metrics = evaluate_binary_classification(
                    partition.labels[fold.validation],
                    (probabilities >= 0.5).astype(np.int64),
                    probabilities,
                )
                fold_results.append(FoldResult(evidence=fold.evidence, metrics=metrics))
        except (ArithmeticError, FloatingPointError, TypeError, ValueError):
            failure_code = "candidate_fit_or_score_failed"
        duration = time.perf_counter() - started
        if failure_code is None:
            means, deviations = metric_summary([result.metrics for result in fold_results])
            result = HyperparameterResult(
                algorithm=candidate.algorithm,
                parameters=parameters,
                status="passed",
                folds=tuple(fold_results),
                mean_metrics=means,
                std_metrics=deviations,
                training_duration_seconds=duration,
            )
        else:
            result = HyperparameterResult(
                algorithm=candidate.algorithm,
                parameters=parameters,
                status="failed",
                failure_code=failure_code,
                training_duration_seconds=duration,
            )
        results.append(result)
    passed = [result for result in results if result.status == "passed"]
    if not passed:
        raise TrainingError("all hyperparameter candidates failed")

    def ranking(result: HyperparameterResult) -> tuple[float, float, float, float, str]:
        means = result.mean_metrics
        return (
            float(means["macro_f1"] or 0.0),
            float(means["pr_auc"] or 0.0),
            float(means["recall"] or 0.0),
            -float(means["false_positive_rate"] or 0.0),
            json.dumps(result.parameters, sort_keys=True),
        )

    return max(passed, key=ranking), tuple(results)


def fit_best_candidate(
    best: HyperparameterResult,
    partition: PartitionData,
    config: SupervisedTrainingConfig,
) -> tuple[Pipeline, float]:
    """Fit the selected hyperparameters on training data only."""

    estimator = build_candidate(
        best.algorithm,  # type: ignore[arg-type]
        best.parameters,
        random_seed=config.random_seed,
    )
    started = time.perf_counter()
    estimator.fit(partition.features, partition.labels)
    return estimator, time.perf_counter() - started
