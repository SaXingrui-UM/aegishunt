"""Validation-only Isolation Forest selection and truthful offline comparison."""

from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from sklearn.pipeline import Pipeline

from aegishunt.ml.anomaly.bundle import estimator_bytes
from aegishunt.ml.anomaly.config import (
    AnomalyTrainingConfig,
    IsolationForestCandidateConfig,
)
from aegishunt.ml.anomaly.contracts import (
    ComparatorResult,
    IsolationForestCandidateResult,
    ScoreDistribution,
)
from aegishunt.ml.anomaly.data import AnomalyTrainingData
from aegishunt.ml.anomaly.errors import AnomalyEvaluationError, AnomalyTrainingError
from aegishunt.ml.anomaly.isolation_forest import (
    build_isolation_forest,
    isolation_parameters,
)
from aegishunt.ml.anomaly.lof import build_lof_comparator, lof_parameters
from aegishunt.ml.anomaly.metrics import summarize_scores
from aegishunt.ml.anomaly.normalization import fit_score_normalizer, normalize_scores
from aegishunt.ml.anomaly.operational import measure_operational_metrics
from aegishunt.ml.anomaly.scoring import score_pipeline
from aegishunt.ml.anomaly.thresholding import evaluate_thresholds, select_threshold


@dataclass(frozen=True, slots=True)
class FittedAnomalyCandidate:
    estimator: Pipeline
    result: IsolationForestCandidateResult
    model_payload: bytes


@dataclass(frozen=True, slots=True)
class CandidateEvaluationSet:
    fitted: tuple[FittedAnomalyCandidate, ...]
    results: tuple[IsolationForestCandidateResult, ...]


def _distribution_pair(
    values: NDArray[np.float64],
    labels: NDArray[np.int64],
) -> tuple[ScoreDistribution, ScoreDistribution]:
    return summarize_scores(values[labels == 0]), summarize_scores(values[labels == 1])


def _fit_candidate(
    candidate: IsolationForestCandidateConfig,
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> FittedAnomalyCandidate:
    estimator = build_isolation_forest(candidate, random_seed=config.random_seed)
    started = time.perf_counter()
    estimator.fit(data.benign_train.features)
    duration = time.perf_counter() - started
    _, training_canonical = score_pipeline(estimator, data.benign_train.features)
    normalizer = fit_score_normalizer(
        training_canonical,
        version=config.normalization_version,
        quantile_count=config.normalization_quantiles,
    )
    validation_raw, validation_canonical = score_pipeline(estimator, data.validation.features)
    validation_normalized = normalize_scores(validation_canonical, normalizer)
    threshold_results = evaluate_thresholds(
        data.validation.labels,
        validation_normalized,
        data.validation.groups,
        candidates=config.threshold_candidates,
        false_positive_rate_limit=config.false_positive_rate_limit,
    )
    selected = select_threshold(threshold_results)
    raw_benign, raw_anomaly = _distribution_pair(validation_raw, data.validation.labels)
    normalized_benign, normalized_anomaly = _distribution_pair(
        validation_normalized, data.validation.labels
    )
    operational = measure_operational_metrics(
        estimator,
        normalizer,
        data.validation.features,
        training_duration_seconds=duration,
        repetitions=config.latency_repetitions,
    )
    result = IsolationForestCandidateResult(
        candidate_id=candidate.candidate_id,
        algorithm="isolation_forest",
        hyperparameters=isolation_parameters(candidate),
        status="passed",
        benign_training_rows=len(data.benign_train.rows),
        benign_training_groups=len(set(data.benign_train.groups.tolist())),
        validation_rows=len(data.validation.rows),
        validation_groups=len(set(data.validation.groups.tolist())),
        selected_threshold=selected.threshold,
        threshold_results=threshold_results,
        validation_metrics=selected.metrics,
        normalizer=normalizer,
        benign_raw_distribution=raw_benign,
        anomaly_raw_distribution=raw_anomaly,
        benign_normalized_distribution=normalized_benign,
        anomaly_normalized_distribution=normalized_anomaly,
        operational_metrics=operational,
    )
    return FittedAnomalyCandidate(estimator, result, estimator_bytes(estimator))


def evaluate_isolation_forest_candidates(
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> CandidateEvaluationSet:
    fitted: list[FittedAnomalyCandidate] = []
    results: list[IsolationForestCandidateResult] = []
    for candidate in config.isolation_forest_candidates:
        try:
            completed = _fit_candidate(candidate, data, config)
            fitted.append(completed)
            results.append(completed.result)
        except (AnomalyEvaluationError, AnomalyTrainingError, ValueError) as exc:
            results.append(
                IsolationForestCandidateResult(
                    candidate_id=candidate.candidate_id,
                    algorithm="isolation_forest",
                    hyperparameters=isolation_parameters(candidate),
                    status="failed",
                    failure_code=type(exc).__name__,
                    benign_training_rows=len(data.benign_train.rows),
                    benign_training_groups=len(set(data.benign_train.groups.tolist())),
                    validation_rows=len(data.validation.rows),
                    validation_groups=len(set(data.validation.groups.tolist())),
                )
            )
    if not fitted:
        detail = ",".join(
            f"{item.candidate_id}:{item.failure_code}" for item in results
        ) or "no candidates configured"
        raise AnomalyTrainingError(f"all Isolation Forest candidates failed: {detail}")
    return CandidateEvaluationSet(tuple(fitted), tuple(results))


def select_production_candidate(
    candidates: tuple[FittedAnomalyCandidate, ...],
) -> FittedAnomalyCandidate:
    """Keep Isolation Forest as production and rank validation evidence deterministically."""

    if not candidates:
        raise AnomalyTrainingError("no fitted Isolation Forest candidate is available")

    def key(candidate: FittedAnomalyCandidate) -> tuple[float | str, ...]:
        result = candidate.result
        if (
            result.validation_metrics is None
            or result.operational_metrics is None
            or result.selected_threshold is None
        ):
            raise AnomalyTrainingError("passed anomaly candidate has incomplete evidence")
        metrics = result.validation_metrics
        selected_threshold = next(
            item for item in result.threshold_results if item.threshold == result.selected_threshold
        )
        pr_auc = metrics.pr_auc if metrics.pr_auc is not None else -1.0
        return (
            float(selected_threshold.satisfies_fpr_limit),
            pr_auc,
            metrics.f1,
            metrics.recall,
            metrics.balanced_accuracy,
            -metrics.benign_false_positive_rate,
            -selected_threshold.group_stability.benign_fpr_standard_deviation,
            -result.operational_metrics.batch_latency_p95_ms,
            -float(result.operational_metrics.estimator_serialized_size_bytes),
            result.candidate_id,
        )

    return max(candidates, key=key)


def evaluate_lof_comparator(
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> ComparatorResult:
    parameters = lof_parameters(config.lof)
    limitations = (
        "offline novelty-mode comparator only; never production bundle selection",
        "distance-based behavior may degrade in high-dimensional or large datasets",
    )
    if not config.lof.enabled:
        return ComparatorResult(
            algorithm="local_outlier_factor",
            production_eligible=False,
            status="not_implemented",
            hyperparameters=parameters,
            limitations=limitations + ("disabled by the versioned experiment configuration",),
        )
    if config.lof.n_neighbors >= len(data.benign_train.rows):
        return ComparatorResult(
            algorithm="local_outlier_factor",
            production_eligible=False,
            status="failed",
            hyperparameters=parameters,
            limitations=limitations,
            failure_code="INSUFFICIENT_BENIGN_NEIGHBORS",
        )
    try:
        estimator = build_lof_comparator(config.lof)
        estimator.fit(data.benign_train.features)
        _, training_canonical = score_pipeline(estimator, data.benign_train.features)
        normalizer = fit_score_normalizer(
            training_canonical,
            version=config.normalization_version,
            quantile_count=config.normalization_quantiles,
        )
        _, validation_canonical = score_pipeline(estimator, data.validation.features)
        normalized = normalize_scores(validation_canonical, normalizer)
        thresholds = evaluate_thresholds(
            data.validation.labels,
            normalized,
            data.validation.groups,
            candidates=config.threshold_candidates,
            false_positive_rate_limit=config.false_positive_rate_limit,
        )
        selected = select_threshold(thresholds)
    except (AnomalyEvaluationError, AnomalyTrainingError, ValueError):
        return ComparatorResult(
            algorithm="local_outlier_factor",
            production_eligible=False,
            status="failed",
            hyperparameters=parameters,
            limitations=limitations,
            failure_code="LOF_EVALUATION_FAILED",
        )
    return ComparatorResult(
        algorithm="local_outlier_factor",
        production_eligible=False,
        status="passed",
        hyperparameters=parameters,
        selected_threshold=selected.threshold,
        validation_metrics=selected.metrics,
        limitations=limitations,
    )


def one_class_svm_status(config: AnomalyTrainingConfig) -> ComparatorResult:
    return ComparatorResult(
        algorithm="one_class_svm",
        production_eligible=False,
        status=config.one_class_svm_status,
        hyperparameters={},
        limitations=(config.one_class_svm_reason,),
    )
