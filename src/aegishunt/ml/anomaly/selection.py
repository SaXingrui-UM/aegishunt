"""Validation-only anomaly candidate selection and truthful comparison."""

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
    NormalizationStrategy,
)
from aegishunt.ml.anomaly.contracts import (
    AnomalyCandidateResult,
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
    result: AnomalyCandidateResult
    model_payload: bytes
    validation_labels: NDArray[np.int64]
    validation_raw_scores: NDArray[np.float64]
    validation_normalized_scores: NDArray[np.float64]


@dataclass(frozen=True, slots=True)
class CandidateEvaluationSet:
    fitted: tuple[FittedAnomalyCandidate, ...]
    results: tuple[IsolationForestCandidateResult, ...]


@dataclass(frozen=True, slots=True)
class CandidateEvaluation:
    fitted: FittedAnomalyCandidate | None
    result: IsolationForestCandidateResult


@dataclass(frozen=True, slots=True)
class LofEvaluation:
    fitted: FittedAnomalyCandidate | None
    comparator: ComparatorResult


def _distribution_pair(
    values: NDArray[np.float64],
    labels: NDArray[np.int64],
) -> tuple[ScoreDistribution, ScoreDistribution]:
    return summarize_scores(values[labels == 0]), summarize_scores(values[labels == 1])


def _fit_candidate(
    candidate: IsolationForestCandidateConfig,
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
    normalization_strategy: NormalizationStrategy,
) -> CandidateEvaluation:
    estimator = build_isolation_forest(candidate, random_seed=config.random_seed)
    started = time.perf_counter()
    estimator.fit(data.benign_train.features)
    duration = time.perf_counter() - started
    _, training_canonical = score_pipeline(estimator, data.benign_train.features)
    normalizer = fit_score_normalizer(
        training_canonical,
        version=config.normalization_version,
        quantile_count=config.normalization_quantiles,
        strategy=normalization_strategy,
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
    evidence_id = (
        candidate.candidate_id
        if config.config_schema_version == "1.0.0"
        else f"{candidate.candidate_id}--{normalization_strategy}"
    )
    try:
        selected = select_threshold(
            threshold_results,
            policy_version=config.selection_policy_version,
        )
    except AnomalyEvaluationError:
        result = IsolationForestCandidateResult(
            candidate_id=evidence_id,
            algorithm="isolation_forest",
            hyperparameters=isolation_parameters(candidate),
            normalization_strategy=normalization_strategy,
            status="failed",
            failure_code="NO_FPR_COMPLIANT_THRESHOLD",
            benign_training_rows=len(data.benign_train.rows),
            benign_training_groups=len(set(data.benign_train.groups.tolist())),
            validation_rows=len(data.validation.rows),
            validation_groups=len(set(data.validation.groups.tolist())),
            threshold_results=threshold_results,
            normalizer=normalizer,
            benign_raw_distribution=raw_benign,
            anomaly_raw_distribution=raw_anomaly,
            benign_normalized_distribution=normalized_benign,
            anomaly_normalized_distribution=normalized_anomaly,
            operational_metrics=operational,
        )
        return CandidateEvaluation(None, result)
    result = IsolationForestCandidateResult(
        candidate_id=evidence_id,
        algorithm="isolation_forest",
        hyperparameters=isolation_parameters(candidate),
        normalization_strategy=normalization_strategy,
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
    fitted = FittedAnomalyCandidate(
        estimator=estimator,
        result=result,
        model_payload=estimator_bytes(estimator),
        validation_labels=data.validation.labels.copy(),
        validation_raw_scores=validation_raw.copy(),
        validation_normalized_scores=validation_normalized.copy(),
    )
    return CandidateEvaluation(fitted, result)


def evaluate_isolation_forest_candidates(
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> CandidateEvaluationSet:
    fitted: list[FittedAnomalyCandidate] = []
    results: list[IsolationForestCandidateResult] = []
    for candidate in config.isolation_forest_candidates:
        for normalization_strategy in config.normalization_strategies:
            evidence_id = (
                candidate.candidate_id
                if config.config_schema_version == "1.0.0"
                else f"{candidate.candidate_id}--{normalization_strategy}"
            )
            try:
                completed = _fit_candidate(
                    candidate,
                    data,
                    config,
                    normalization_strategy,
                )
                if completed.fitted is not None:
                    fitted.append(completed.fitted)
                results.append(completed.result)
            except (AnomalyEvaluationError, AnomalyTrainingError, ValueError) as exc:
                results.append(
                    IsolationForestCandidateResult(
                        candidate_id=evidence_id,
                        algorithm="isolation_forest",
                        hyperparameters=isolation_parameters(candidate),
                        normalization_strategy=normalization_strategy,
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
    *,
    selection_policy_version: str = "1.0.0",
) -> FittedAnomalyCandidate:
    """Rank production-eligible validation evidence deterministically."""

    if not candidates:
        raise AnomalyTrainingError("no fitted anomaly candidate is available")

    eligible = candidates
    if selection_policy_version in {"1.0.1", "2.0.0"}:
        eligible = tuple(
            candidate
            for candidate in candidates
            if candidate.result.validation_metrics is not None
            and candidate.result.validation_metrics.f1 > 0.0
            and candidate.result.validation_metrics.recall > 0.0
        )
        if not eligible:
            raise AnomalyTrainingError(
                "no anomaly candidate satisfies positive validation utility"
            )
    elif selection_policy_version != "1.0.0":
        raise AnomalyTrainingError("unsupported anomaly candidate-selection policy")

    def key(candidate: FittedAnomalyCandidate) -> tuple[float, ...]:
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
        original = (
            float(selected_threshold.satisfies_fpr_limit),
            pr_auc,
            metrics.f1,
            metrics.recall,
            metrics.balanced_accuracy,
            -metrics.benign_false_positive_rate,
            -selected_threshold.group_stability.benign_fpr_standard_deviation,
            -result.operational_metrics.batch_latency_p95_ms,
            -float(result.operational_metrics.estimator_serialized_size_bytes),
        )
        if selection_policy_version == "1.0.0":
            return original
        if selection_policy_version == "2.0.0":
            return (
                float(metrics.f1 > 0.0),
                metrics.f1,
                metrics.recall,
                pr_auc,
                metrics.balanced_accuracy,
                -metrics.benign_false_positive_rate,
            )
        parameters = result.hyperparameters
        n_estimators = float(parameters["n_estimators"])
        max_samples = float(parameters["max_samples"])
        max_features = float(parameters["max_features"])
        bootstrap = float(bool(parameters["bootstrap"]))
        return (
            float(metrics.f1 > 0.0),
            metrics.f1,
            metrics.recall,
            pr_auc,
            metrics.balanced_accuracy,
            -metrics.benign_false_positive_rate,
            -n_estimators,
            -max_samples,
            -max_features,
            -bootstrap,
        )

    return max(sorted(eligible, key=lambda item: item.result.candidate_id), key=key)


def evaluate_lof_candidate(
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> LofEvaluation:
    parameters = lof_parameters(config.lof)
    eligible = config.lof_production_eligible
    limitations = (
        (
            "validation-qualified production candidate under ADR 0015; "
            "independent holdout still required"
            if eligible
            else "offline novelty-mode comparator only; never production bundle selection"
        ),
        "distance-based behavior may degrade in high-dimensional or large datasets",
    )
    candidate_id = (
        f"lof-novelty-{config.lof.n_neighbors}--{config.normalization_strategies[0]}"
    )
    if not config.lof.enabled:
        return LofEvaluation(
            fitted=None,
            comparator=ComparatorResult(
                algorithm="local_outlier_factor",
                candidate_id=candidate_id,
                production_eligible=False,
                status="not_implemented",
                hyperparameters=parameters,
                limitations=limitations
                + ("disabled by the versioned experiment configuration",),
            ),
        )
    if config.lof.n_neighbors >= len(data.benign_train.rows):
        return LofEvaluation(
            fitted=None,
            comparator=ComparatorResult(
                algorithm="local_outlier_factor",
                candidate_id=candidate_id,
                production_eligible=eligible,
                status="failed",
                hyperparameters=parameters,
                limitations=limitations,
                failure_code="INSUFFICIENT_BENIGN_NEIGHBORS",
            ),
        )
    try:
        estimator = build_lof_comparator(config.lof)
        started = time.perf_counter()
        estimator.fit(data.benign_train.features)
        training_duration = time.perf_counter() - started
        _, training_canonical = score_pipeline(estimator, data.benign_train.features)
        normalizer = fit_score_normalizer(
            training_canonical,
            version=config.normalization_version,
            quantile_count=config.normalization_quantiles,
            strategy=config.normalization_strategies[0],
        )
        validation_raw, validation_canonical = score_pipeline(
            estimator, data.validation.features
        )
        normalized = normalize_scores(validation_canonical, normalizer)
        thresholds = evaluate_thresholds(
            data.validation.labels,
            normalized,
            data.validation.groups,
            candidates=config.threshold_candidates,
            false_positive_rate_limit=config.false_positive_rate_limit,
        )
        selected = select_threshold(
            thresholds,
            policy_version=config.selection_policy_version,
        )
        raw_benign, raw_anomaly = _distribution_pair(validation_raw, data.validation.labels)
        normalized_benign, normalized_anomaly = _distribution_pair(
            normalized, data.validation.labels
        )
        operational = measure_operational_metrics(
            estimator,
            normalizer,
            data.validation.features,
            training_duration_seconds=training_duration,
            repetitions=config.latency_repetitions,
        )
    except (AnomalyEvaluationError, AnomalyTrainingError, ValueError):
        return LofEvaluation(
            fitted=None,
            comparator=ComparatorResult(
                algorithm="local_outlier_factor",
                candidate_id=candidate_id,
                production_eligible=eligible,
                status="failed",
                hyperparameters=parameters,
                limitations=limitations,
                failure_code="LOF_EVALUATION_FAILED",
            ),
        )
    comparator = ComparatorResult(
        algorithm="local_outlier_factor",
        candidate_id=candidate_id,
        production_eligible=eligible,
        status="passed",
        hyperparameters=parameters,
        preprocessing="standard_scaler",
        raw_score_method="score_samples",
        canonical_score_transform="negative_raw_score",
        normalizer=normalizer,
        threshold_policy="validation_benign_fpr_constrained",
        false_positive_rate_limit=config.false_positive_rate_limit,
        benign_training_rows=len(data.benign_train.rows),
        benign_training_groups=len(set(data.benign_train.groups.tolist())),
        validation_rows=len(data.validation.rows),
        validation_groups=len(set(data.validation.groups.tolist())),
        selected_threshold=selected.threshold,
        threshold_results=thresholds,
        validation_metrics=selected.metrics,
        benign_raw_distribution=raw_benign,
        anomaly_raw_distribution=raw_anomaly,
        benign_normalized_distribution=normalized_benign,
        anomaly_normalized_distribution=normalized_anomaly,
        operational_metrics=operational,
        limitations=limitations,
    )
    result = AnomalyCandidateResult(
        candidate_id=candidate_id,
        algorithm="local_outlier_factor",
        hyperparameters=parameters,
        normalization_strategy=config.normalization_strategies[0],
        status="passed",
        benign_training_rows=len(data.benign_train.rows),
        benign_training_groups=len(set(data.benign_train.groups.tolist())),
        validation_rows=len(data.validation.rows),
        validation_groups=len(set(data.validation.groups.tolist())),
        selected_threshold=selected.threshold,
        threshold_results=thresholds,
        validation_metrics=selected.metrics,
        normalizer=normalizer,
        benign_raw_distribution=raw_benign,
        anomaly_raw_distribution=raw_anomaly,
        benign_normalized_distribution=normalized_benign,
        anomaly_normalized_distribution=normalized_anomaly,
        operational_metrics=operational,
    )
    fitted = FittedAnomalyCandidate(
        estimator=estimator,
        result=result,
        model_payload=estimator_bytes(estimator),
        validation_labels=data.validation.labels.copy(),
        validation_raw_scores=validation_raw.copy(),
        validation_normalized_scores=normalized.copy(),
    )
    return LofEvaluation(fitted=fitted, comparator=comparator)


def evaluate_lof_comparator(
    data: AnomalyTrainingData,
    config: AnomalyTrainingConfig,
) -> ComparatorResult:
    return evaluate_lof_candidate(data, config).comparator


def one_class_svm_status(config: AnomalyTrainingConfig) -> ComparatorResult:
    return ComparatorResult(
        algorithm="one_class_svm",
        production_eligible=False,
        status=config.one_class_svm_status,
        hyperparameters={},
        limitations=(config.one_class_svm_reason,),
    )
