"""Validation-only candidate comparison and versioned selection policy."""

from __future__ import annotations

from dataclasses import dataclass

from sklearn.pipeline import Pipeline

from aegishunt.ml.supervised.calibration import ProbabilityCalibrator, select_calibration
from aegishunt.ml.supervised.candidates import raw_positive_scores
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import CandidateValidationResult, HyperparameterResult
from aegishunt.ml.supervised.cross_validation import fit_best_candidate, tune_candidate
from aegishunt.ml.supervised.data import TrainingValidationData
from aegishunt.ml.supervised.errors import TrainingError
from aegishunt.ml.supervised.metrics import evaluate_binary_classification
from aegishunt.ml.supervised.operational import measure_operational_metrics
from aegishunt.ml.supervised.thresholding import select_threshold


@dataclass(frozen=True, slots=True)
class FittedCandidate:
    """A validation-evaluated candidate retained without any frozen-test evidence."""

    result: CandidateValidationResult
    estimator: Pipeline
    calibrator: ProbabilityCalibrator
    tuning_results: tuple[HyperparameterResult, ...]


def evaluate_candidates(
    data: TrainingValidationData,
    config: SupervisedTrainingConfig,
) -> tuple[FittedCandidate, ...]:
    """Tune on training folds, then calibrate and evaluate on validation only."""

    evaluated: list[FittedCandidate] = []
    for candidate in config.candidates:
        best, tuning_results = tune_candidate(candidate, data.train, config)
        estimator, training_duration = fit_best_candidate(best, data.train, config)
        raw_scores = raw_positive_scores(estimator, data.validation.features)
        calibrator, calibration_evidence = select_calibration(
            raw_scores,
            data.validation.labels,
            config,
        )
        probabilities = calibrator.transform(raw_scores)
        threshold, threshold_evidence = select_threshold(
            probabilities,
            data.validation.labels,
            config.threshold_candidates,
        )
        validation_metrics = evaluate_binary_classification(
            data.validation.labels,
            (probabilities >= threshold).astype("int64"),
            probabilities,
        )
        operational = measure_operational_metrics(
            estimator,
            calibrator,
            data.validation.features,
            training_duration_seconds=training_duration,
            repetitions=config.latency_repeats,
        )
        if not operational.deterministic_predictions:
            raise TrainingError("candidate predictions are not deterministic")
        evaluated.append(
            FittedCandidate(
                result=CandidateValidationResult(
                    algorithm=candidate.algorithm,
                    hyperparameters=best.parameters,
                    calibration_method=calibrator.method,
                    calibration_candidates=calibration_evidence,
                    threshold=threshold,
                    threshold_results=threshold_evidence,
                    validation_metrics=validation_metrics,
                    cv_mean_metrics=best.mean_metrics,
                    cv_std_metrics=best.std_metrics,
                    operational_metrics=operational,
                ),
                estimator=estimator,
                calibrator=calibrator,
                tuning_results=tuning_results,
            )
        )
    return tuple(evaluated)


def selection_rank(
    candidate: FittedCandidate,
) -> tuple[float, float, float, float, float, float, float, float, str]:
    """Rank by the documented validation policy; Accuracy is deliberately absent."""

    result = candidate.result
    metrics = result.validation_metrics
    fold_variance = result.cv_std_metrics.get("macro_f1")
    return (
        metrics.macro_f1,
        metrics.pr_auc or 0.0,
        metrics.recall,
        -metrics.false_positive_rate,
        -(metrics.brier_score or 1.0),
        -float(fold_variance or 0.0),
        -result.operational_metrics.per_sample_latency_p50_ms,
        -float(result.operational_metrics.serialized_size_bytes),
        result.algorithm,
    )


def select_main_candidate(candidates: tuple[FittedCandidate, ...]) -> FittedCandidate:
    """Select one candidate without accepting or reading any test metrics."""

    if not candidates:
        raise TrainingError("model selection requires validation candidates")
    return max(candidates, key=selection_rank)
