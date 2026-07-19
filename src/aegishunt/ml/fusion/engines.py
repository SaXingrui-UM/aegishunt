"""Fixed Phase 5/6 engine adapters for isolated Phase 7 experiments."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import cast

import numpy as np
from numpy.typing import NDArray
from sklearn.pipeline import Pipeline

from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import AnomalyPredictionResult, ScoreNormalization
from aegishunt.ml.anomaly.lof import build_lof_comparator, lof_parameters
from aegishunt.ml.anomaly.normalization import fit_score_normalizer, normalize_scores
from aegishunt.ml.anomaly.scoring import score_pipeline
from aegishunt.ml.anomaly.thresholding import (
    evaluate_thresholds as evaluate_anomaly_thresholds,
)
from aegishunt.ml.anomaly.thresholding import select_threshold as select_anomaly_threshold
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.dataset import ExperimentPartition
from aegishunt.ml.fusion.errors import FusionContractError
from aegishunt.ml.supervised.calibration import ProbabilityCalibrator, fit_calibration_method
from aegishunt.ml.supervised.candidates import build_candidate, raw_positive_scores
from aegishunt.ml.supervised.config import ParameterValue, SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import PredictionResult
from aegishunt.ml.supervised.thresholding import select_threshold as select_supervised_threshold


@dataclass(frozen=True, slots=True)
class EngineScoreVectors:
    """Aligned bounded score vectors from the two independently fitted engines."""

    supervised: NDArray[np.float64]
    anomaly: NDArray[np.float64]

    def __post_init__(self) -> None:
        if (
            self.supervised.ndim != 1
            or self.supervised.shape != self.anomaly.shape
            or not len(self.supervised)
            or not np.isfinite(self.supervised).all()
            or not np.isfinite(self.anomaly).all()
            or np.any((self.supervised < 0.0) | (self.supervised > 1.0))
            or np.any((self.anomaly < 0.0) | (self.anomaly > 1.0))
        ):
            raise FusionContractError("engine score vectors must be finite, bounded, and aligned")


@dataclass(frozen=True, slots=True)
class FittedExperimentalEngines:
    """Temporary research models; never registered as Phase 5/6 active bundles."""

    supervised_estimator: Pipeline
    supervised_calibrator: ProbabilityCalibrator
    supervised_threshold: float
    anomaly_estimator: Pipeline
    anomaly_normalizer: ScoreNormalization
    anomaly_threshold: float
    supervised_fit_seconds: float
    anomaly_fit_seconds: float

    def score_supervised(self, partition: ExperimentPartition) -> NDArray[np.float64]:
        raw = raw_positive_scores(self.supervised_estimator, partition.features)
        return self.supervised_calibrator.transform(raw)

    def score_anomaly(self, partition: ExperimentPartition) -> NDArray[np.float64]:
        _, canonical = score_pipeline(self.anomaly_estimator, partition.features)
        return normalize_scores(canonical, self.anomaly_normalizer)

    def score(self, partition: ExperimentPartition) -> EngineScoreVectors:
        return EngineScoreVectors(
            supervised=self.score_supervised(partition),
            anomaly=self.score_anomaly(partition),
        )


def _validate_fixed_configs(
    fusion: FusionExperimentConfig,
    supervised: SupervisedTrainingConfig,
    anomaly: AnomalyTrainingConfig,
) -> None:
    random_forest = next(
        (
            candidate
            for candidate in supervised.candidates
            if candidate.algorithm == "random_forest"
        ),
        None,
    )
    parameters = cast(dict[str, ParameterValue], fusion.supervised_hyperparameters)
    if random_forest is None or parameters not in random_forest.combinations():
        raise FusionContractError("Phase 7 supervised configuration differs from Phase 5")
    if fusion.supervised_calibration not in supervised.calibration_methods:
        raise FusionContractError("Phase 7 calibration differs from Phase 5")
    if lof_parameters(anomaly.lof) != fusion.anomaly_hyperparameters:
        raise FusionContractError("Phase 7 anomaly configuration differs from Phase 6")
    if not anomaly.lof_production_eligible or anomaly.candidate_status != "validation_qualified":
        raise FusionContractError("Phase 6 LOF is not validation-qualified")
    if fusion.anomaly_normalization not in anomaly.normalization_strategies:
        raise FusionContractError("Phase 7 anomaly normalization differs from Phase 6")


def fit_experimental_engines(
    train: ExperimentPartition,
    validation: ExperimentPartition,
    *,
    fusion_config: FusionExperimentConfig,
    supervised_config: SupervisedTrainingConfig,
    anomaly_config: AnomalyTrainingConfig,
) -> tuple[FittedExperimentalEngines, EngineScoreVectors]:
    """Fit fixed engines on train groups and select thresholds on validation only."""

    _validate_fixed_configs(fusion_config, supervised_config, anomaly_config)
    if set(train.labels.tolist()) != {0, 1} or set(validation.labels.tolist()) != {0, 1}:
        raise FusionContractError("experimental supervised fitting requires both classes")
    if set(train.groups.tolist()) & set(validation.groups.tolist()):
        raise FusionContractError("experimental train and validation groups overlap")
    supervised_estimator = build_candidate(
        "random_forest",
        cast(dict[str, ParameterValue], fusion_config.supervised_hyperparameters),
        random_seed=fusion_config.model_seed,
    )
    started = time.perf_counter()
    supervised_estimator.fit(train.features, train.labels)
    supervised_fit_seconds = time.perf_counter() - started
    validation_raw = raw_positive_scores(supervised_estimator, validation.features)
    calibrator = fit_calibration_method(
        "isotonic",
        validation_raw,
        validation.labels,
        random_seed=fusion_config.model_seed,
    )
    validation_supervised = calibrator.transform(validation_raw)
    supervised_threshold, _ = select_supervised_threshold(
        validation_supervised,
        validation.labels,
        fusion_config.supervised_threshold_candidates,
    )

    benign_mask = train.labels == 0
    benign_features = train.features[benign_mask]
    if len(benign_features) < anomaly_config.minimum_benign_groups:
        raise FusionContractError("benign training evidence is insufficient for Phase 6 LOF")
    anomaly_estimator = build_lof_comparator(anomaly_config.lof)
    started = time.perf_counter()
    anomaly_estimator.fit(benign_features)
    anomaly_fit_seconds = time.perf_counter() - started
    _, benign_canonical = score_pipeline(anomaly_estimator, benign_features)
    normalizer = fit_score_normalizer(
        benign_canonical,
        version=anomaly_config.normalization_version,
        quantile_count=anomaly_config.normalization_quantiles,
        strategy="benign_training_quantile_cdf",
    )
    _, validation_canonical = score_pipeline(anomaly_estimator, validation.features)
    validation_anomaly = normalize_scores(validation_canonical, normalizer)
    anomaly_results = evaluate_anomaly_thresholds(
        validation.labels,
        validation_anomaly,
        validation.groups,
        candidates=fusion_config.anomaly_threshold_candidates,
        false_positive_rate_limit=fusion_config.anomaly_false_positive_rate_ceiling,
    )
    anomaly_threshold = select_anomaly_threshold(
        anomaly_results,
        policy_version="2.0.0",
    ).threshold
    engines = FittedExperimentalEngines(
        supervised_estimator=supervised_estimator,
        supervised_calibrator=calibrator,
        supervised_threshold=supervised_threshold,
        anomaly_estimator=anomaly_estimator,
        anomaly_normalizer=normalizer,
        anomaly_threshold=anomaly_threshold,
        supervised_fit_seconds=supervised_fit_seconds,
        anomaly_fit_seconds=anomaly_fit_seconds,
    )
    return engines, EngineScoreVectors(
        supervised=validation_supervised,
        anomaly=validation_anomaly,
    )


def adapt_verified_predictions(
    supervised: tuple[PredictionResult, ...],
    anomaly: tuple[AnomalyPredictionResult, ...],
    config: FusionExperimentConfig,
) -> EngineScoreVectors:
    """Adapt already verified operational outputs without a single-engine fallback."""

    if not supervised or len(supervised) != len(anomaly):
        raise FusionContractError("both engine result sets must be present and aligned")
    for supervised_item, anomaly_item in zip(supervised, anomaly, strict=True):
        identity = (
            supervised_item.model_id,
            supervised_item.model_version,
            anomaly_item.model_id,
            anomaly_item.model_version,
            supervised_item.feature_schema_version,
            anomaly_item.feature_schema_version,
        )
        expected = (
            config.supervised_model_id,
            config.supervised_model_version,
            config.anomaly_model_id,
            config.anomaly_model_version,
            config.feature_schema_version,
            config.feature_schema_version,
        )
        if identity != expected:
            raise FusionContractError("operational engine identity does not match fusion config")
    return EngineScoreVectors(
        supervised=np.asarray(
            [item.calibrated_probability for item in supervised], dtype=np.float64
        ),
        anomaly=np.asarray(
            [item.normalized_anomaly_score for item in anomaly], dtype=np.float64
        ),
    )
