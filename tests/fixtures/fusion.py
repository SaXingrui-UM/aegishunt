"""Small Phase 7 configuration builders for isolated tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from aegishunt.ml.fusion.config import (
    FusionExperimentConfig,
    ParameterShiftDefinition,
    WeightCandidate,
)

PROJECT_ROOT = Path(__file__).parents[2]
FUSION_CONFIG_PATH = PROJECT_ROOT / "configs" / "models" / "fusion.yaml"


def fusion_config(**updates: object) -> FusionExperimentConfig:
    payload: dict[str, object] = {
        "config_schema_version": "1.0.0",
        "experiment_id": "phase-07-controlled-fusion-001",
        "policy_id": "aegishunt-fusion-controlled",
        "policy_version": "1.0.0",
        "dataset_id": "aegishunt-phase-07-controlled",
        "dataset_version": "1.0.0",
        "feature_schema_version": "1.0.0",
        "controlled_synthetic_only": True,
        "public_benchmark": False,
        "groups_per_pattern": 9,
        "rows_per_group": 2,
        "data_seed": 7207,
        "model_seed": 7307,
        "bootstrap_seed": 7407,
        "bootstrap_draws": 1000,
        "protocol_frozen_at": datetime(2026, 7, 20, tzinfo=UTC),
        "supervised_model_id": "aegishunt-supervised-1.0.1",
        "supervised_model_version": "1.0.1",
        "supervised_algorithm": "random_forest",
        "supervised_hyperparameters": {
            "class_weight": "none",
            "max_depth": 8,
            "max_features": "sqrt",
            "min_samples_leaf": 1,
            "min_samples_split": 2,
            "n_estimators": 64,
            "n_jobs": 1,
        },
        "supervised_calibration": "isotonic",
        "supervised_threshold_candidates": (0.25, 0.5, 0.75),
        "anomaly_model_id": "aegishunt-anomaly-1.1.0-candidate",
        "anomaly_model_version": "1.1.0-candidate",
        "anomaly_algorithm": "local_outlier_factor",
        "anomaly_hyperparameters": {
            "n_neighbors": 5,
            "metric": "minkowski",
            "algorithm": "auto",
            "leaf_size": 30,
            "n_jobs": 1,
            "novelty": True,
        },
        "anomaly_normalization": "benign_training_quantile_cdf",
        "anomaly_threshold_candidates": (0.4, 0.6, 0.8, 1.0),
        "anomaly_false_positive_rate_ceiling": 0.35,
        "weight_candidates": (
            WeightCandidate(
                candidate_id="supervised-25-anomaly-75",
                supervised_weight=0.25,
                anomaly_weight=0.75,
            ),
            WeightCandidate(
                candidate_id="supervised-50-anomaly-50",
                supervised_weight=0.5,
                anomaly_weight=0.5,
            ),
            WeightCandidate(
                candidate_id="supervised-75-anomaly-25",
                supervised_weight=0.75,
                anomaly_weight=0.25,
            ),
        ),
        "fusion_threshold_candidates": (0.25, 0.5, 0.75),
        "false_positive_rate_ceiling": 0.25,
        "recommendation_min_macro_f1_delta": 0.0,
        "recommendation_max_fpr_increase": 0.05,
        "selection_policy_version": "1.0.0",
        "selection_objective": "macro_f1_under_fpr_ceiling",
        "tie_break_order": (
            "positive_macro_f1",
            "macro_f1",
            "recall",
            "pr_auc",
            "balanced_accuracy",
            "lower_false_negative_rate",
            "lower_false_positive_rate",
            "stable_candidate_id",
        ),
        "parameter_shifts": tuple(
            ParameterShiftDefinition(
                shift_id=f"shift-{axis.replace('_', '-')}",
                axis=axis,
                factor=1.25,
                description=f"Pre-registered bounded synthetic shift for {axis} behavior.",
            )
            for axis in (
                "flow_duration",
                "packet_rate",
                "packet_size_pattern",
                "connection_frequency",
            )
        ),
        "latency_repetitions": 10,
        "no_historical_test_access": True,
        "negative_results_retained": True,
    }
    payload.update(updates)
    return FusionExperimentConfig.model_validate(payload)
