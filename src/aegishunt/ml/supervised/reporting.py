"""Machine-readable Phase 5 experiment report generation."""

from __future__ import annotations

import json

from aegishunt.ml.supervised.artifacts import ExperimentStore
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import (
    BundleManifest,
    FrozenTestReport,
    ModelSelectionRecord,
)
from aegishunt.ml.supervised.selection import FittedCandidate


def write_training_artifacts(
    store: ExperimentStore,
    config: SupervisedTrainingConfig,
    candidates: tuple[FittedCandidate, ...],
    selection: ModelSelectionRecord,
    model_payload: bytes,
) -> None:
    """Persist complete train/CV/validation evidence without test metrics."""

    store.write_json("training_config.json", config)
    store.write_json(
        "candidate_models.json",
        [candidate.model_dump(mode="json") for candidate in config.candidates],
    )
    hyperparameter_rows: list[dict[str, object]] = []
    fold_rows: list[dict[str, object]] = []
    threshold_rows: list[dict[str, object]] = []
    calibration_payload: dict[str, object] = {}
    validation_payload: dict[str, object] = {}
    comparison_rows: list[dict[str, object]] = []
    latency_rows: list[dict[str, object]] = []
    for candidate in candidates:
        result = candidate.result
        validation_payload[result.algorithm] = result.validation_metrics.model_dump(mode="json")
        calibration_payload[result.algorithm] = [
            item.model_dump(mode="json") for item in result.calibration_candidates
        ]
        for tuning_index, tuning in enumerate(candidate.tuning_results):
            hyperparameter_rows.append(
                {
                    "algorithm": result.algorithm,
                    "candidate_index": tuning_index,
                    "parameters": json.dumps(tuning.parameters, sort_keys=True),
                    "status": tuning.status,
                    "failure_code": tuning.failure_code or "",
                    "macro_f1_mean": tuning.mean_metrics.get("macro_f1"),
                    "pr_auc_mean": tuning.mean_metrics.get("pr_auc"),
                    "training_duration_seconds": tuning.training_duration_seconds,
                }
            )
            for fold in tuning.folds:
                fold_rows.append(
                    {
                        "algorithm": result.algorithm,
                        "candidate_index": tuning_index,
                        "fold_index": fold.evidence.fold_index,
                        "train_rows": fold.evidence.train_rows,
                        "validation_rows": fold.evidence.validation_rows,
                        "train_groups": len(fold.evidence.train_groups),
                        "validation_groups": len(fold.evidence.validation_groups),
                        "group_overlap": len(fold.evidence.group_overlap),
                        "source_overlap": len(fold.evidence.source_overlap),
                        "session_overlap": len(fold.evidence.session_overlap),
                        "scenario_overlap": len(fold.evidence.scenario_overlap),
                        "macro_f1": fold.metrics.macro_f1,
                        "pr_auc": fold.metrics.pr_auc,
                    }
                )
        for threshold in result.threshold_results:
            threshold_rows.append(
                {
                    "algorithm": result.algorithm,
                    "threshold": threshold.threshold,
                    "macro_f1": threshold.metrics.macro_f1,
                    "recall": threshold.metrics.recall,
                    "false_positive_rate": threshold.metrics.false_positive_rate,
                    "selected": threshold.threshold == result.threshold,
                }
            )
        comparison_rows.append(
            {
                "algorithm": result.algorithm,
                "macro_f1": result.validation_metrics.macro_f1,
                "pr_auc": result.validation_metrics.pr_auc,
                "recall": result.validation_metrics.recall,
                "false_positive_rate": result.validation_metrics.false_positive_rate,
                "brier_score": result.validation_metrics.brier_score,
                "cv_macro_f1_std": result.cv_std_metrics.get("macro_f1"),
                "selected": result.algorithm == selection.algorithm,
            }
        )
        operational = result.operational_metrics
        latency_rows.append(
            {
                "algorithm": result.algorithm,
                "batch_size": operational.batch_size,
                "repetitions": operational.repetitions,
                "batch_p50_ms": operational.batch_latency_p50_ms,
                "batch_p95_ms": operational.batch_latency_p95_ms,
                "batch_p99_ms": operational.batch_latency_p99_ms,
                "per_sample_p50_ms": operational.per_sample_latency_p50_ms,
                "throughput_samples_per_second": operational.throughput_samples_per_second,
                "serialized_size_bytes": operational.serialized_size_bytes,
                "peak_memory_bytes": operational.peak_memory_bytes or "",
            }
        )
    store.write_csv("hyperparameter_results.csv", hyperparameter_rows)
    store.write_csv("cross_validation_results.csv", fold_rows)
    store.write_json("validation_metrics.json", validation_payload)
    store.write_csv("threshold_results.csv", threshold_rows)
    store.write_json("calibration_metrics.json", calibration_payload)
    store.write_csv("model_comparison.csv", comparison_rows)
    store.write_csv("latency_results.csv", latency_rows)
    store.write_bytes("selection.skops", model_payload)
    store.write_json("model_selection.json", selection)


def write_frozen_artifacts(
    store: ExperimentStore,
    frozen: FrozenTestReport,
    manifest: BundleManifest,
    model_card: str,
) -> None:
    """Persist the one-time frozen report and final bundle metadata."""

    store.write_json("frozen_test_metrics.json", frozen)
    matrix = frozen.metrics.confusion_matrix
    store.write_csv(
        "confusion_matrix.csv",
        [
            {
                "actual": "benign",
                "predicted_benign": matrix[0][0],
                "predicted_malicious": matrix[0][1],
            },
            {
                "actual": "malicious",
                "predicted_benign": matrix[1][0],
                "predicted_malicious": matrix[1][1],
            },
        ],
    )
    classification_report = {
        name: value.model_dump(mode="json")
        for name, value in frozen.metrics.per_class.items()
    }
    store.write_json("classification_report.json", classification_report)
    store.write_text("model_card.md", model_card)
    store.write_json("model_bundle_manifest.json", manifest)
