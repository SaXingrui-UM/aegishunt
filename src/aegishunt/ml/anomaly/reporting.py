"""Machine-readable anomaly experiment report generation."""

from __future__ import annotations

import json

from aegishunt.ml.anomaly.artifacts import AnomalyExperimentStore
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import (
    AnomalyBundleManifest,
    AnomalyFrozenTestReport,
    AnomalySelectionRecord,
    BenignTrainingManifest,
    ComparatorResult,
    IsolationForestCandidateResult,
)


def write_training_artifacts(
    store: AnomalyExperimentStore,
    config: AnomalyTrainingConfig,
    benign_manifest: BenignTrainingManifest,
    candidates: tuple[IsolationForestCandidateResult, ...],
    lof: ComparatorResult,
    one_class_svm: ComparatorResult,
    selection: AnomalySelectionRecord,
    model_payload: bytes,
) -> None:
    """Persist validation evidence without frozen-test rows or metrics."""

    store.write_json("anomaly_training_config.json", config)
    store.write_json("benign_training_manifest.json", benign_manifest)
    store.write_json(
        "isolation_forest_candidates.json",
        [candidate.model_dump(mode="json") for candidate in candidates],
    )
    hyperparameter_rows: list[dict[str, object]] = []
    threshold_rows: list[dict[str, object]] = []
    comparison_rows: list[dict[str, object]] = []
    distribution_rows: list[dict[str, object]] = []
    latency_rows: list[dict[str, object]] = []
    for candidate in candidates:
        hyperparameter_rows.append(
            {
                "candidate_id": candidate.candidate_id,
                "parameters": json.dumps(candidate.hyperparameters, sort_keys=True),
                "status": candidate.status,
                "failure_code": (
                    candidate.failure_code if candidate.failure_code is not None else ""
                ),
                "selected_threshold": (
                    candidate.selected_threshold
                    if candidate.selected_threshold is not None
                    else ""
                ),
                "validation_pr_auc": (
                    candidate.validation_metrics.pr_auc if candidate.validation_metrics else ""
                ),
                "validation_f1": (
                    candidate.validation_metrics.f1 if candidate.validation_metrics else ""
                ),
                "benign_fpr": (
                    candidate.validation_metrics.benign_false_positive_rate
                    if candidate.validation_metrics
                    else ""
                ),
                "selected": candidate.candidate_id == selection.selected_candidate_id,
            }
        )
        for threshold in candidate.threshold_results:
            threshold_rows.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "threshold": threshold.threshold,
                    "benign_fpr": threshold.metrics.benign_false_positive_rate,
                    "anomaly_recall": threshold.metrics.recall,
                    "precision": threshold.metrics.precision,
                    "f1": threshold.metrics.f1,
                    "balanced_accuracy": threshold.metrics.balanced_accuracy,
                    "satisfies_fpr_limit": threshold.satisfies_fpr_limit,
                    "selected": (
                        candidate.candidate_id == selection.selected_candidate_id
                        and threshold.threshold == selection.threshold
                    ),
                }
            )
        if candidate.validation_metrics is not None:
            comparison_rows.append(
                {
                    "algorithm": candidate.algorithm,
                    "candidate_id": candidate.candidate_id,
                    "production_eligible": True,
                    "status": candidate.status,
                    "pr_auc": candidate.validation_metrics.pr_auc,
                    "f1": candidate.validation_metrics.f1,
                    "recall": candidate.validation_metrics.recall,
                    "benign_fpr": candidate.validation_metrics.benign_false_positive_rate,
                    "selected": candidate.candidate_id == selection.selected_candidate_id,
                }
            )
        for score_type, benign, anomaly in (
            (
                "raw",
                candidate.benign_raw_distribution,
                candidate.anomaly_raw_distribution,
            ),
            (
                "normalized",
                candidate.benign_normalized_distribution,
                candidate.anomaly_normalized_distribution,
            ),
        ):
            if candidate.candidate_id == selection.selected_candidate_id:
                for label, distribution in (("benign", benign), ("anomaly", anomaly)):
                    if distribution is not None:
                        distribution_rows.append(
                            {
                                "candidate_id": candidate.candidate_id,
                                "score_type": score_type,
                                "class": label,
                                **distribution.model_dump(),
                            }
                        )
        if candidate.operational_metrics is not None:
            operational = candidate.operational_metrics
            latency_rows.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "batch_size": operational.batch_size,
                    "repetitions": operational.repetitions,
                    "batch_p50_ms": operational.batch_latency_p50_ms,
                    "batch_p95_ms": operational.batch_latency_p95_ms,
                    "batch_p99_ms": operational.batch_latency_p99_ms,
                    "per_sample_p50_ms": operational.per_sample_latency_p50_ms,
                    "throughput_samples_per_second": operational.throughput_samples_per_second,
                    "estimator_serialized_size_bytes": (
                        operational.estimator_serialized_size_bytes
                    ),
                    "peak_memory_bytes": (
                        operational.peak_memory_bytes
                        if operational.peak_memory_bytes is not None
                        else ""
                    ),
                }
            )
    for comparator in (lof, one_class_svm):
        comparison_rows.append(
            {
                "algorithm": comparator.algorithm,
                "candidate_id": comparator.algorithm,
                "production_eligible": comparator.production_eligible,
                "status": comparator.status,
                "pr_auc": (
                    comparator.validation_metrics.pr_auc
                    if comparator.validation_metrics
                    else ""
                ),
                "f1": comparator.validation_metrics.f1 if comparator.validation_metrics else "",
                "recall": (
                    comparator.validation_metrics.recall
                    if comparator.validation_metrics
                    else ""
                ),
                "benign_fpr": (
                    comparator.validation_metrics.benign_false_positive_rate
                    if comparator.validation_metrics
                    else ""
                ),
                "selected": False,
            }
        )
    store.write_csv("anomaly_hyperparameter_results.csv", hyperparameter_rows)
    store.write_json("validation_anomaly_metrics.json", selection.validation_metrics)
    store.write_json("score_normalization.json", selection.normalizer)
    store.write_csv("threshold_results.csv", threshold_rows)
    store.write_csv("threshold_sensitivity.csv", threshold_rows)
    store.write_csv("anomaly_model_comparison.csv", comparison_rows)
    store.write_json("lof_comparison.json", lof)
    store.write_json("one_class_svm_comparison.json", one_class_svm)
    store.write_csv("score_distribution.csv", distribution_rows)
    store.write_csv("latency_results.csv", latency_rows)
    store.write_bytes("selection.skops", model_payload)
    store.write_json("anomaly_model_selection.json", selection)


def write_frozen_artifacts(
    store: AnomalyExperimentStore,
    frozen: AnomalyFrozenTestReport,
    manifest: AnomalyBundleManifest,
    model_card: str,
) -> None:
    store.write_json("anomaly_frozen_test_metrics.json", frozen)
    matrix = frozen.metrics.confusion_matrix
    store.write_csv(
        "anomaly_confusion_matrix.csv",
        [
            {
                "actual": "benign",
                "predicted_benign": matrix[0][0],
                "predicted_anomaly": matrix[0][1],
            },
            {
                "actual": "anomaly",
                "predicted_benign": matrix[1][0],
                "predicted_anomaly": matrix[1][1],
            },
        ],
    )
    store.write_json(
        "anomaly_classification_report.json",
        {
            name: metrics.model_dump(mode="json")
            for name, metrics in frozen.metrics.per_class.items()
        },
    )
    store.write_text("model_card.md", model_card)
    store.write_json("anomaly_bundle_manifest.json", manifest)
