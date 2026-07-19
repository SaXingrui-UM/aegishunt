"""Machine-readable anomaly experiment report generation."""

from __future__ import annotations

import hashlib
import json

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.artifacts import (
    SELECTION_CHECKSUM_FILENAME,
    SELECTION_RECORD_FILENAME,
    AnomalyExperimentStore,
)
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import (
    AnomalyBundleManifest,
    AnomalyCandidateResult,
    AnomalyFrozenTestReport,
    AnomalySelectionRecord,
    BenignTrainingManifest,
    ComparatorResult,
    IsolationForestCandidateResult,
)
from aegishunt.ml.anomaly.plotting import write_validation_plots


def _comparison_row(
    *,
    algorithm: str,
    candidate_id: str,
    production_eligible: bool,
    status: str,
    selected_threshold: float | None,
    metrics: object,
    operational: object,
    training_rows: int | None,
    training_groups: int | None,
    validation_rows: int | None,
    validation_groups: int | None,
    selected: bool,
) -> dict[str, object]:
    from aegishunt.ml.anomaly.contracts import AnomalyMetrics, AnomalyOperationalMetrics

    validated_metrics = metrics if isinstance(metrics, AnomalyMetrics) else None
    validated_operational = (
        operational if isinstance(operational, AnomalyOperationalMetrics) else None
    )
    matrix = (
        validated_metrics.confusion_matrix
        if validated_metrics is not None
        else (("", ""), ("", ""))
    )
    return {
        "algorithm": algorithm,
        "candidate_id": candidate_id,
        "production_eligible": production_eligible,
        "status": status,
        "selected_threshold": selected_threshold if selected_threshold is not None else "",
        "accuracy": validated_metrics.accuracy if validated_metrics else "",
        "precision": validated_metrics.precision if validated_metrics else "",
        "recall": validated_metrics.recall if validated_metrics else "",
        "f1": validated_metrics.f1 if validated_metrics else "",
        "macro_f1": validated_metrics.macro_f1 if validated_metrics else "",
        "weighted_f1": validated_metrics.weighted_f1 if validated_metrics else "",
        "balanced_accuracy": validated_metrics.balanced_accuracy if validated_metrics else "",
        "mcc": validated_metrics.mcc if validated_metrics else "",
        "roc_auc": validated_metrics.roc_auc if validated_metrics else "",
        "pr_auc": validated_metrics.pr_auc if validated_metrics else "",
        "specificity": validated_metrics.specificity if validated_metrics else "",
        "benign_fpr": (
            validated_metrics.benign_false_positive_rate if validated_metrics else ""
        ),
        "anomaly_fnr": (
            validated_metrics.anomaly_false_negative_rate if validated_metrics else ""
        ),
        "tn": matrix[0][0],
        "fp": matrix[0][1],
        "fn": matrix[1][0],
        "tp": matrix[1][1],
        "training_rows": training_rows if training_rows is not None else "",
        "training_groups": training_groups if training_groups is not None else "",
        "validation_rows": validation_rows if validation_rows is not None else "",
        "validation_groups": validation_groups if validation_groups is not None else "",
        "batch_p95_ms": (
            validated_operational.batch_latency_p95_ms if validated_operational else ""
        ),
        "per_sample_p50_ms": (
            validated_operational.per_sample_latency_p50_ms if validated_operational else ""
        ),
        "throughput_samples_per_second": (
            validated_operational.throughput_samples_per_second
            if validated_operational
            else ""
        ),
        "estimator_serialized_size_bytes": (
            validated_operational.estimator_serialized_size_bytes
            if validated_operational
            else ""
        ),
        "selected": selected,
    }


def write_training_artifacts(
    store: AnomalyExperimentStore,
    config: AnomalyTrainingConfig,
    benign_manifest: BenignTrainingManifest,
    candidates: tuple[IsolationForestCandidateResult, ...],
    lof: ComparatorResult,
    one_class_svm: ComparatorResult,
    selected_candidate: AnomalyCandidateResult,
    selection: AnomalySelectionRecord,
    model_payload: bytes,
    validation_labels: NDArray[np.int64],
    validation_raw_scores: NDArray[np.float64],
    validation_normalized_scores: NDArray[np.float64],
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
                "normalization_strategy": candidate.normalization_strategy,
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
                    "algorithm": candidate.algorithm,
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
        comparison_rows.append(
            _comparison_row(
                algorithm=candidate.algorithm,
                candidate_id=candidate.candidate_id,
                production_eligible=True,
                status=candidate.status,
                selected_threshold=candidate.selected_threshold,
                metrics=candidate.validation_metrics,
                operational=candidate.operational_metrics,
                training_rows=candidate.benign_training_rows,
                training_groups=candidate.benign_training_groups,
                validation_rows=candidate.validation_rows,
                validation_groups=candidate.validation_groups,
                selected=candidate.candidate_id == selection.selected_candidate_id,
            )
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
                    "algorithm": candidate.algorithm,
                    "candidate_id": candidate.candidate_id,
                    "production_eligible": True,
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
        comparator_id = comparator.candidate_id or comparator.algorithm
        comparison_rows.append(
            _comparison_row(
                algorithm=comparator.algorithm,
                candidate_id=comparator_id,
                production_eligible=comparator.production_eligible,
                status=comparator.status,
                selected_threshold=comparator.selected_threshold,
                metrics=comparator.validation_metrics,
                operational=comparator.operational_metrics,
                training_rows=comparator.benign_training_rows,
                training_groups=comparator.benign_training_groups,
                validation_rows=comparator.validation_rows,
                validation_groups=comparator.validation_groups,
                selected=comparator_id == selection.selected_candidate_id,
            )
        )
        for threshold in comparator.threshold_results:
            threshold_rows.append(
                {
                    "algorithm": comparator.algorithm,
                    "candidate_id": comparator_id,
                    "threshold": threshold.threshold,
                    "benign_fpr": threshold.metrics.benign_false_positive_rate,
                    "anomaly_recall": threshold.metrics.recall,
                    "precision": threshold.metrics.precision,
                    "f1": threshold.metrics.f1,
                    "balanced_accuracy": threshold.metrics.balanced_accuracy,
                    "satisfies_fpr_limit": threshold.satisfies_fpr_limit,
                    "selected": (
                        comparator_id == selection.selected_candidate_id
                        and threshold.threshold == comparator.selected_threshold
                    ),
                }
            )
        for score_type, benign, anomaly in (
            (
                "raw",
                comparator.benign_raw_distribution,
                comparator.anomaly_raw_distribution,
            ),
            (
                "normalized",
                comparator.benign_normalized_distribution,
                comparator.anomaly_normalized_distribution,
            ),
        ):
            for label, distribution in (("benign", benign), ("anomaly", anomaly)):
                if distribution is not None:
                    distribution_rows.append(
                        {
                            "candidate_id": comparator_id,
                            "score_type": score_type,
                            "class": label,
                            **distribution.model_dump(),
                        }
                    )
        if comparator.operational_metrics is not None:
            operational = comparator.operational_metrics
            latency_rows.append(
                {
                    "algorithm": comparator.algorithm,
                    "candidate_id": comparator.algorithm,
                    "production_eligible": comparator.production_eligible,
                    "batch_size": operational.batch_size,
                    "repetitions": operational.repetitions,
                    "batch_p50_ms": operational.batch_latency_p50_ms,
                    "batch_p95_ms": operational.batch_latency_p95_ms,
                    "batch_p99_ms": operational.batch_latency_p99_ms,
                    "per_sample_p50_ms": operational.per_sample_latency_p50_ms,
                    "throughput_samples_per_second": (
                        operational.throughput_samples_per_second
                    ),
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
    selection_payload = selection.model_dump_json(indent=2) + "\n"
    store.write_text(SELECTION_RECORD_FILENAME, selection_payload)
    store.write_text(
        SELECTION_CHECKSUM_FILENAME,
        hashlib.sha256(selection_payload.encode("utf-8")).hexdigest() + "\n",
    )
    write_validation_plots(
        store,
        experiment_id=selection.experiment_id,
        feature_schema_version=selection.feature_schema_version,
        selected_threshold=selection.threshold,
        selected_candidate_id=selection.selected_candidate_id,
        dataset_manifest_checksum=selection.dataset_manifest_checksum,
        split_manifest_checksum=selection.split_manifest_checksum,
        false_positive_rate_limit=selection.false_positive_rate_limit,
        labels=np.asarray(validation_labels, dtype=np.int64),
        raw_scores=np.asarray(validation_raw_scores, dtype=np.float64),
        normalized_scores=np.asarray(validation_normalized_scores, dtype=np.float64),
        threshold_results=selected_candidate.threshold_results,
    )


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
