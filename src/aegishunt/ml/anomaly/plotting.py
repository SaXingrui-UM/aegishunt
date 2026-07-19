"""Validation-only anomaly plot generation for ignored experiment artifacts."""

from __future__ import annotations

import hashlib
import io
from collections.abc import Sequence

import numpy as np
from matplotlib.backends.backend_agg import FigureCanvasAgg
from matplotlib.figure import Figure
from numpy.typing import NDArray

from aegishunt.ml.anomaly.artifacts import AnomalyExperimentStore
from aegishunt.ml.anomaly.contracts import ThresholdResult
from aegishunt.ml.anomaly.errors import AnomalyArtifactError

PLOT_NOTICE = "Controlled synthetic pipeline verification only"


def _validated_scores(
    labels: NDArray[np.int64],
    raw_scores: NDArray[np.float64],
    normalized_scores: NDArray[np.float64],
) -> tuple[NDArray[np.int64], NDArray[np.float64], NDArray[np.float64]]:
    validated_labels = np.asarray(labels, dtype=np.int64)
    validated_raw = np.asarray(raw_scores, dtype=np.float64)
    validated_normalized = np.asarray(normalized_scores, dtype=np.float64)
    if (
        validated_labels.ndim != 1
        or not len(validated_labels)
        or validated_raw.shape != validated_labels.shape
        or validated_normalized.shape != validated_labels.shape
    ):
        raise AnomalyArtifactError("anomaly plots require aligned validation score vectors")
    if not np.isfinite(validated_raw).all() or not np.isfinite(validated_normalized).all():
        raise AnomalyArtifactError("anomaly plots require finite validation scores")
    if np.any((validated_normalized < 0.0) | (validated_normalized > 1.0)):
        raise AnomalyArtifactError("normalized anomaly plot scores must be bounded")
    if set(validated_labels.tolist()) != {0, 1}:
        raise AnomalyArtifactError("anomaly plots require benign and anomaly validation rows")
    return validated_labels, validated_raw, validated_normalized


def _bins(values: NDArray[np.float64]) -> NDArray[np.float64]:
    minimum = float(np.min(values))
    maximum = float(np.max(values))
    if minimum == maximum:
        padding = max(abs(minimum) * 0.05, 0.5)
        minimum -= padding
        maximum += padding
    return np.linspace(minimum, maximum, num=min(16, max(6, len(values) + 1)))


def _new_figure() -> Figure:
    return Figure(figsize=(8.0, 4.8), dpi=120, constrained_layout=True)


def _encode_png(figure: Figure) -> bytes:
    output = io.BytesIO()
    FigureCanvasAgg(figure)
    figure.savefig(
        output,
        format="png",
        metadata={"Software": "AegisHunt Phase 6 validation plot generator"},
    )
    return output.getvalue()


def _annotate(
    figure: Figure,
    *,
    experiment_id: str,
    feature_schema_version: str,
    selected_threshold: float,
    selected_candidate_id: str,
    dataset_manifest_checksum: str,
    split_manifest_checksum: str,
) -> None:
    figure.text(
        0.5,
        0.01,
        (
            f"{PLOT_NOTICE} | experiment={experiment_id} | "
            f"candidate={selected_candidate_id} | feature_schema={feature_schema_version} | "
            f"threshold={selected_threshold:g} | dataset={dataset_manifest_checksum[:12]} | "
            f"split={split_manifest_checksum[:12]}"
        ),
        ha="center",
        fontsize=7,
    )


def _distribution_plot(
    values: NDArray[np.float64],
    labels: NDArray[np.int64],
    *,
    title: str,
    x_label: str,
    experiment_id: str,
    feature_schema_version: str,
    selected_threshold: float,
    selected_candidate_id: str,
    dataset_manifest_checksum: str,
    split_manifest_checksum: str,
    threshold_line: bool,
) -> bytes:
    figure = _new_figure()
    axes = figure.subplots()
    axes.hist(
        (values[labels == 0], values[labels == 1]),
        bins=_bins(values),
        label=("benign validation", "anomaly validation"),
        color=("#2B6CB0", "#C53030"),
        alpha=0.72,
        edgecolor="white",
    )
    if threshold_line:
        axes.axvline(
            selected_threshold,
            color="#1A202C",
            linestyle="--",
            linewidth=1.8,
            label=f"selected threshold {selected_threshold:g}",
        )
    axes.set_title(title)
    axes.set_xlabel(x_label)
    axes.set_ylabel("Validation row count")
    axes.legend()
    axes.grid(axis="y", alpha=0.25)
    _annotate(
        figure,
        experiment_id=experiment_id,
        feature_schema_version=feature_schema_version,
        selected_threshold=selected_threshold,
        selected_candidate_id=selected_candidate_id,
        dataset_manifest_checksum=dataset_manifest_checksum,
        split_manifest_checksum=split_manifest_checksum,
    )
    return _encode_png(figure)


def _threshold_plot(
    threshold_results: Sequence[ThresholdResult],
    *,
    experiment_id: str,
    feature_schema_version: str,
    selected_threshold: float,
    selected_candidate_id: str,
    dataset_manifest_checksum: str,
    split_manifest_checksum: str,
) -> bytes:
    if not threshold_results:
        raise AnomalyArtifactError("threshold sensitivity plot requires validation evidence")
    thresholds = np.asarray([item.threshold for item in threshold_results], dtype=np.float64)
    fprs = np.asarray(
        [item.metrics.benign_false_positive_rate for item in threshold_results],
        dtype=np.float64,
    )
    recalls = np.asarray([item.metrics.recall for item in threshold_results], dtype=np.float64)
    f1_values = np.asarray([item.metrics.f1 for item in threshold_results], dtype=np.float64)
    if not all(np.isfinite(values).all() for values in (thresholds, fprs, recalls, f1_values)):
        raise AnomalyArtifactError("threshold sensitivity plot requires finite evidence")
    if not np.any(np.isclose(thresholds, selected_threshold, rtol=0.0, atol=1e-12)):
        raise AnomalyArtifactError("selected threshold is absent from sensitivity evidence")

    figure = _new_figure()
    axes = figure.subplots()
    axes.plot(thresholds, fprs, marker="o", label="benign FPR", color="#2B6CB0")
    axes.plot(thresholds, recalls, marker="o", label="anomaly recall", color="#C53030")
    axes.plot(thresholds, f1_values, marker="o", label="anomaly F1", color="#2F855A")
    axes.axvline(
        selected_threshold,
        color="#1A202C",
        linestyle="--",
        linewidth=1.8,
        label=f"selected threshold {selected_threshold:g}",
    )
    axes.set_title("Validation threshold sensitivity")
    axes.set_xlabel("Normalized anomaly-score threshold")
    axes.set_ylabel("Metric value")
    axes.set_ylim(-0.02, 1.02)
    axes.legend()
    axes.grid(alpha=0.25)
    _annotate(
        figure,
        experiment_id=experiment_id,
        feature_schema_version=feature_schema_version,
        selected_threshold=selected_threshold,
        selected_candidate_id=selected_candidate_id,
        dataset_manifest_checksum=dataset_manifest_checksum,
        split_manifest_checksum=split_manifest_checksum,
    )
    return _encode_png(figure)


def _focused_threshold_plot(
    threshold_results: Sequence[ThresholdResult],
    *,
    mode: str,
    experiment_id: str,
    feature_schema_version: str,
    selected_threshold: float,
    selected_candidate_id: str,
    dataset_manifest_checksum: str,
    split_manifest_checksum: str,
    false_positive_rate_limit: float,
) -> bytes:
    if not threshold_results:
        raise AnomalyArtifactError("focused threshold plot requires validation evidence")
    thresholds = np.asarray([item.threshold for item in threshold_results], dtype=np.float64)
    figure = _new_figure()
    axes = figure.subplots()
    if mode == "fpr":
        fprs = np.asarray(
            [item.metrics.benign_false_positive_rate for item in threshold_results],
            dtype=np.float64,
        )
        axes.plot(thresholds, fprs, marker="o", color="#2B6CB0", label="benign FPR")
        axes.axhline(
            false_positive_rate_limit,
            color="#C53030",
            linestyle=":",
            label=f"FPR ceiling {false_positive_rate_limit:g}",
        )
        axes.set_title("Validation benign FPR versus threshold")
        axes.set_ylabel("Benign false-positive rate")
    elif mode == "utility":
        axes.plot(
            thresholds,
            [item.metrics.f1 for item in threshold_results],
            marker="o",
            color="#2F855A",
            label="anomaly F1",
        )
        axes.plot(
            thresholds,
            [item.metrics.recall for item in threshold_results],
            marker="o",
            color="#C53030",
            label="anomaly recall",
        )
        axes.plot(
            thresholds,
            [item.metrics.balanced_accuracy for item in threshold_results],
            marker="o",
            color="#805AD5",
            label="balanced accuracy",
        )
        axes.set_title("Validation anomaly utility versus threshold")
        axes.set_ylabel("Validation metric")
    else:
        raise AnomalyArtifactError("unknown focused threshold plot mode")
    axes.axvline(
        selected_threshold,
        color="#1A202C",
        linestyle="--",
        label=f"selected threshold {selected_threshold:g}",
    )
    axes.set_xlabel("Normalized anomaly-score threshold")
    axes.set_ylim(-0.02, 1.02)
    axes.grid(alpha=0.25)
    axes.legend()
    _annotate(
        figure,
        experiment_id=experiment_id,
        feature_schema_version=feature_schema_version,
        selected_threshold=selected_threshold,
        selected_candidate_id=selected_candidate_id,
        dataset_manifest_checksum=dataset_manifest_checksum,
        split_manifest_checksum=split_manifest_checksum,
    )
    return _encode_png(figure)


def write_validation_plots(
    store: AnomalyExperimentStore,
    *,
    experiment_id: str,
    feature_schema_version: str,
    selected_threshold: float,
    selected_candidate_id: str,
    dataset_manifest_checksum: str,
    split_manifest_checksum: str,
    false_positive_rate_limit: float,
    labels: NDArray[np.int64],
    raw_scores: NDArray[np.float64],
    normalized_scores: NDArray[np.float64],
    threshold_results: Sequence[ThresholdResult],
) -> dict[str, object]:
    """Write real validation plots and a checksum manifest under the experiment root."""

    validated_labels, validated_raw, validated_normalized = _validated_scores(
        labels, raw_scores, normalized_scores
    )
    if not np.isfinite(selected_threshold) or not 0.0 <= selected_threshold <= 1.0:
        raise AnomalyArtifactError("selected anomaly plot threshold must be finite and bounded")

    payloads = {
        "raw_score_distribution.png": _distribution_plot(
            validated_raw,
            validated_labels,
            title="Validation raw model-score distribution",
            x_label="sklearn score_samples (higher means more normal)",
            experiment_id=experiment_id,
            feature_schema_version=feature_schema_version,
            selected_threshold=selected_threshold,
            selected_candidate_id=selected_candidate_id,
            dataset_manifest_checksum=dataset_manifest_checksum,
            split_manifest_checksum=split_manifest_checksum,
            threshold_line=False,
        ),
        "normalized_score_distribution.png": _distribution_plot(
            validated_normalized,
            validated_labels,
            title="Validation normalized anomaly-score distribution",
            x_label="Normalized anomaly score (not probability)",
            experiment_id=experiment_id,
            feature_schema_version=feature_schema_version,
            selected_threshold=selected_threshold,
            selected_candidate_id=selected_candidate_id,
            dataset_manifest_checksum=dataset_manifest_checksum,
            split_manifest_checksum=split_manifest_checksum,
            threshold_line=True,
        ),
        "threshold_sensitivity.png": _threshold_plot(
            threshold_results,
            experiment_id=experiment_id,
            feature_schema_version=feature_schema_version,
            selected_threshold=selected_threshold,
            selected_candidate_id=selected_candidate_id,
            dataset_manifest_checksum=dataset_manifest_checksum,
            split_manifest_checksum=split_manifest_checksum,
        ),
        "benign_fpr_vs_threshold.png": _focused_threshold_plot(
            threshold_results,
            mode="fpr",
            experiment_id=experiment_id,
            feature_schema_version=feature_schema_version,
            selected_threshold=selected_threshold,
            selected_candidate_id=selected_candidate_id,
            dataset_manifest_checksum=dataset_manifest_checksum,
            split_manifest_checksum=split_manifest_checksum,
            false_positive_rate_limit=false_positive_rate_limit,
        ),
        "anomaly_utility_vs_threshold.png": _focused_threshold_plot(
            threshold_results,
            mode="utility",
            experiment_id=experiment_id,
            feature_schema_version=feature_schema_version,
            selected_threshold=selected_threshold,
            selected_candidate_id=selected_candidate_id,
            dataset_manifest_checksum=dataset_manifest_checksum,
            split_manifest_checksum=split_manifest_checksum,
            false_positive_rate_limit=false_positive_rate_limit,
        ),
    }
    artifacts: list[dict[str, str]] = []
    for filename, payload in payloads.items():
        store.write_bytes(filename, payload)
        artifacts.append(
            {
                "filename": filename,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    manifest: dict[str, object] = {
        "schema_version": "1.1.0",
        "experiment_id": experiment_id,
        "evidence_partition": "validation",
        "dataset_notice": PLOT_NOTICE,
        "feature_schema_version": feature_schema_version,
        "selected_candidate_id": selected_candidate_id,
        "selected_threshold": selected_threshold,
        "false_positive_rate_limit": false_positive_rate_limit,
        "dataset_manifest_checksum": dataset_manifest_checksum,
        "split_manifest_checksum": split_manifest_checksum,
        "frozen_test_accessed": False,
        "artifacts": artifacts,
    }
    store.write_json("validation_plot_manifest.json", manifest)
    return manifest
