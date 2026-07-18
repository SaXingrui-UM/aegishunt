"""Evidence-backed Phase 6 anomaly model-card rendering."""

from __future__ import annotations

from aegishunt.datasets.reports import DatasetManifest, SplitManifest
from aegishunt.ml.anomaly.contracts import (
    AnomalyFrozenTestReport,
    AnomalySelectionRecord,
)


def _metric_rows(metrics: object) -> str:
    names = (
        "accuracy",
        "precision",
        "recall",
        "f1",
        "macro_f1",
        "weighted_f1",
        "balanced_accuracy",
        "mcc",
        "roc_auc",
        "pr_auc",
        "specificity",
        "benign_false_positive_rate",
        "anomaly_false_negative_rate",
    )
    return "\n".join(f"| {name} | {getattr(metrics, name)} |" for name in names)


def render_model_card(
    selection: AnomalySelectionRecord,
    frozen: AnomalyFrozenTestReport,
    dataset: DatasetManifest,
    split: SplitManifest,
) -> str:
    """Describe actual evidence without equating anomaly with attack probability."""

    marker = (
        "**CONTROLLED SYNTHETIC PIPELINE VERIFICATION ONLY — not a public benchmark, "
        "production result, or real-world performance claim.**"
        if selection.pipeline_verification_only
        else "Evaluation uses the registered benchmark and license evidence below."
    )
    provenance = (
        "The AegisHunt project generated this controlled fixture offline. No public dataset "
        "license or external benchmark status is claimed."
        if selection.pipeline_verification_only
        else "Dataset provenance and licensing follow the registered provider evidence."
    )
    validation_rows = split.row_counts["validation"]
    test_rows = split.row_counts["test"]
    validation_groups = split.group_counts["validation"]
    test_groups = split.group_counts["test"]
    operational = selection.operational_metrics
    feature_summary = (
        f"`{selection.feature_schema_version}` "
        f"({len(selection.feature_names)} ordered float64 features)"
    )
    benign_training_summary = (
        f"{selection.benign_training_rows} rows / "
        f"{len(selection.benign_training_groups)} groups"
    )
    normalization_summary = (
        f"`{selection.normalizer.method}` version `{selection.normalizer.version}` "
        "using only benign-training scores"
    )
    one_class_svm_summary = (
        f"`{selection.one_class_svm_comparison.status}` — "
        f"{selection.one_class_svm_comparison.limitations[0]}"
    )
    latency_summary = " / ".join(
        f"{value:.6f}"
        for value in (
            operational.batch_latency_p50_ms,
            operational.batch_latency_p95_ms,
            operational.batch_latency_p99_ms,
        )
    )
    bootstrap_draws = min(
        interval.successful_iterations for interval in frozen.confidence_intervals.values()
    )
    return f"""# AegisHunt Anomaly Model Card

{marker}

## Model details

- Model ID: `{selection.model_id}`
- Version: `{selection.model_version}`
- Model type: unsupervised anomaly detector
- Production algorithm: Isolation Forest (`{selection.selected_candidate_id}`)
- Status: validated research prototype
- Feature schema: {feature_summary}
- Preprocessing: `{selection.preprocessing}` fitted on benign training only

## Intended and out-of-scope use

The model identifies flow-feature deviation from its current benign training baseline for offline
research. `is_anomaly` is a thresholded model decision, not confirmation of malicious activity.
The normalized score is bounded but is **not a probability**. Legitimate rare behavior can receive
a high score. This model does not guarantee zero-day detection and must not be a sole production
blocking control.

Phase 6 does not create alerts, severity, supervised/anomaly fusion, reason codes, explanations,
correlation, MITRE mappings, hypotheses, cases, or automated response. Fusion begins in Phase 7.

## Data and research boundary

- Dataset: `{dataset.dataset_id}` version `{dataset.dataset_version}`
- Dataset type: `{dataset.dataset_type}`
- Provider: {dataset.provider}
- License: {dataset.license_name}
- Source: {dataset.source}
- Split strategy: {split.split_strategy}; group key `{split.group_key}`
- Benign training: {benign_training_summary}
- Validation: {validation_rows} rows / {validation_groups} groups
- Frozen test: {test_rows} rows / {test_groups} groups

{provenance}

Only benign rows from the Phase 4 training partition fitted preprocessing, Isolation Forest, and
the score normalizer. Malicious training rows were excluded. Validation labels selected the
candidate and threshold. The frozen test opened once only after selection was checksummed.

## Score and threshold contract

- Raw score: sklearn `score_samples`; larger means more normal
- Canonical transform: `{selection.canonical_score_transform}`; larger means more anomalous
- Normalization: {normalization_summary}
- Normalized range: `[0.0, 1.0]` with explicit clipping; not a probability
- Threshold policy: `{selection.threshold_policy}`
- Validation benign-FPR limit: {selection.false_positive_rate_limit}
- Selected threshold: {selection.threshold}

## Validation metrics

| Metric | Value |
| --- | ---: |
{_metric_rows(selection.validation_metrics)}

## Frozen test metrics

| Metric | Value |
| --- | ---: |
{_metric_rows(frozen.metrics)}

The frozen confusion matrix is {frozen.metrics.confusion_matrix}. Group-resampled 95% confidence
intervals used at least {bootstrap_draws} successful fixed-seed draws per reported metric.

## Comparator evidence

- LOF: `{selection.lof_comparison.status}`; novelty mode, offline only, never production-selected
- One-Class SVM: {one_class_svm_summary}
- Autoencoder: not implemented in Phase 6

## Operational observations

- Training duration: {operational.training_duration_seconds:.6f} seconds
- Batch latency p50/p95/p99: {latency_summary} ms
- Per-sample p50: {operational.per_sample_latency_p50_ms:.6f} ms
- Throughput: {operational.throughput_samples_per_second:.3f} samples/second
- Serialized preprocessing + estimator size: {operational.estimator_serialized_size_bytes} bytes
- Peak traced scoring memory: {operational.peak_memory_bytes} bytes

These development-machine observations are not a production SLA.

## Limitations and known failure modes

- Controlled synthetic evidence cannot establish benchmark or deployment performance.
- The baseline is limited to observed benign training groups;
  domain and concept drift can raise FPR.
- Rare legitimate behavior may look anomalous; familiar attacks may look normal.
- Score normalization is distribution-relative and not probabilistic or causal.
- LOF is sensitive to high dimensionality and scale; One-Class SVM was intentionally omitted.
- A complete database outage still cannot record its own failure in that database (DEF-004).

## Security and reproducibility

The four-file bundle requires exact inventory and SHA-256 checksums, loads only a system-created
skops pipeline with an empty untrusted-type allowlist, and rejects pickle/joblib, schema drift,
missing/extra/corrupt files, and version collisions. Reproduction requires dataset manifest
`{selection.dataset_manifest_checksum}`, split manifest `{selection.split_manifest_checksum}`,
configuration `{selection.training_config_checksum}`, seed `{selection.random_seed}`, feature
schema `{selection.feature_schema_version}`, and the recorded software environment. Do not reuse
the frozen test for iterative optimization; retrain only under a new versioned experiment.
"""
