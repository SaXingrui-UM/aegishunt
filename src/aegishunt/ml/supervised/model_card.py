"""Research-bound model-card rendering from actual experiment evidence."""

from __future__ import annotations

from aegishunt.datasets.reports import DatasetManifest, SplitManifest
from aegishunt.ml.supervised.contracts import FrozenTestReport, ModelSelectionRecord


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
        "false_positive_rate",
        "false_negative_rate",
    )
    return "\n".join(f"| {name} | {getattr(metrics, name)} |" for name in names)


def render_model_card(
    selection: ModelSelectionRecord,
    frozen: FrozenTestReport,
    dataset: DatasetManifest,
    split: SplitManifest,
) -> str:
    """Render a model card that never promotes controlled-demo results as conclusions."""

    marker = (
        "**PIPELINE VERIFICATION ONLY — controlled synthetic demo metrics are not "
        "research, production, or real-world performance evidence.**"
        if selection.pipeline_verification_only
        else "Evaluation uses the registered benchmark described below."
    )
    feature_summary = (
        f"`{selection.feature_schema_version}` ({len(selection.feature_names)} float64 features)"
    )
    row_summary = ", ".join(
        f"{name} {split.row_counts[name]}" for name in ("train", "validation", "test")
    )
    group_summary = ", ".join(
        f"{name} {split.group_counts[name]}" for name in ("train", "validation", "test")
    )
    bootstrap_draws = min(
        interval.successful_iterations for interval in frozen.confidence_intervals.values()
    )
    latency_summary = " / ".join(
        f"{value:.6f}"
        for value in (
            selection.operational_metrics.batch_latency_p50_ms,
            selection.operational_metrics.batch_latency_p95_ms,
            selection.operational_metrics.batch_latency_p99_ms,
        )
    )
    return f"""# AegisHunt Supervised Model Card

{marker}

## Model details

- Model ID: `{selection.model_id}`
- Version: `{selection.model_version}`
- Algorithm: `{selection.algorithm}`
- Model type: supervised binary classifier
- Status: validated research prototype
- Feature schema: {feature_summary}
- Preprocessing version: `{selection.preprocessing_version}`
- Label mapping version: `{selection.label_mapping_version}`

## Intended use

Offline research on known benign/attack patterns represented by the training distribution. The
model is not an autonomous enforcement control. It does not guarantee zero-day detection, and its
calibrated output is not the real-world probability that an attack occurred.

## Out-of-scope use

Do not use this model as a sole production blocking control, as a vulnerability scanner, for live
capture, or as evidence that every network environment is covered. Phase 5 does not create alerts,
severity, fusion risk, anomaly scores, MITRE mappings, or threat hypotheses.

## Data and provenance

- Dataset: `{dataset.dataset_id}` version `{dataset.dataset_version}`
- Dataset type: `{dataset.dataset_type}`
- Provider: {dataset.provider}
- License: {dataset.license_name}
- Source: {dataset.source}
- Split strategy: {split.split_strategy}; group key `{split.group_key}`
- Rows: {row_summary}
- Groups: {group_summary}

The test split remained frozen until algorithm, hyperparameters, preprocessing, calibration, and
threshold were written to `model_selection.json`. Test metrics did not affect model selection.

## Training and selection

- Group-aware CV: training partition only
- Validation use: candidate comparison, calibration, and threshold selection
- Test use: one frozen final evaluation only
- Hyperparameters: `{selection.hyperparameters}`
- Imbalance handling: candidate-configured class weights; no resampling
- Calibration: `{selection.calibration_method}`, selected on validation Brier score
- Classification threshold: `{selection.threshold}`; validation Macro F1 with recall/FPR tie breaks
- Selection policy: `{selection.selection_policy_version}`; Accuracy was not a ranking key

## Validation metrics

| Metric | Value |
| --- | ---: |
{_metric_rows(selection.validation_metrics)}

## Frozen test metrics

| Metric | Value |
| --- | ---: |
{_metric_rows(frozen.metrics)}

Group-bootstrap 95% intervals used {bootstrap_draws}
or more successful draws per reported metric with the configured fixed seed.

## Operational observations

- Training duration: {selection.operational_metrics.training_duration_seconds:.6f} seconds
- Batch latency p50/p95/p99: {latency_summary} ms
- Per-sample p50 latency: {selection.operational_metrics.per_sample_latency_p50_ms:.6f} ms
- Throughput: {selection.operational_metrics.throughput_samples_per_second:.3f} samples/second
- Serialized preprocessing + model size: {selection.operational_metrics.serialized_size_bytes} bytes
- Peak traced prediction memory: {selection.operational_metrics.peak_memory_bytes} bytes

These measurements describe one development environment and are not a production SLA.

## Limitations and known failure modes

- Controlled synthetic data does not establish benchmark or deployment performance.
- Domain shift, unseen protocols, capture differences, and novel attacks may degrade performance.
- Probability calibration is distribution-dependent and is not causal evidence.
- Feature importance, if added later, would not establish causality.
- The fixed Phase 3 feature contract limits the model to its declared flow-level evidence.
- A fully unavailable database still cannot record its own failure (existing DEF-004; non-blocking).

## Security, ethics, and reproducibility

The bundle uses a checksummed skops artifact with an exact type inventory, rejects arbitrary
pickle/joblib input, and rejects schema drift. Reproduction requires the recorded dataset and split
checksums, seed `{selection.random_seed}`, training-config checksum
`{selection.training_config_checksum}`, and the software versions in the bundle manifest.

Retraining is required after approved feature-schema, label-mapping, material data-distribution, or
dependency compatibility changes. The frozen test must not be reused for iterative optimization.
"""
