"""Known, unknown-family, temporal, and parameter-shift experiments."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.fusion.bootstrap import (
    group_bootstrap_delta_intervals,
    group_bootstrap_intervals,
)
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.contracts import (
    CandidateEvaluation,
    ComparisonResult,
    ExperimentIsolationAudit,
    FeatureRange,
    FusionSelectionRecord,
    MetricInterval,
    ParameterShiftAudit,
    ScoreDistributionEvidence,
)
from aegishunt.ml.fusion.dataset import (
    ControlledExperimentDataset,
    ExperimentPartition,
    build_parameter_shift_partition,
    parameter_shift_features,
)
from aegishunt.ml.fusion.engines import FittedExperimentalEngines, fit_experimental_engines
from aegishunt.ml.fusion.metrics import evaluate_scores, metric_deltas
from aegishunt.ml.fusion.scoring import weighted_score
from aegishunt.ml.fusion.selection import select_fusion_policy
from aegishunt.ml.supervised.config import SupervisedTrainingConfig

ExperimentKind = Literal[
    "known_attack",
    "leave_one_family_out",
    "temporal_holdout",
    "parameter_shift",
]


@dataclass(frozen=True, slots=True)
class FusionExperimentRun:
    """All actual Phase 7 evidence retained regardless of result direction."""

    selection: FusionSelectionRecord
    known: ComparisonResult
    leave_one_family_out: tuple[ComparisonResult, ...]
    temporal: ComparisonResult
    parameter_shifts: tuple[ComparisonResult, ...]
    latency: dict[str, float | int | bool]


def _fused_scores(
    supervised: NDArray[np.float64],
    anomaly: NDArray[np.float64],
    selection: FusionSelectionRecord,
) -> NDArray[np.float64]:
    return np.asarray(
        [
            weighted_score(
                float(supervised_value),
                float(anomaly_value),
                selection.selected_weights,
            )
            for supervised_value, anomaly_value in zip(supervised, anomaly, strict=True)
        ],
        dtype=np.float64,
    )


def _candidate(
    *,
    candidate_id: str,
    mode: Literal["supervised_only", "anomaly_only", "dual_engine_fusion"],
    labels: NDArray[np.int64],
    scores: NDArray[np.float64],
    threshold: float,
    selection: FusionSelectionRecord,
) -> CandidateEvaluation:
    metrics = evaluate_scores(labels, scores, threshold=threshold)
    return CandidateEvaluation(
        candidate_id=candidate_id,
        mode=mode,
        weights=selection.selected_weights if mode == "dual_engine_fusion" else None,
        threshold=threshold,
        metrics=metrics,
        satisfies_fpr_ceiling=(
            metrics.benign_false_positive_rate <= selection.false_positive_rate_ceiling
        ),
        selection_used_validation_only=True,
    )


def _identity_overlap(
    partitions: tuple[ExperimentPartition, ...], attribute: str
) -> tuple[str, ...]:
    identities = [
        {str(getattr(row.metadata, attribute)) for row in partition.rows}
        for partition in partitions
    ]
    return tuple(
        sorted(
            {
                identity
                for index, left in enumerate(identities)
                for right in identities[index + 1 :]
                for identity in left & right
            }
        )
    )


def _isolation_audit(
    train: ExperimentPartition,
    validation: ExperimentPartition,
    evaluation: ExperimentPartition,
    *,
    held_out_family: str | None,
) -> ExperimentIsolationAudit:
    partitions = (train, validation, evaluation)
    return ExperimentIsolationAudit(
        train_rows=len(train.rows),
        validation_rows=len(validation.rows),
        evaluation_rows=len(evaluation.rows),
        train_groups=len(set(train.groups.tolist())),
        validation_groups=len(set(validation.groups.tolist())),
        evaluation_groups=len(set(evaluation.groups.tolist())),
        group_overlap=_identity_overlap(partitions, "group_id"),
        source_overlap=_identity_overlap(partitions, "source_file"),
        session_overlap=_identity_overlap(partitions, "capture_session_id"),
        scenario_overlap=_identity_overlap(partitions, "scenario_id"),
        held_out_family_absent_from_train=(
            held_out_family not in set(train.families.tolist())
            if held_out_family is not None
            else None
        ),
        held_out_family_absent_from_validation=(
            held_out_family not in set(validation.families.tolist())
            if held_out_family is not None
            else None
        ),
        metadata_and_labels_excluded_from_features=True,
        future_data_used_for_fit=False,
    )


def _distribution(
    scores: NDArray[np.float64],
    labels: NDArray[np.int64],
    sample_class: Literal["benign", "attack"],
) -> ScoreDistributionEvidence:
    values = scores[labels == (0 if sample_class == "benign" else 1)]
    if not len(values):
        raise ValueError("score distribution class is empty")
    return ScoreDistributionEvidence(
        sample_class=sample_class,
        count=len(values),
        minimum=float(np.min(values)),
        maximum=float(np.max(values)),
        mean=float(np.mean(values)),
        standard_deviation=float(np.std(values)),
        q25=float(np.quantile(values, 0.25)),
        median=float(np.median(values)),
        q75=float(np.quantile(values, 0.75)),
    )


def _score_distributions(
    labels: NDArray[np.int64],
    supervised: NDArray[np.float64],
    anomaly: NDArray[np.float64],
    fusion: NDArray[np.float64],
) -> dict[str, ScoreDistributionEvidence]:
    sample_classes: tuple[Literal["benign", "attack"], ...] = ("benign", "attack")
    return {
        f"{mode}.{sample_class}": _distribution(scores, labels, sample_class)
        for mode, scores in (
            ("supervised", supervised),
            ("anomaly", anomaly),
            ("fusion", fusion),
        )
        for sample_class in sample_classes
    }


def _parameter_shift_audit(
    base: ExperimentPartition,
    shifted: ExperimentPartition,
    *,
    shift_id: str,
    axis: Literal[
        "flow_duration",
        "packet_rate",
        "packet_size_pattern",
        "connection_frequency",
    ],
    factor: float,
) -> ParameterShiftAudit:
    names = tuple(row for row in parameter_shift_features(axis))
    all_feature_names = base.rows[0].features.names
    positions = {name: all_feature_names.index(name) for name in names}

    def ranges(partition: ExperimentPartition) -> dict[str, FeatureRange]:
        return {
            name: FeatureRange(
                minimum=float(np.min(partition.features[:, position])),
                maximum=float(np.max(partition.features[:, position])),
            )
            for name, position in positions.items()
        }

    return ParameterShiftAudit(
        shift_id=shift_id,
        axis=axis,
        factor=factor,
        relevant_features=names,
        base_ranges=ranges(base),
        shifted_ranges=ranges(shifted),
        base_group_count=len(set(base.groups.tolist())),
        shifted_group_count=len(set(shifted.groups.tolist())),
        group_overlap=tuple(sorted(set(base.groups.tolist()) & set(shifted.groups.tolist()))),
        result_driven_expansion=False,
        safe_bounded_simulation=True,
        network_access=False,
        external_target=False,
    )


def evaluate_partition(
    partition: ExperimentPartition,
    *,
    kind: ExperimentKind,
    scenario_id: str,
    engines: FittedExperimentalEngines,
    selection: FusionSelectionRecord,
    config: FusionExperimentConfig,
    train_partition: ExperimentPartition,
    validation_partition: ExperimentPartition,
    held_out_family: str | None = None,
    shift_axis: str | None = None,
    parameter_shift_audit: ParameterShiftAudit | None = None,
) -> ComparisonResult:
    """Evaluate all modes on exactly the same rows without changing the policy."""

    scores = engines.score(partition)
    fusion_scores = _fused_scores(scores.supervised, scores.anomaly, selection)
    supervised = _candidate(
        candidate_id="supervised-only",
        mode="supervised_only",
        labels=partition.labels,
        scores=scores.supervised,
        threshold=engines.supervised_threshold,
        selection=selection,
    )
    anomaly = _candidate(
        candidate_id="anomaly-only",
        mode="anomaly_only",
        labels=partition.labels,
        scores=scores.anomaly,
        threshold=engines.anomaly_threshold,
        selection=selection,
    )
    fusion = _candidate(
        candidate_id=selection.selected_candidate_id,
        mode="dual_engine_fusion",
        labels=partition.labels,
        scores=fusion_scores,
        threshold=selection.selected_threshold,
        selection=selection,
    )
    intervals: dict[str, MetricInterval] = {}
    for prefix, values, threshold in (
        ("supervised", scores.supervised, engines.supervised_threshold),
        ("anomaly", scores.anomaly, engines.anomaly_threshold),
        ("fusion", fusion_scores, selection.selected_threshold),
    ):
        for name, interval in group_bootstrap_intervals(
            partition.labels,
            values,
            partition.groups,
            threshold=threshold,
            draws=config.bootstrap_draws,
            random_seed=config.bootstrap_seed,
        ).items():
            intervals[f"{prefix}.{name}"] = interval
    delta_intervals: dict[str, MetricInterval] = {}
    for prefix, baseline_scores, baseline_threshold in (
        ("supervised", scores.supervised, engines.supervised_threshold),
        ("anomaly", scores.anomaly, engines.anomaly_threshold),
    ):
        for name, interval in group_bootstrap_delta_intervals(
            partition.labels,
            fusion_scores,
            baseline_scores,
            partition.groups,
            fusion_threshold=selection.selected_threshold,
            baseline_threshold=baseline_threshold,
            draws=config.bootstrap_draws,
            random_seed=config.bootstrap_seed + 1,
        ).items():
            delta_intervals[f"fusion_minus_{prefix}.{name}"] = interval
    return ComparisonResult(
        experiment_kind=kind,
        scenario_id=scenario_id,
        held_out_family=held_out_family,
        shift_axis=shift_axis,
        row_count=len(partition.rows),
        groups=tuple(sorted(set(partition.groups.tolist()))),
        family_distribution=dict(sorted(Counter(partition.families.tolist()).items())),
        isolation=_isolation_audit(
            train_partition,
            validation_partition,
            partition,
            held_out_family=held_out_family,
        ),
        supervised=supervised,
        anomaly=anomaly,
        fusion=fusion,
        score_distributions=_score_distributions(
            partition.labels,
            scores.supervised,
            scores.anomaly,
            fusion_scores,
        ),
        confidence_intervals=intervals,
        fusion_minus_supervised=metric_deltas(fusion.metrics, supervised.metrics),
        fusion_minus_anomaly=metric_deltas(fusion.metrics, anomaly.metrics),
        delta_confidence_intervals=delta_intervals,
        fpr_ceiling_satisfied=fusion.satisfies_fpr_ceiling,
        recommendation_status=selection.recommendation_status,
        parameter_shift_audit=parameter_shift_audit,
        limitations=(
            "controlled synthetic pipeline verification only; not a public benchmark",
            "fusion score is not probability, risk, severity, or attack confirmation",
        ),
    )


def _fit_and_select(
    train: ExperimentPartition,
    validation: ExperimentPartition,
    *,
    fusion_config: FusionExperimentConfig,
    supervised_config: SupervisedTrainingConfig,
    anomaly_config: AnomalyTrainingConfig,
) -> tuple[FittedExperimentalEngines, FusionSelectionRecord]:
    engines, validation_scores = fit_experimental_engines(
        train,
        validation,
        fusion_config=fusion_config,
        supervised_config=supervised_config,
        anomaly_config=anomaly_config,
    )
    selection = select_fusion_policy(
        labels=validation.labels,
        groups=validation.groups,
        supervised_scores=validation_scores.supervised,
        anomaly_scores=validation_scores.anomaly,
        supervised_threshold=engines.supervised_threshold,
        anomaly_threshold=engines.anomaly_threshold,
        config=fusion_config,
        created_at=fusion_config.protocol_frozen_at,
    )
    return engines, selection


def _percentile(values: list[float], percentile: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=np.float64), percentile))


def _measure_latency(
    engines: FittedExperimentalEngines,
    partition: ExperimentPartition,
    selection: FusionSelectionRecord,
    *,
    repetitions: int,
) -> dict[str, float | int | bool]:
    engines.score(partition)
    supervised_ms: list[float] = []
    anomaly_ms: list[float] = []
    fusion_ms: list[float] = []
    total_ms: list[float] = []
    deterministic = True
    expected = engines.score(partition)
    for _ in range(repetitions):
        total_started = time.perf_counter()
        started = time.perf_counter()
        supervised = engines.score_supervised(partition)
        supervised_ms.append((time.perf_counter() - started) * 1_000)
        started = time.perf_counter()
        anomaly = engines.score_anomaly(partition)
        anomaly_ms.append((time.perf_counter() - started) * 1_000)
        started = time.perf_counter()
        _fused_scores(supervised, anomaly, selection)
        fusion_ms.append((time.perf_counter() - started) * 1_000)
        total_ms.append((time.perf_counter() - total_started) * 1_000)
        deterministic = deterministic and np.array_equal(supervised, expected.supervised)
        deterministic = deterministic and np.array_equal(anomaly, expected.anomaly)
    batch_size = len(partition.rows)
    total_seconds = sum(total_ms) / 1_000
    supervised_size, anomaly_size = engines.temporary_serialized_sizes()
    return {
        "batch_size": batch_size,
        "repetitions": repetitions,
        "supervised_batch_p50_ms": _percentile(supervised_ms, 50),
        "anomaly_batch_p50_ms": _percentile(anomaly_ms, 50),
        "fusion_batch_p50_ms": _percentile(fusion_ms, 50),
        "dual_batch_p50_ms": _percentile(total_ms, 50),
        "dual_batch_p95_ms": _percentile(total_ms, 95),
        "dual_batch_p99_ms": _percentile(total_ms, 99),
        "per_sample_p50_ms": _percentile(total_ms, 50) / batch_size,
        "throughput_samples_per_second": batch_size * repetitions / total_seconds,
        "temporary_supervised_model_size_bytes": supervised_size,
        "temporary_anomaly_model_size_bytes": anomaly_size,
        "deterministic_scoring": deterministic,
        "controlled_environment_only": True,
    }


def run_experiments(
    dataset: ControlledExperimentDataset,
    *,
    fusion_config: FusionExperimentConfig,
    supervised_config: SupervisedTrainingConfig,
    anomaly_config: AnomalyTrainingConfig,
) -> FusionExperimentRun:
    """Run every pre-registered experiment without historical test access."""

    train = dataset.stage("early")
    validation = dataset.stage("middle")
    evaluation = dataset.stage("late")
    engines, selection = _fit_and_select(
        train,
        validation,
        fusion_config=fusion_config,
        supervised_config=supervised_config,
        anomaly_config=anomaly_config,
    )
    known = evaluate_partition(
        evaluation,
        kind="known_attack",
        scenario_id="known-late-groups",
        engines=engines,
        selection=selection,
        config=fusion_config,
        train_partition=train,
        validation_partition=validation,
    )
    loao: list[ComparisonResult] = []
    for family in dataset.eligible_attack_families:
        family_train, family_validation, family_evaluation = dataset.leave_one_family_out(family)
        family_engines, family_selection = _fit_and_select(
            family_train,
            family_validation,
            fusion_config=fusion_config,
            supervised_config=supervised_config,
            anomaly_config=anomaly_config,
        )
        loao.append(
            evaluate_partition(
                family_evaluation,
                kind="leave_one_family_out",
                scenario_id=f"loao-{family}",
                engines=family_engines,
                selection=family_selection,
                config=fusion_config,
                train_partition=family_train,
                validation_partition=family_validation,
                held_out_family=family,
            )
        )
    temporal = evaluate_partition(
        evaluation,
        kind="temporal_holdout",
        scenario_id="early-middle-late-controlled-timeline",
        engines=engines,
        selection=selection,
        config=fusion_config,
        train_partition=train,
        validation_partition=validation,
    )
    shift_results: list[ComparisonResult] = []
    for shift in fusion_config.parameter_shifts:
        shifted = build_parameter_shift_partition(evaluation, shift)
        shift_results.append(
            evaluate_partition(
                shifted,
                kind="parameter_shift",
                scenario_id=shift.shift_id,
                engines=engines,
                selection=selection,
                config=fusion_config,
                train_partition=train,
                validation_partition=validation,
                shift_axis=shift.axis,
                parameter_shift_audit=_parameter_shift_audit(
                    evaluation,
                    shifted,
                    shift_id=shift.shift_id,
                    axis=shift.axis,
                    factor=shift.factor,
                ),
            )
        )
    return FusionExperimentRun(
        selection=selection,
        known=known,
        leave_one_family_out=tuple(loao),
        temporal=temporal,
        parameter_shifts=tuple(shift_results),
        latency=_measure_latency(
            engines,
            evaluation,
            selection,
            repetitions=fusion_config.latency_repetitions,
        ),
    )
