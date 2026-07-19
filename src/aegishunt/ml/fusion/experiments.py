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
    FusionSelectionRecord,
    MetricInterval,
)
from aegishunt.ml.fusion.dataset import (
    ControlledExperimentDataset,
    ExperimentPartition,
    build_parameter_shift_partition,
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
        validation_only=True,
    )


def evaluate_partition(
    partition: ExperimentPartition,
    *,
    kind: ExperimentKind,
    scenario_id: str,
    engines: FittedExperimentalEngines,
    selection: FusionSelectionRecord,
    config: FusionExperimentConfig,
    held_out_family: str | None = None,
    shift_axis: str | None = None,
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
        supervised=supervised,
        anomaly=anomaly,
        fusion=fusion,
        confidence_intervals=intervals,
        fusion_minus_supervised=metric_deltas(fusion.metrics, supervised.metrics),
        fusion_minus_anomaly=metric_deltas(fusion.metrics, anomaly.metrics),
        delta_confidence_intervals=delta_intervals,
        fpr_ceiling_satisfied=fusion.satisfies_fpr_ceiling,
        recommendation_status=selection.recommendation_status,
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
    )
    shifts = tuple(
        evaluate_partition(
            build_parameter_shift_partition(evaluation, shift),
            kind="parameter_shift",
            scenario_id=shift.shift_id,
            engines=engines,
            selection=selection,
            config=fusion_config,
            shift_axis=shift.axis,
        )
        for shift in fusion_config.parameter_shifts
    )
    return FusionExperimentRun(
        selection=selection,
        known=known,
        leave_one_family_out=tuple(loao),
        temporal=temporal,
        parameter_shifts=shifts,
        latency=_measure_latency(
            engines,
            evaluation,
            selection,
            repetitions=fusion_config.latency_repetitions,
        ),
    )
