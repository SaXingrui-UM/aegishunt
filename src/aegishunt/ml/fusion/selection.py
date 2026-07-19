"""Validation-only fusion weight and threshold selection."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.contracts import (
    CandidateEvaluation,
    FusionSelectionRecord,
    FusionWeights,
    RecommendationStatus,
)
from aegishunt.ml.fusion.errors import FusionSelectionError
from aegishunt.ml.fusion.metrics import evaluate_scores
from aegishunt.ml.fusion.scoring import weighted_score


def _rank(candidate: CandidateEvaluation) -> tuple[float | str, ...]:
    metrics = candidate.metrics
    return (
        float(metrics.macro_f1 > 0.0),
        metrics.macro_f1,
        metrics.recall,
        metrics.pr_auc if metrics.pr_auc is not None else -1.0,
        metrics.balanced_accuracy,
        -metrics.anomaly_false_negative_rate,
        -metrics.benign_false_positive_rate,
        candidate.candidate_id,
    )


def _baseline(
    *,
    candidate_id: str,
    mode: Literal["supervised_only", "anomaly_only"],
    labels: NDArray[np.int64],
    scores: NDArray[np.float64],
    threshold: float,
    fpr_ceiling: float,
) -> CandidateEvaluation:
    if mode not in {"supervised_only", "anomaly_only"}:
        raise FusionSelectionError("baseline mode is invalid")
    metrics = evaluate_scores(labels, scores, threshold=threshold)
    return CandidateEvaluation(
        candidate_id=candidate_id,
        mode=mode,
        weights=None,
        threshold=threshold,
        metrics=metrics,
        satisfies_fpr_ceiling=metrics.benign_false_positive_rate <= fpr_ceiling,
        selection_used_validation_only=True,
    )


def select_fusion_policy(
    *,
    labels: NDArray[np.int64],
    groups: NDArray[np.str_],
    supervised_scores: NDArray[np.float64],
    anomaly_scores: NDArray[np.float64],
    supervised_threshold: float,
    anomaly_threshold: float,
    config: FusionExperimentConfig,
    created_at: datetime | None = None,
) -> FusionSelectionRecord:
    """Freeze one policy using validation vectors only."""

    if (
        labels.ndim != 1
        or labels.shape != groups.shape
        or labels.shape != supervised_scores.shape
        or labels.shape != anomaly_scores.shape
        or not len(labels)
    ):
        raise FusionSelectionError("fusion validation vectors must be aligned")
    if set(labels.tolist()) != {0, 1}:
        raise FusionSelectionError("fusion validation requires both classes")
    supervised = _baseline(
        candidate_id="supervised-only",
        mode="supervised_only",
        labels=labels,
        scores=supervised_scores,
        threshold=supervised_threshold,
        fpr_ceiling=config.false_positive_rate_ceiling,
    )
    anomaly = _baseline(
        candidate_id="anomaly-only",
        mode="anomaly_only",
        labels=labels,
        scores=anomaly_scores,
        threshold=anomaly_threshold,
        fpr_ceiling=config.false_positive_rate_ceiling,
    )
    candidates: list[CandidateEvaluation] = []
    for weight in config.weight_candidates:
        weights = FusionWeights(
            supervised_weight=weight.supervised_weight,
            anomaly_weight=weight.anomaly_weight,
        )
        scores = np.asarray(
            [
                weighted_score(float(supervised_score), float(anomaly_score), weights)
                for supervised_score, anomaly_score in zip(
                    supervised_scores, anomaly_scores, strict=True
                )
            ],
            dtype=np.float64,
        )
        for threshold in config.fusion_threshold_candidates:
            metrics = evaluate_scores(labels, scores, threshold=threshold)
            candidates.append(
                CandidateEvaluation(
                    candidate_id=f"{weight.candidate_id}-t{threshold:.3f}",
                    mode="dual_engine_fusion",
                    weights=weights,
                    threshold=threshold,
                    metrics=metrics,
                    satisfies_fpr_ceiling=(
                        metrics.benign_false_positive_rate
                        <= config.false_positive_rate_ceiling
                    ),
                    selection_used_validation_only=True,
                )
            )
    compliant = tuple(
        item
        for item in candidates
        if item.satisfies_fpr_ceiling and item.metrics.macro_f1 > 0.0
    )
    if not compliant:
        raise FusionSelectionError(
            "no dual-engine candidate satisfies validation FPR and positive utility"
        )
    selected = max(compliant, key=_rank)
    best_baseline = max((supervised, anomaly), key=_rank)
    macro_delta = selected.metrics.macro_f1 - best_baseline.metrics.macro_f1
    fpr_delta = (
        selected.metrics.benign_false_positive_rate
        - best_baseline.metrics.benign_false_positive_rate
    )
    recommendation: RecommendationStatus
    rationale: tuple[str, ...]
    if (
        macro_delta > config.recommendation_min_macro_f1_delta
        and fpr_delta <= config.recommendation_max_fpr_increase
    ):
        recommendation = "fusion_recommended"
        rationale = (
            "validation Macro F1 improved over the best single-engine baseline",
            "validation FPR increase stayed within the pre-registered allowance",
        )
    elif macro_delta < 0.0 or fpr_delta > config.recommendation_max_fpr_increase:
        recommendation = "fusion_not_recommended"
        rationale = (
            "validation fusion did not satisfy the pre-registered improvement rule",
        )
    else:
        recommendation = "inconclusive"
        rationale = (
            "validation evidence did not establish a pre-registered fusion advantage",
        )
    if selected.weights is None:
        raise FusionSelectionError("selected fusion candidate has no weights")
    return FusionSelectionRecord(
        record_schema_version="1.0.0",
        status="validation_frozen",
        experiment_id=config.experiment_id,
        policy_id=config.policy_id,
        policy_version=config.policy_version,
        selected_candidate_id=selected.candidate_id,
        selected_weights=selected.weights,
        selected_threshold=selected.threshold,
        false_positive_rate_ceiling=config.false_positive_rate_ceiling,
        selection_policy_version=config.selection_policy_version,
        candidates=tuple(candidates),
        supervised_baseline=supervised,
        anomaly_baseline=anomaly,
        recommendation_status=recommendation,
        recommendation_rationale=rationale,
        validation_groups=tuple(sorted(set(groups.tolist()))),
        evaluation_data_accessed=False,
        held_out_family_accessed=False,
        created_at=created_at or datetime.now(UTC),
    )
