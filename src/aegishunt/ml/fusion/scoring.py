"""Pure, fail-closed dual-engine score arithmetic."""

from __future__ import annotations

import math
from datetime import UTC, datetime

from aegishunt.ml.fusion.contracts import (
    FusionScoreInput,
    FusionScoreResult,
    FusionWeights,
    PolicyManifest,
)
from aegishunt.ml.fusion.errors import FusionContractError


def weighted_score(
    supervised_probability: float,
    normalized_anomaly_score: float,
    weights: FusionWeights,
) -> float:
    """Return one bounded experimental score; never silently repair input."""

    values = (supervised_probability, normalized_anomaly_score)
    if any(isinstance(value, bool) or not math.isfinite(value) for value in values):
        raise FusionContractError("fusion inputs must be finite numeric scores")
    if any(value < 0.0 or value > 1.0 for value in values):
        raise FusionContractError("fusion inputs must be inside zero and one")
    if not weights.is_dual_engine:
        raise FusionContractError("dual-engine fusion requires two positive weights")
    score = (
        weights.supervised_weight * supervised_probability
        + weights.anomaly_weight * normalized_anomaly_score
    )
    if not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise FusionContractError("fusion arithmetic produced an invalid score")
    return score


def fuse_score(
    score_input: FusionScoreInput,
    policy: PolicyManifest,
    *,
    scored_at: datetime | None = None,
) -> FusionScoreResult:
    """Validate engine identity and apply one independently loaded policy."""

    actual = (
        score_input.supervised_model_id,
        score_input.supervised_model_version,
        score_input.anomaly_model_id,
        score_input.anomaly_model_version,
        score_input.feature_schema_version,
    )
    expected = (
        policy.supervised_model_id,
        policy.supervised_model_version,
        policy.anomaly_model_id,
        policy.anomaly_model_version,
        policy.feature_schema_version,
    )
    if actual != expected:
        raise FusionContractError("fusion engine or feature identity does not match policy")
    score = weighted_score(
        score_input.supervised_probability,
        score_input.normalized_anomaly_score,
        policy.selected_weights,
    )
    return FusionScoreResult(
        supervised_probability=score_input.supervised_probability,
        normalized_anomaly_score=score_input.normalized_anomaly_score,
        supervised_weight=policy.selected_weights.supervised_weight,
        anomaly_weight=policy.selected_weights.anomaly_weight,
        fusion_score=score,
        selected_fusion_threshold=policy.selected_threshold,
        fusion_positive=score >= policy.selected_threshold,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        scored_at=scored_at or datetime.now(UTC),
        semantics=(
            "experimental suspiciousness score; not probability, risk, severity, "
            "or attack confirmation"
        ),
    )
