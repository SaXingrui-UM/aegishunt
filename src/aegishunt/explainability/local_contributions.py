"""Deterministic single-feature reference-replacement sensitivity."""

from __future__ import annotations

from aegishunt.detection.adapters import FeatureScoreAdapter
from aegishunt.detection.contracts import LoadedRiskPolicy
from aegishunt.detection.errors import DetectionContractError
from aegishunt.detection.risk import evaluate_risk
from aegishunt.explainability.contracts import (
    EffectDirection,
    LocalContribution,
    ReferenceProfile,
)

_LIMITATIONS = (
    "Single-feature replacement measures configured model sensitivity, not causation.",
    "Contributions are not SHAP values and need not add up to the risk score.",
    "Reference bounds describe benign training observations, not safety boundaries.",
)


def compute_local_contributions(
    features: tuple[float, ...],
    *,
    feature_names: tuple[str, ...],
    profile: ReferenceProfile,
    scorer: FeatureScoreAdapter,
    risk_policy: LoadedRiskPolicy,
    top_k: int,
    max_features: int,
    neutral_tolerance: float = 1e-12,
) -> tuple[LocalContribution, ...]:
    """Replace one feature at a time and rank absolute risk deltas stably."""

    if feature_names != profile.feature_names or profile.feature_schema_version != (
        risk_policy.policy.required_feature_schema_version
    ):
        raise DetectionContractError("local explanation feature contract is incompatible")
    if len(features) != len(feature_names):
        raise DetectionContractError("local explanation feature width is invalid")
    if top_k < 1 or max_features < 1:
        raise DetectionContractError("local explanation bounds must be positive")
    original_risk = evaluate_risk(scorer.score(features), risk_policy).risk_score
    contributions: list[tuple[int, LocalContribution]] = []
    for index, reference in enumerate(profile.features[:max_features]):
        replaced = list(features)
        replaced[index] = reference.median
        replacement_risk = evaluate_risk(scorer.score(tuple(replaced)), risk_policy).risk_score
        delta = original_risk - replacement_risk
        direction: EffectDirection
        if abs(delta) <= neutral_tolerance:
            direction = "neutral"
            delta = 0.0
        elif delta > 0.0:
            direction = "increases_suspicion"
        else:
            direction = "decreases_suspicion"
        contributions.append(
            (
                index,
                LocalContribution(
                    feature_name=reference.feature_name,
                    observed_value=features[index],
                    reference_median=reference.median,
                    reference_low=reference.q05,
                    reference_high=reference.q95,
                    risk_with_observed=original_risk,
                    risk_with_reference_replacement=replacement_risk,
                    effect_delta=delta,
                    effect_direction=direction,
                    method="single_feature_reference_replacement",
                    limitations=_LIMITATIONS,
                ),
            )
        )
    ranked = sorted(contributions, key=lambda item: (-abs(item[1].effect_delta), item[0]))
    return tuple(item for _, item in ranked[:top_k])
