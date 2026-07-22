"""Bounded, transparent correlation scoring and triage severity mapping."""

from __future__ import annotations

from statistics import mean

from aegishunt.correlation.config import CorrelationPolicy
from aegishunt.correlation.contracts import (
    CorrelationScoreComponents,
    IndexedAlert,
    RuleMatch,
    ScoredCorrelation,
)
from aegishunt.schemas.enums import Severity


def _bounded(value: float) -> float:
    return min(1.0, max(0.0, value))


def score_correlation(
    alerts: tuple[IndexedAlert, ...],
    matches: tuple[RuleMatch, ...],
    policy: CorrelationPolicy,
) -> ScoredCorrelation:
    """Compute retained components; the result is explicitly not a probability."""

    risks = [alert.risk_score for alert in alerts]
    risk = max(risks) if policy.risk_aggregation == "maximum" else mean(risks)
    alert_count = _bounded(len(alerts) / policy.alert_count_reference)
    reason_codes = {code for alert in alerts for code in alert.reason_codes}
    diversity_evidence = len(reason_codes) + len({item.rule_id for item in matches})
    evidence_diversity = _bounded(
        diversity_evidence / policy.evidence_diversity_reference
    )
    span = max(item.event_end for item in alerts) - min(item.event_start for item in alerts)
    span_ratio = span.total_seconds() / policy.correlation_window_seconds
    temporal_density = _bounded(1.0 - span_ratio * policy.temporal_decay_factor)
    components = CorrelationScoreComponents(
        risk=risk,
        alert_count=alert_count,
        evidence_diversity=evidence_diversity,
        temporal_density=temporal_density,
    )
    weights = policy.score_weights
    score = _bounded(
        risk * weights.risk
        + alert_count * weights.alert_count
        + evidence_diversity * weights.evidence_diversity
        + temporal_density * weights.temporal_density
    )
    return ScoredCorrelation(score=score, components=components)


def severity_for(score: float, policy: CorrelationPolicy) -> Severity:
    """Map non-probabilistic evidence strength to an operational triage band."""

    selected = policy.severity_bands[0].severity
    for band in policy.severity_bands:
        if score >= band.minimum_score:
            selected = band.severity
    return selected
