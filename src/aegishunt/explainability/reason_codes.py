"""Versioned deterministic reason-code catalog and evidence triggers."""

from __future__ import annotations

from collections.abc import Callable

from aegishunt.detection.contracts import RiskDecision, VerifiedScores
from aegishunt.explainability.contracts import (
    ReasonCatalogEntry,
    ReasonCodeCatalog,
    ReasonEvidence,
    ReferenceProfile,
)

_NON_CAUSAL = ("This reason is evidence for analyst review and does not establish causation.",)


def default_reason_catalog() -> ReasonCodeCatalog:
    """Return the stable Phase 8 catalog, including disabled cross-flow reservations."""

    entries = (
        _entry("ABNORMALLY_HIGH_PACKET_RATE", "flow_behavior", "packets_per_second"),
        _entry("LOW_IAT_VARIANCE", "flow_behavior", "std_inter_arrival_time"),
        _entry(
            "PERIODIC_BEACONING_PATTERN",
            "flow_behavior",
            "periodicity_score",
            classification="model_inference",
        ),
        _entry("HIGH_SYN_RATIO", "flow_behavior", "syn_ratio"),
        _entry("HIGH_RESET_RATIO", "flow_behavior", "rst_ratio"),
        _entry("STRONG_TRAFFIC_ASYMMETRY", "flow_behavior", "asymmetry_score"),
        _entry(
            "REPEATED_DESTINATION_ACTIVITY",
            "flow_behavior",
            "cross_flow_destination_window",
            condition="reserved for Phase 9",
            classification="model_inference",
            enabled=False,
        ),
        _entry(
            "SHORT_CONNECTION_BURST",
            "flow_behavior",
            "connection_burst_score",
            classification="model_inference",
        ),
        _threshold_entry(
            "SUPERVISED_HIGH_CONFIDENCE",
            "supervised",
            "supervised_probability",
            "at or above supervised threshold",
        ),
        _threshold_entry(
            "ANOMALY_HIGH_SCORE",
            "anomaly",
            "normalized_anomaly_score",
            "at or above anomaly threshold",
        ),
        _threshold_entry(
            "MULTI_ENGINE_SUPPORT",
            "multi_engine",
            "supervised_and_anomaly",
            "both engine thresholds met",
        ),
        _threshold_entry(
            "RISK_SCORE_ABOVE_ALERT_THRESHOLD",
            "risk",
            "risk_score",
            "at or above alert threshold",
        ),
        _threshold_entry(
            "MULTIPLE_CORRELATED_ALERTS",
            "multi_engine",
            "alert_correlation",
            "reserved for Phase 9",
            enabled=False,
        ),
    )
    return ReasonCodeCatalog(
        catalog_schema_version="1.0.0",
        catalog_id="aegishunt-phase-08-reason-codes",
        catalog_version="1.0.0",
        entries=entries,
    )


def _entry(
    code: str,
    category: str,
    source: str,
    *,
    condition: str = "outside benign q05-q95 reference range",
    classification: str = "observed_fact",
    enabled: bool = True,
) -> ReasonCatalogEntry:
    return ReasonCatalogEntry.model_validate(
        {
            "code": code,
            "version": "1.0.0",
            "category": category,
            "trigger_source": source,
            "trigger_condition": condition,
            "evidence_type": "feature_reference",
            "classification": classification,
            "description_template": f"{code.replace('_', ' ').title()} evidence observed.",
            "limitations": _NON_CAUSAL,
            "enabled_in_phase_8": enabled,
        }
    )


def _threshold_entry(
    code: str,
    category: str,
    source: str,
    condition: str,
    *,
    enabled: bool = True,
) -> ReasonCatalogEntry:
    return ReasonCatalogEntry.model_validate(
        {
            "code": code,
            "version": "1.0.0",
            "category": category,
            "trigger_source": source,
            "trigger_condition": condition,
            "evidence_type": "configured_threshold",
            "classification": "model_inference",
            "description_template": f"{code.replace('_', ' ').title()} evidence observed.",
            "limitations": _NON_CAUSAL,
            "enabled_in_phase_8": enabled,
        }
    )


def generate_reason_evidence(
    features: dict[str, float],
    *,
    profile: ReferenceProfile,
    scores: VerifiedScores,
    risk: RiskDecision,
    catalog: ReasonCodeCatalog,
) -> tuple[ReasonEvidence, ...]:
    """Generate only evidence-backed Phase 8 reasons in catalog order."""

    references = {item.feature_name: item for item in profile.features}
    by_code = {item.code: item for item in catalog.entries}
    output: list[ReasonEvidence] = []

    def feature_high(code: str, name: str) -> None:
        reference = references.get(name)
        value = features.get(name)
        if reference is not None and value is not None and value > reference.q95:
            output.append(_reference_evidence(by_code[code], value, reference.q05, reference.q95))

    feature_high("ABNORMALLY_HIGH_PACKET_RATE", "packets_per_second")
    std_reference = references.get("std_inter_arrival_time")
    std_value = features.get("std_inter_arrival_time")
    mean_iat = features.get("mean_inter_arrival_time")
    if (
        std_reference is not None
        and std_value is not None
        and mean_iat is not None
        and mean_iat > 0.0
        and std_value < std_reference.q05
    ):
        output.append(
            _reference_evidence(
                by_code["LOW_IAT_VARIANCE"], std_value, std_reference.q05, std_reference.q95
            )
        )
    feature_high("PERIODIC_BEACONING_PATTERN", "periodicity_score")
    feature_high("HIGH_SYN_RATIO", "syn_ratio")
    feature_high("HIGH_RESET_RATIO", "rst_ratio")
    feature_high("STRONG_TRAFFIC_ASYMMETRY", "asymmetry_score")
    feature_high("SHORT_CONNECTION_BURST", "connection_burst_score")

    threshold_triggers: tuple[tuple[str, float, float, Callable[[], bool]], ...] = (
        (
            "SUPERVISED_HIGH_CONFIDENCE",
            scores.supervised_probability,
            scores.supervised_threshold,
            lambda: scores.supervised_probability >= scores.supervised_threshold,
        ),
        (
            "ANOMALY_HIGH_SCORE",
            scores.normalized_anomaly_score,
            scores.anomaly_threshold,
            lambda: scores.normalized_anomaly_score >= scores.anomaly_threshold,
        ),
        (
            "MULTI_ENGINE_SUPPORT",
            min(scores.supervised_probability, scores.normalized_anomaly_score),
            min(scores.supervised_threshold, scores.anomaly_threshold),
            lambda: scores.supervised_probability >= scores.supervised_threshold
            and scores.normalized_anomaly_score >= scores.anomaly_threshold,
        ),
        (
            "RISK_SCORE_ABOVE_ALERT_THRESHOLD",
            risk.risk_score,
            risk.alert_threshold,
            lambda: risk.alert_required,
        ),
    )
    for code, value, threshold, triggered in threshold_triggers:
        if triggered():
            output.append(_threshold_evidence(by_code[code], value, threshold))
    return tuple(output)


def _reference_evidence(
    entry: ReasonCatalogEntry,
    value: float,
    low: float,
    high: float,
) -> ReasonEvidence:
    return ReasonEvidence(
        code=entry.code,
        version=entry.version,
        observed_value=value,
        reference_low=low,
        reference_high=high,
        description=entry.description_template,
        evidence_type=entry.evidence_type,
        classification=entry.classification,
        limitations=entry.limitations,
    )


def _threshold_evidence(
    entry: ReasonCatalogEntry,
    value: float,
    threshold: float,
) -> ReasonEvidence:
    return ReasonEvidence(
        code=entry.code,
        version=entry.version,
        observed_value=value,
        configured_threshold=threshold,
        description=entry.description_template,
        evidence_type=entry.evidence_type,
        classification=entry.classification,
        limitations=entry.limitations,
    )
