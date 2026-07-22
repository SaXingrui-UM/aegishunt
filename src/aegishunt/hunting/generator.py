"""Evidence-preserving deterministic hypothesis construction."""

from __future__ import annotations

from typing import cast
from uuid import NAMESPACE_URL, uuid5

from pydantic import JsonValue

from aegishunt.correlation.config import LoadedCorrelationPolicy
from aegishunt.hunting.errors import HypothesisGateError
from aegishunt.hunting.templates import (
    TEMPLATE_CATALOG_VERSION,
    TEMPLATE_PRIORITY,
    TEMPLATES,
    query_for,
)
from aegishunt.schemas import AlertGroup, ThreatHypothesis
from aegishunt.schemas.base import JsonObject
from aegishunt.schemas.enums import HypothesisStatus


def _bounded(value: float) -> float:
    return min(1.0, max(0.0, value))


def _reason_codes(group: AlertGroup) -> set[str]:
    members = group.evidence.get("member_alerts", [])
    if not isinstance(members, list):
        return set()
    output: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            continue
        codes = member.get("reason_codes", [])
        if isinstance(codes, list):
            output.update(str(code) for code in codes)
    return output


def _candidate_templates(group: AlertGroup) -> tuple[str, ...]:
    rules = set(group.matched_rule_ids)
    codes = {code.casefold() for code in _reason_codes(group)}
    candidates: set[str] = set()
    if rules & {"source_centered_reconnaissance", "source_fan_out"}:
        candidates.add("possible_network_reconnaissance")
    if "repeated_source_destination_failures" in rules:
        candidates.add("possible_brute_force_activity")
    if any("auth" in code or "credential" in code or "account" in code for code in codes):
        candidates.add("possible_credential_abuse")
    if "periodic_beacon_like_activity" in rules:
        candidates.add("possible_beaconing_behavior")
        if "multi_engine_evidence" in rules:
            candidates.add("possible_command_and_control_pattern")
    if any("exfil" in code or "outbound" in code for code in codes):
        candidates.add("possible_data_exfiltration_pattern")
    if "destination_fan_in" in rules:
        candidates.add("possible_denial_of_service_behavior")
    if not candidates:
        candidates.add("unclassified_behavioral_anomaly")
    return tuple(item for item in TEMPLATE_PRIORITY if item in candidates)


def _facts(group: AlertGroup) -> list[str]:
    return [
        f"Alert group contains {group.alert_count} distinct alerts.",
        (
            f"Observed event-time window is {group.first_seen.isoformat()} to "
            f"{group.last_seen.isoformat()}."
        ),
        f"Canonical correlation entities: {', '.join(group.entity_keys)}.",
        f"Matched deterministic rules: {', '.join(group.matched_rule_ids)}.",
    ]


def hypothesis_gate_failure(
    group: AlertGroup,
    loaded: LoadedCorrelationPolicy,
) -> str | None:
    """Return an explicit eligibility failure without using exceptions for control flow."""

    policy = loaded.policy
    if group.group_schema_version != "1.0.0":
        return "hypothesis generation requires a Phase 9 alert group"
    if group.alert_count is None or group.alert_count < policy.minimum_alerts:
        return "alert group does not meet the minimum member count"
    if group.severity is None:
        return "alert group lacks a triage severity"
    if group.correlation_score < policy.hypothesis_generation_threshold:
        return "alert group is below the hypothesis generation threshold"
    if not group.matched_rule_ids or not group.evidence:
        return "alert group lacks rule or evidence provenance"
    return None


def generate_hypothesis(
    group: AlertGroup,
    loaded: LoadedCorrelationPolicy,
) -> ThreatHypothesis:
    """Generate one proposed hypothesis or fail closed at the configured gate."""

    policy = loaded.policy
    gate_failure = hypothesis_gate_failure(group, loaded)
    if gate_failure is not None:
        raise HypothesisGateError(gate_failure)
    severity = group.severity
    if severity is None:
        raise HypothesisGateError("alert group lacks a triage severity")
    candidates = _candidate_templates(group)
    primary = candidates[0]
    template = TEMPLATES[primary]
    specificity = _bounded(max(0.2, 1.0 - (len(candidates) - 1) * 0.15))
    diversity = _bounded(len(group.matched_rule_ids) / 4.0)
    coherence = 1.0 if group.entity_keys else 0.0
    weights = policy.hypothesis_confidence_weights
    confidence_components = {
        "correlation": group.correlation_score,
        "rule_specificity": specificity,
        "evidence_diversity": diversity,
        "entity_coherence": coherence,
    }
    confidence = _bounded(
        confidence_components["correlation"] * weights.correlation
        + confidence_components["rule_specificity"] * weights.rule_specificity
        + confidence_components["evidence_diversity"] * weights.evidence_diversity
        + confidence_components["entity_coherence"] * weights.entity_coherence
    )
    hypothesis_id = uuid5(
        NAMESPACE_URL,
        f"aegishunt-hypothesis:{group.group_id}:{policy.policy_id}:{policy.policy_version}",
    )
    snapshot: JsonObject = {
        "group_id": str(group.group_id),
        "alert_ids": cast(list[JsonValue], list(group.alert_ids)),
        "entity_keys": cast(list[JsonValue], list(group.entity_keys)),
        "matched_rule_ids": cast(list[JsonValue], list(group.matched_rule_ids)),
        "correlation_score": group.correlation_score,
        "score_semantics": "correlation evidence strength; not attack probability",
        "policy_id": group.policy_id,
        "policy_version": group.policy_version,
        "policy_checksum": group.policy_checksum,
    }
    return ThreatHypothesis(
        hypothesis_id=hypothesis_id,
        group_id=group.group_id,
        title=template.title,
        description=(
            f"Correlated evidence is consistent with {template.category}. This is a "
            "deterministic hunting lead requiring analyst review, not a confirmed attack."
        ),
        confidence=confidence,
        confidence_components=confidence_components,
        severity=severity,
        involved_entities=list(group.entity_keys),
        supporting_alert_ids=list(group.alert_ids),
        supporting_features=list(group.matched_rule_ids),
        first_seen=group.first_seen,
        last_seen=group.last_seen,
        possible_attack_category=template.category,
        possible_mitre_mappings=[] if template.mapping is None else [template.mapping],
        observed_facts=_facts(group),
        derived_inferences=[
            f"The primary deterministic template is {primary}.",
            "Correlation and hypothesis confidence are triage scores, not probabilities.",
        ],
        assumptions=[
            "Alert event-time facts and entity identifiers are accurate.",
            "Configured correlation thresholds are suitable for this controlled context.",
        ],
        alternative_explanations=list(template.benign_alternatives),
        recommended_queries=[query_for(template)],
        recommended_steps=[
            "Validate entities and time boundaries against authoritative local telemetry.",
            "Review source alerts and model limitations before containment decisions.",
            "Document benign context or escalate through an analyst-controlled workflow.",
        ],
        primary_template_id=primary,
        template_catalog_version=TEMPLATE_CATALOG_VERSION,
        candidate_template_ids=list(candidates),
        source_group_snapshot=snapshot,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_checksum=loaded.configuration_checksum,
        hypothesis_schema_version="1.0.0",
        status=HypothesisStatus.PROPOSED,
        created_at=group.last_seen,
        updated_at=group.last_seen,
    )
