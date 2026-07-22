"""Deterministic local correlation rules over bounded candidate clusters."""

from __future__ import annotations

from statistics import mean
from typing import cast

from aegishunt.correlation.config import CorrelationPolicy
from aegishunt.correlation.contracts import IndexedAlert, RuleMatch
from aegishunt.correlation.index import CandidateCluster
from aegishunt.schemas.base import JsonObject


def _values(alerts: tuple[IndexedAlert, ...], entity_type: str) -> set[str]:
    return {
        key.value
        for alert in alerts
        for key in alert.entity_keys
        if key.entity_type == entity_type
    }


def _match(
    rule_id: str,
    cluster: CandidateCluster,
    policy: CorrelationPolicy,
    *,
    evidence: dict[str, object],
    limitation: str,
) -> RuleMatch:
    return RuleMatch(
        rule_id=rule_id,
        version=policy.rule_versions[rule_id],
        matched_alert_ids=tuple(alert.alert_id for alert in cluster.alerts),
        required_entity_keys=(cluster.entity_key,),
        evidence=cast(JsonObject, evidence),
        limitations=(limitation,),
    )


def evaluate_rules(
    cluster: CandidateCluster,
    policy: CorrelationPolicy,
) -> tuple[RuleMatch, ...]:
    """Evaluate all configured rules without enrichment or pairwise scans."""

    alerts = cluster.alerts
    source_ips = _values(alerts, "source_ip")
    destination_ips = _values(alerts, "destination_ip")
    reason_codes = sorted({code for alert in alerts for code in alert.reason_codes})
    matches: list[RuleMatch] = []
    if len(source_ips) == 1 and len(destination_ips) >= policy.minimum_distinct_destinations:
        matches.append(
            _match(
                "source_centered_reconnaissance",
                cluster,
                policy,
                evidence={
                    "distinct_destinations": len(destination_ips),
                    "source_ips": sorted(source_ips),
                },
                limitation="Fan-out may reflect benign scanning, monitoring, or service discovery.",
            )
        )
        matches.append(
            _match(
                "source_fan_out",
                cluster,
                policy,
                evidence={"distinct_destinations": len(destination_ips)},
                limitation="Destination diversity alone does not establish malicious intent.",
            )
        )
    if len(destination_ips) == 1 and len(source_ips) >= policy.minimum_distinct_sources:
        matches.append(
            _match(
                "destination_fan_in",
                cluster,
                policy,
                evidence={"distinct_sources": len(source_ips)},
                limitation="Fan-in may reflect a public or shared service.",
            )
        )
    failure_tokens = ("fail", "denied", "reject", "reset", "rst", "auth")
    failure_codes = [
        code for code in reason_codes if any(token in code.casefold() for token in failure_tokens)
    ]
    if cluster.entity_key.startswith("source_destination_pair:") and failure_codes:
        matches.append(
            _match(
                "repeated_source_destination_failures",
                cluster,
                policy,
                evidence={"failure_reason_codes": failure_codes},
                limitation="Reason codes are model-derived indicators, not protocol outcomes.",
            )
        )
    timestamps = [alert.event_start.timestamp() for alert in alerts]
    intervals = [right - left for left, right in zip(timestamps, timestamps[1:], strict=False)]
    if len(intervals) >= 2 and mean(intervals) > 0:
        spread = max(intervals) - min(intervals)
        periodicity = max(0.0, 1.0 - spread / mean(intervals))
        if periodicity >= 0.8:
            matches.append(
                _match(
                    "periodic_beacon_like_activity",
                    cluster,
                    policy,
                    evidence={"intervals_seconds": intervals, "regularity": periodicity},
                    limitation="Regular timing may be produced by legitimate scheduled traffic.",
                )
            )
    multi_engine_ids = [
        alert.alert_id for alert in alerts if alert.alert_type == "multi_engine_suspicion"
    ]
    if multi_engine_ids:
        matches.append(
            _match(
                "multi_engine_evidence",
                cluster,
                policy,
                evidence={"multi_engine_alert_ids": multi_engine_ids},
                limitation=(
                    "Multiple engines may share upstream features and are not "
                    "independent proof."
                ),
            )
        )
    if len(reason_codes) >= policy.minimum_distinct_reason_codes:
        matches.append(
            _match(
                "multi_alert_accumulation",
                cluster,
                policy,
                evidence={
                    "alert_count": len(alerts),
                    "distinct_reason_codes": reason_codes,
                },
                limitation="Accumulated alerts remain suspiciousness evidence requiring review.",
            )
        )
    return tuple(sorted(matches, key=lambda item: item.rule_id))
