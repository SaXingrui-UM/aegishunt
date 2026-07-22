"""Stable alert-group construction with rule evidence and deduplication."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import cast
from uuid import NAMESPACE_URL, uuid5

from aegishunt.correlation.config import LoadedCorrelationPolicy
from aegishunt.correlation.contracts import IndexedAlert, RuleMatch
from aegishunt.correlation.index import EntityIndex
from aegishunt.correlation.rules import evaluate_rules
from aegishunt.correlation.scoring import score_correlation, severity_for
from aegishunt.schemas import AlertGroup, SecurityAlert
from aegishunt.schemas.base import JsonObject, require_aware_utc


def correlate_alerts(
    alerts: list[SecurityAlert] | tuple[SecurityAlert, ...],
    loaded: LoadedCorrelationPolicy,
    *,
    generated_at: datetime,
) -> tuple[AlertGroup, ...]:
    """Correlate eligible alerts in bounded event-time windows deterministically."""

    policy = loaded.policy
    lifecycle_time = require_aware_utc(generated_at)
    index = EntityIndex.build(alerts, policy)
    members: dict[tuple[str, ...], tuple[IndexedAlert, ...]] = {}
    entities: dict[tuple[str, ...], set[str]] = defaultdict(set)
    rules: dict[tuple[str, ...], dict[str, RuleMatch]] = defaultdict(dict)
    for cluster in index.candidate_clusters():
        matches = evaluate_rules(cluster, policy)
        if not matches:
            continue
        key = tuple(sorted(alert.alert_id for alert in cluster.alerts))
        members[key] = tuple(sorted(cluster.alerts, key=lambda item: item.alert_id))
        entities[key].add(cluster.entity_key)
        for match in matches:
            rules[key][match.rule_id] = match
    groups: list[AlertGroup] = []
    for alert_ids in sorted(members):
        group_alerts = members[alert_ids]
        matches = tuple(rules[alert_ids][key] for key in sorted(rules[alert_ids]))
        scored = score_correlation(group_alerts, matches, policy)
        if scored.score < policy.group_score_threshold:
            continue
        first_seen = min(item.event_start for item in group_alerts)
        last_seen = max(item.event_end for item in group_alerts)
        identity = json.dumps(
            {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "policy_checksum": loaded.configuration_checksum,
                "alert_ids": alert_ids,
                "entity_keys": sorted(entities[alert_ids]),
                "first_seen": first_seen.isoformat(),
                "last_seen": last_seen.isoformat(),
                "matched_rule_ids": [item.rule_id for item in matches],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        group_id = uuid5(NAMESPACE_URL, f"aegishunt-alert-group:{identity}")
        evidence = cast(JsonObject, {
            "score_semantics": scored.semantics,
            "rule_matches": [item.model_dump(mode="json") for item in matches],
            "member_alerts": [item.evidence_snapshot for item in group_alerts],
            "limitations": sorted(
                {limitation for item in matches for limitation in item.limitations}
            ),
            "event_time_source": "security_alert.evidence.observed_facts",
            "generated_at": lifecycle_time.isoformat(),
        })
        groups.append(
            AlertGroup(
                group_id=group_id,
                alert_ids=list(alert_ids),
                entity_keys=sorted(entities[alert_ids]),
                matched_rule_ids=[item.rule_id for item in matches],
                correlation_score=scored.score,
                score_components=scored.components.model_dump(),
                first_seen=first_seen,
                last_seen=last_seen,
                alert_count=len(alert_ids),
                severity=severity_for(scored.score, policy),
                summary=(
                    f"{len(alert_ids)} alerts matched {len(matches)} deterministic "
                    "correlation rules; analyst review is required."
                ),
                evidence=evidence,
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_checksum=loaded.configuration_checksum,
                status="open",
                group_schema_version="1.0.0",
                created_at=lifecycle_time,
            )
        )
    return tuple(sorted(groups, key=lambda item: (item.first_seen, str(item.group_id))))
