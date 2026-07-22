"""Canonical entity and event-time extraction from immutable alert evidence."""

from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import cast

from pydantic import JsonValue

from aegishunt.correlation.config import CorrelationPolicy
from aegishunt.correlation.contracts import EntityKey, EntityType, IndexedAlert
from aegishunt.correlation.errors import CorrelationInputError
from aegishunt.schemas import SecurityAlert
from aegishunt.schemas.base import JsonObject, require_aware_utc

_IP_TYPES = {"source_ip", "destination_ip"}
_CASEFOLD_TYPES = {"source_host", "destination_host", "user", "protocol", "service"}
_OBSERVED_ENTITY_TYPES: tuple[EntityType, ...] = (
    "source_ip",
    "destination_ip",
    "source_host",
    "destination_host",
    "user",
    "protocol",
    "service",
    "flow_id",
    "capture_session_id",
)


def canonical_entity(
    entity_type: EntityType,
    value: object,
    *,
    maximum_length: int,
) -> EntityKey:
    """Normalize one local evidence value without enrichment or lookup."""

    if not isinstance(value, str):
        raise CorrelationInputError(f"{entity_type} entity must be text")
    normalized = value.strip()
    if not normalized:
        raise CorrelationInputError(f"{entity_type} entity cannot be empty")
    if len(normalized) > maximum_length:
        raise CorrelationInputError(f"{entity_type} entity exceeds the configured limit")
    if entity_type in _IP_TYPES:
        try:
            normalized = ip_address(normalized).compressed
        except ValueError as exc:
            raise CorrelationInputError(f"{entity_type} entity is not a valid IP address") from exc
    elif entity_type in _CASEFOLD_TYPES:
        normalized = normalized.casefold()
    return EntityKey(entity_type=entity_type, value=normalized)


def _timestamp(value: object, *, field_name: str) -> datetime:
    if not isinstance(value, str):
        raise CorrelationInputError(f"alert observed {field_name} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return require_aware_utc(parsed)
    except ValueError as exc:
        raise CorrelationInputError(f"alert observed {field_name} is invalid") from exc


def _observed_facts(alert: SecurityAlert) -> JsonObject:
    value = alert.evidence.get("observed_facts")
    if not isinstance(value, dict):
        raise CorrelationInputError("alert evidence lacks observed event facts")
    return cast(JsonObject, value)


def _entity_values(alert: SecurityAlert, facts: JsonObject) -> list[tuple[EntityType, object]]:
    values: list[tuple[EntityType, object]] = []
    supported = set(_OBSERVED_ENTITY_TYPES)
    for raw in alert.involved_entities:
        entity_type, separator, value = raw.partition(":")
        if separator and entity_type in supported:
            values.append((cast(EntityType, entity_type), value))
    for entity_type in _OBSERVED_ENTITY_TYPES:
        observed_value: JsonValue | None = facts.get(entity_type)
        if observed_value is not None:
            values.append((entity_type, observed_value))
    return values


def index_alert(alert: SecurityAlert, policy: CorrelationPolicy) -> IndexedAlert:
    """Build one immutable correlation input or fail closed."""

    facts = _observed_facts(alert)
    event_start = _timestamp(facts.get("first_seen"), field_name="first_seen")
    event_end = _timestamp(facts.get("last_seen"), field_name="last_seen")
    if event_end < event_start:
        raise CorrelationInputError("alert observed time window is reversed")
    enabled = set(policy.enabled_entity_keys)
    entities: dict[str, EntityKey] = {}
    for entity_type, value in _entity_values(alert, facts):
        if entity_type not in enabled or not isinstance(value, str) or not value.strip():
            continue
        entity = canonical_entity(
            entity_type,
            value,
            maximum_length=policy.maximum_entity_value_length,
        )
        entities[entity.serialized] = entity
    source = next(
        (item for item in entities.values() if item.entity_type == "source_ip"), None
    )
    destination = next(
        (item for item in entities.values() if item.entity_type == "destination_ip"), None
    )
    if source is not None and destination is not None and "source_destination_pair" in enabled:
        pair = canonical_entity(
            "source_destination_pair",
            f"{source.value}->{destination.value}",
            maximum_length=policy.maximum_entity_value_length,
        )
        entities[pair.serialized] = pair
    if not entities:
        raise CorrelationInputError("alert has no enabled canonical correlation entities")
    if len(entities) > policy.maximum_entities_per_alert:
        raise CorrelationInputError("alert exceeds the configured entity limit")
    snapshot: JsonObject = {
        "alert_id": str(alert.alert_id),
        "risk_score": alert.risk_score,
        "severity": alert.severity.value,
        "alert_type": alert.alert_type,
        "reason_codes": list(sorted(set(alert.reason_codes))),
        "analyst_verdict": (
            None if alert.analyst_verdict is None else alert.analyst_verdict.value
        ),
        "model_versions": dict(sorted(alert.model_versions.items())),
        "policy_versions": dict(sorted(alert.policy_versions.items())),
        "observed_facts": facts,
        "top_local_contributions": alert.evidence.get("top_local_contributions", []),
    }
    return IndexedAlert(
        alert_id=str(alert.alert_id),
        event_start=event_start,
        event_end=event_end,
        entity_keys=tuple(entities[key] for key in sorted(entities)),
        risk_score=alert.risk_score,
        severity=alert.severity.value,
        alert_type=alert.alert_type,
        reason_codes=tuple(sorted(set(alert.reason_codes))),
        analyst_verdict=None if alert.analyst_verdict is None else alert.analyst_verdict.value,
        model_versions=dict(sorted(alert.model_versions.items())),
        policy_versions=dict(sorted(alert.policy_versions.items())),
        observed_facts=facts,
        evidence_snapshot=snapshot,
    )
