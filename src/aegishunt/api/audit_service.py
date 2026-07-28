"""Bounded, read-only case audit-history projection."""

from __future__ import annotations

from datetime import datetime
from typing import cast
from uuid import UUID

from pydantic import JsonValue

from aegishunt.api.contracts import CaseAuditEvent
from aegishunt.schemas.audit import AuditEvent
from aegishunt.schemas.base import JsonObject
from aegishunt.storage.repositories import AuditLogRepository

_SENSITIVE_TOKENS = ("password", "secret", "token", "credential", "api_key")
_SUMMARY_KEYS = 20
_SUMMARY_ITEMS = 10
_SUMMARY_STRING = 500


def _safe_key(value: object) -> str:
    return str(value)[:128]


def _safe_value(value: object, *, depth: int = 0) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:_SUMMARY_STRING]
    if depth >= 2:
        return str(value)[:_SUMMARY_STRING]
    if isinstance(value, dict):
        mapped: dict[str, JsonValue] = {}
        for raw_key, raw_value in list(value.items())[:_SUMMARY_KEYS]:
            key = _safe_key(raw_key)
            if any(token in key.lower() for token in _SENSITIVE_TOKENS):
                continue
            mapped[key] = _safe_value(raw_value, depth=depth + 1)
        if len(value) > _SUMMARY_KEYS:
            mapped["_truncated_key_count"] = len(value) - _SUMMARY_KEYS
        return mapped
    if isinstance(value, (list, tuple)):
        items: list[JsonValue] = [
            _safe_value(item, depth=depth + 1) for item in value[:_SUMMARY_ITEMS]
        ]
        if len(value) > _SUMMARY_ITEMS:
            items.append(f"<{len(value) - _SUMMARY_ITEMS} additional items>")
        return items
    return str(value)[:_SUMMARY_STRING]


def _summary(value: object) -> JsonObject | None:
    if value is None:
        return None
    safe = _safe_value(value)
    if isinstance(safe, dict):
        return cast(JsonObject, safe)
    return {"value": safe}


def _metadata(details: JsonObject) -> JsonObject:
    return cast(
        JsonObject,
        _safe_value(
            {
                key: value
                for key, value in details.items()
                if key not in {"before", "after", "before_state", "after_state", "reason"}
            }
        ),
    )


def project_case_audit_event(event: AuditEvent) -> CaseAuditEvent:
    """Map one immutable event without returning unbounded raw detail blobs."""

    details = event.details
    before = details.get("before", details.get("before_state"))
    after = details.get("after", details.get("after_state"))
    reason = details.get("reason")
    return CaseAuditEvent(
        audit_event_id=event.audit_id,
        object_type=event.object_type,
        object_id=event.object_id,
        action=event.action,
        actor=event.actor,
        reason=reason[:_SUMMARY_STRING] if isinstance(reason, str) else None,
        timestamp=event.created_at,
        before_summary=_summary(before),
        after_summary=_summary(after),
        metadata_summary=_metadata(details),
    )


def list_case_audit_events(
    repository: AuditLogRepository,
    case_id: UUID,
    *,
    limit: int,
    offset: int,
    action: str | None,
    actor: str | None,
    created_from: datetime | None,
    created_to: datetime | None,
    descending: bool,
) -> tuple[list[CaseAuditEvent], int]:
    """Return a bounded case timeline from the append-only repository."""

    events, total = repository.list_case_events(
        case_id,
        limit=limit,
        offset=offset,
        action=action,
        actor=actor,
        created_from=created_from,
        created_to=created_to,
        descending=descending,
    )
    return [project_case_audit_event(item) for item in events], total
