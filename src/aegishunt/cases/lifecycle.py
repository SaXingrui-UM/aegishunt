"""Deterministic identities and monotonic case lifecycle helpers."""

from __future__ import annotations

import hashlib
from datetime import datetime
from uuid import UUID, uuid5

from aegishunt.cases.config import LoadedCaseFeedbackPolicy
from aegishunt.cases.errors import CaseTransitionError
from aegishunt.schemas.base import require_aware_utc
from aegishunt.schemas.enums import CaseEvidenceObjectType, CaseStatus

_CASE_NAMESPACE = UUID("b9b9cfcc-a41a-53cb-a75e-87ae7cde77fe")
_REFERENCE_NAMESPACE = UUID("df2e3018-513c-5ac9-a93d-b67b26eef056")
_NOTE_NAMESPACE = UUID("c8bc199b-6847-5a73-a6ef-d1050e519063")


def case_identity(hypothesis_id: UUID, loaded: LoadedCaseFeedbackPolicy) -> UUID:
    policy = loaded.policy
    return uuid5(
        _CASE_NAMESPACE,
        f"{hypothesis_id}:1.0.0:{policy.policy_id}:{policy.policy_version}",
    )


def reference_identity(
    case_id: UUID, object_type: CaseEvidenceObjectType, object_id: str
) -> UUID:
    return uuid5(_REFERENCE_NAMESPACE, f"{case_id}:{object_type.value}:{object_id}")


def note_identity(
    case_id: UUID, *, author: str, body: str, note_type: str, created_at: datetime
) -> UUID:
    digest = hashlib.sha256(body.encode()).hexdigest()
    return uuid5(
        _NOTE_NAMESPACE,
        f"{case_id}:{author}:{note_type}:{created_at.isoformat()}:{digest}",
    )


def require_later(now: datetime, previous: datetime) -> datetime:
    lifecycle_time = require_aware_utc(now)
    if lifecycle_time <= previous:
        raise CaseTransitionError("case lifecycle time must be strictly later")
    return lifecycle_time


def require_transition(
    loaded: LoadedCaseFeedbackPolicy,
    current: CaseStatus,
    target: CaseStatus,
) -> None:
    if target not in loaded.policy.allowed_case_status_transitions[current]:
        raise CaseTransitionError("case status transition is not allowed")
