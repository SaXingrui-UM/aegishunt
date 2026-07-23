"""Transactional analyst-feedback recording and bounded queries."""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime
from uuid import UUID, uuid5

from sqlalchemy.orm import Session

from aegishunt.cases.config import LoadedCaseFeedbackPolicy
from aegishunt.feedback.errors import FeedbackConflictError, FeedbackEligibilityError
from aegishunt.schemas import AnalystFeedback
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import AnalystVerdict, FeedbackObjectType
from aegishunt.storage.repositories import (
    AnalystFeedbackRepository,
    AuditLogRepository,
    InvestigationCaseRepository,
    SecurityAlertRepository,
)

_FEEDBACK_NAMESPACE = UUID("44e9915c-85a5-5d7f-a340-2a27708a737b")


def feedback_identity(
    *, object_type: FeedbackObjectType, object_id: str, actor: str, source: str
) -> UUID:
    return uuid5(_FEEDBACK_NAMESPACE, f"{object_type.value}:{object_id}:{actor}:{source}")


class AnalystFeedbackService:
    """Record human-supplied, possibly noisy judgments without model side effects."""

    def __init__(
        self,
        session: Session,
        loaded_policy: LoadedCaseFeedbackPolicy,
        *,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session = session
        self._loaded = loaded_policy
        self._clock = clock
        self._audit = AuditLogRepository(session)
        self._feedback = AnalystFeedbackRepository(session, self._audit)
        self._alerts = SecurityAlertRepository(session, self._audit)
        self._cases = InvestigationCaseRepository(session, self._audit)

    def record_alert(
        self,
        alert_id: UUID,
        verdict: AnalystVerdict,
        *,
        confidence: float,
        notes: str,
        actor: str,
        source: str = "analyst_cli",
        allow_update: bool = False,
        correction_reason: str | None = None,
        related_case_id: UUID | None = None,
    ) -> AnalystFeedback:
        alert = self._alerts.get(alert_id)
        if alert is None:
            raise FeedbackEligibilityError("security alert does not exist")
        now = require_aware_utc(self._clock())
        if alert.analyst_verdict not in {None, verdict} and not allow_update:
            raise FeedbackConflictError(
                "alert verdict conflicts with feedback; explicit update is required"
            )
        feedback = self._record(
            object_type=FeedbackObjectType.ALERT,
            object_id=str(alert_id),
            verdict=verdict,
            confidence=confidence,
            notes=notes,
            actor=actor,
            source=source,
            now=now,
            allow_update=allow_update,
            correction_reason=correction_reason,
            related_case_id=related_case_id,
            provenance={
                "trust_boundary": "human_supplied_possible_noisy_label",
                "object_contract": "security_alert",
                "detection_id": str(alert.detection_id),
            },
        )
        if alert.analyst_verdict != verdict:
            self._alerts.update_verdict(
                alert_id,
                verdict,
                actor=actor,
                changed_at=now,
                reason=(
                    correction_reason.strip()
                    if correction_reason is not None and correction_reason.strip()
                    else "record explicit analyst feedback"
                ),
                source=source,
            )
        return feedback

    def record_case(
        self,
        case_id: UUID,
        verdict: AnalystVerdict,
        *,
        confidence: float,
        notes: str,
        actor: str,
        source: str = "case_verdict",
        allow_update: bool = False,
        correction_reason: str | None = None,
    ) -> AnalystFeedback:
        case = self._cases.get(case_id)
        if case is None:
            raise FeedbackEligibilityError("investigation case does not exist")
        if case.verdict != verdict:
            raise FeedbackConflictError("case feedback must match the persisted case verdict")
        return self._record(
            object_type=FeedbackObjectType.CASE,
            object_id=str(case_id),
            verdict=verdict,
            confidence=confidence,
            notes=notes,
            actor=actor,
            source=source,
            now=require_aware_utc(self._clock()),
            allow_update=allow_update,
            correction_reason=correction_reason,
            related_case_id=case_id,
            provenance={
                "trust_boundary": "human_supplied_possible_noisy_label",
                "object_contract": "investigation_case",
                "row_label_propagation": "prohibited",
            },
        )

    def _record(
        self,
        *,
        object_type: FeedbackObjectType,
        object_id: str,
        verdict: AnalystVerdict,
        confidence: float,
        notes: str,
        actor: str,
        source: str,
        now: datetime,
        allow_update: bool,
        correction_reason: str | None,
        related_case_id: UUID | None,
        provenance: JsonObject,
    ) -> AnalystFeedback:
        normalized_actor = actor.strip()
        normalized_source = source.strip()
        normalized_notes = notes.strip()
        if not normalized_actor or not normalized_source or not normalized_notes:
            raise FeedbackEligibilityError("feedback actor, source, and notes are required")
        if len(normalized_notes) > 4_000:
            raise FeedbackEligibilityError("feedback notes exceed the Phase 10 bound")
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise FeedbackEligibilityError("feedback confidence must be finite in [0, 1]")
        identifier = feedback_identity(
            object_type=object_type,
            object_id=object_id,
            actor=normalized_actor,
            source=normalized_source,
        )
        existing = self._feedback.get_by_identity(
            object_type=object_type,
            object_id=object_id,
            actor=normalized_actor,
            source=normalized_source,
        )
        if existing is None:
            entity = AnalystFeedback(
                feedback_id=identifier,
                object_type=object_type,
                object_id=object_id,
                verdict=verdict,
                confidence=confidence,
                notes=normalized_notes,
                actor=normalized_actor,
                source=normalized_source,
                created_at=now,
                updated_at=now,
                feedback_schema_version="1.0.0",
                related_case_id=related_case_id,
                provenance=provenance,
            )
            return self._feedback.add(entity, actor=normalized_actor)
        same = (
            existing.verdict == verdict
            and existing.confidence == confidence
            and existing.notes == normalized_notes
            and existing.related_case_id == related_case_id
        )
        if same:
            return existing
        if not allow_update or not correction_reason or not correction_reason.strip():
            raise FeedbackConflictError(
                "conflicting feedback requires explicit update and correction reason"
            )
        if existing.updated_at is None or now <= existing.updated_at:
            raise FeedbackConflictError("feedback update time must be strictly later")
        updated = existing.model_copy(
            update={
                "verdict": verdict,
                "confidence": confidence,
                "notes": normalized_notes,
                "updated_at": now,
                "related_case_id": related_case_id,
                "correction_reason": correction_reason.strip(),
            }
        )
        return self._feedback.update(updated, actor=normalized_actor, changed_at=now)

    def list(
        self,
        *,
        limit: int,
        offset: int = 0,
        object_type: FeedbackObjectType | None = None,
        object_id: str | None = None,
        verdict: AnalystVerdict | None = None,
        actor: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
    ) -> tuple[list[AnalystFeedback], int]:
        maximum = self._loaded.policy.maximum_feedback_per_query
        if limit < 1 or limit > maximum or offset < 0:
            raise FeedbackEligibilityError("feedback pagination is outside policy bounds")
        if created_from is not None:
            created_from = require_aware_utc(created_from)
        if created_to is not None:
            created_to = require_aware_utc(created_to)
        if created_from is not None and created_to is not None and created_from > created_to:
            raise FeedbackEligibilityError("feedback date range is invalid")
        return self._feedback.list_filtered(
            limit=limit,
            offset=offset,
            object_type=object_type,
            object_id=object_id,
            verdict=verdict,
            actor=actor,
            created_from=created_from,
            created_to=created_to,
        )
