"""Transactional InvestigationCase creation and analyst-controlled lifecycle."""

from __future__ import annotations

import math
from collections.abc import Callable
from datetime import datetime
from typing import Literal, cast
from uuid import UUID

from pydantic import JsonValue
from sqlalchemy.orm import Session

from aegishunt.cases.config import LoadedCaseFeedbackPolicy
from aegishunt.cases.errors import (
    CaseConflictError,
    CaseEligibilityError,
    CaseTransitionError,
)
from aegishunt.cases.evidence import EvidenceResolver
from aegishunt.cases.lifecycle import (
    case_identity,
    note_identity,
    require_later,
    require_transition,
)
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas import CaseEvidenceReference, CaseNote, InvestigationCase
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
)
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    CaseEvidenceReferenceRepository,
    CaseNoteRepository,
    InvestigationCaseRepository,
    SecurityAlertRepository,
    ThreatHypothesisRepository,
)


class InvestigationCaseService:
    """Manage cases without changing source hypotheses, alerts, models, or policies."""

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
        self._cases = InvestigationCaseRepository(session, self._audit)
        self._notes = CaseNoteRepository(session)
        self._references = CaseEvidenceReferenceRepository(session)
        self._hypotheses = ThreatHypothesisRepository(session)
        self._groups = AlertGroupRepository(session)
        self._alerts = SecurityAlertRepository(session)
        self._resolver = EvidenceResolver(session)

    @staticmethod
    def _actor(value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise CaseEligibilityError("actor is required")
        return normalized

    @staticmethod
    def _reason(value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise CaseEligibilityError("a non-empty mutation reason is required")
        return normalized

    def create_from_hypothesis(self, hypothesis_id: UUID, *, actor: str) -> InvestigationCase:
        normalized_actor = self._actor(actor)
        hypothesis = self._hypotheses.get(hypothesis_id)
        if hypothesis is None:
            raise CaseEligibilityError("threat hypothesis does not exist")
        if hypothesis.status.value not in self._loaded.policy.eligible_hypothesis_statuses:
            raise CaseEligibilityError("hypothesis status is not eligible for a case")
        if hypothesis.group_id is None or not hypothesis.supporting_alert_ids:
            raise CaseEligibilityError("hypothesis lacks a source group or supporting alerts")
        group = self._groups.get(hypothesis.group_id)
        if group is None or group.alert_ids != hypothesis.supporting_alert_ids:
            raise CaseEligibilityError("hypothesis group evidence is incomplete or inconsistent")
        members = self._groups.list_members(group.group_id)
        if [str(item.alert_id) for item in members] != hypothesis.supporting_alert_ids:
            raise CaseEligibilityError("hypothesis supporting alerts cannot be resolved")

        identifier = case_identity(hypothesis_id, self._loaded)
        existing = self._cases.get_by_hypothesis(hypothesis_id)
        if existing is not None:
            if existing.case_id != identifier or existing.policy_checksum != (
                self._loaded.configuration_checksum
            ):
                raise CaseConflictError("existing primary case has conflicting identity")
            return existing

        now = require_aware_utc(self._clock())
        reference_specs = [
            (
                CaseEvidenceObjectType.THREAT_HYPOTHESIS,
                str(hypothesis_id),
                "Primary proposed hypothesis for analyst investigation; not attack confirmation.",
            ),
            (
                CaseEvidenceObjectType.ALERT_GROUP,
                str(group.group_id),
                "Source alert group with correlation evidence; score is not probability.",
            ),
            *[
                (
                    CaseEvidenceObjectType.SECURITY_ALERT,
                    str(member.alert_id),
                    "Supporting security alert requiring analyst review; not a confirmed attack.",
                )
                for member in members
            ],
        ]
        references = [
            self._resolver.reference(
                case_id=identifier,
                object_type=object_type,
                object_id=object_id,
                description=description,
                actor=normalized_actor,
                added_at=now,
            )
            for object_type, object_id, description in reference_specs
        ]
        reference_ids = sorted(str(item.reference_id) for item in references)
        related_object_ids = sorted(
            f"{item.object_type.value}:{item.object_id}" for item in references
        )
        evidence_snapshot: JsonObject = {
            "hypothesis_identity": {
                "hypothesis_id": str(hypothesis.hypothesis_id),
                "group_id": str(hypothesis.group_id),
                "hypothesis_schema_version": hypothesis.hypothesis_schema_version,
                "policy_id": hypothesis.policy_id,
                "policy_version": hypothesis.policy_version,
                "policy_checksum": hypothesis.policy_checksum,
            },
            "event_window": {
                "first_seen": hypothesis.first_seen.isoformat(),
                "last_seen": hypothesis.last_seen.isoformat(),
            },
            "uncertainty": {
                "status": hypothesis.status.value,
                "assumptions": cast(JsonValue, hypothesis.assumptions),
                "benign_alternatives": cast(
                    JsonValue, hypothesis.alternative_explanations
                ),
                "possible_mitre_mappings": [
                    item.model_dump(mode="json")
                    if not isinstance(item, str)
                    else item
                    for item in hypothesis.possible_mitre_mappings
                ],
                "semantics": "reviewable lead; not a fact or confirmed attack",
            },
            "reference_checksums": {
                str(item.reference_id): item.snapshot_checksum for item in references
            },
        }
        title = f"Investigation: {hypothesis.title}"[:255]
        case = InvestigationCase(
            case_id=identifier,
            hypothesis_id=hypothesis_id,
            related_hypothesis_ids=[str(hypothesis_id)],
            related_alert_ids=sorted(hypothesis.supporting_alert_ids),
            title=title,
            description=(
                "Analyst investigation work item derived from a proposed hypothesis. "
                "Creation does not confirm an attack or compromise."
            ),
            priority=self._loaded.policy.hypothesis_severity_to_priority[
                hypothesis.severity
            ],
            status=CaseStatus.OPEN,
            evidence_references=reference_ids,
            evidence_snapshot=evidence_snapshot,
            related_object_ids=related_object_ids,
            created_by=normalized_actor,
            case_schema_version="1.0.0",
            policy_id=self._loaded.policy.policy_id,
            policy_version=self._loaded.policy.policy_version,
            policy_checksum=self._loaded.configuration_checksum,
            created_at=now,
            updated_at=now,
        )
        persisted = InvestigationCaseRepository(self._session).add(case)
        for reference in references:
            self._references.add(reference)
        self._audit.record(
            actor=normalized_actor,
            action="create_case_from_hypothesis",
            object_type="investigation_cases",
            object_id=str(identifier),
            details={
                "operation_id": f"case-create:{identifier}",
                "before": None,
                "after": {
                    "status": CaseStatus.OPEN.value,
                    "priority": case.priority.value,
                },
                "reason": "explicit case creation from reviewable hypothesis",
                "hypothesis_id": str(hypothesis_id),
                "evidence_reference_count": len(references),
                "source": "explicit_analyst_action",
            },
            created_at=now,
        )
        return persisted

    def update_status(
        self,
        case_id: UUID,
        status: CaseStatus,
        *,
        actor: str,
        reason: str,
    ) -> InvestigationCase:
        if status is CaseStatus.CLOSED:
            raise CaseTransitionError("use the explicit close operation")
        normalized_reason = self._reason(reason)
        case = self._require_case(case_id)
        if case.status is status:
            return case
        require_transition(self._loaded, case.status, status)
        now = require_later(self._clock(), case.updated_at)
        updated = case.model_copy(update={"status": status, "updated_at": now})
        return self._cases.update(
            updated,
            actor=self._actor(actor),
            action="update_case_status",
            details={
                "operation_id": f"case-status:{case_id}:{now.isoformat()}",
                "before": case.status.value,
                "after": status.value,
                "reason": normalized_reason,
                "source": "case_service",
            },
            changed_at=now,
        )

    def set_priority(
        self,
        case_id: UUID,
        priority: CasePriority,
        *,
        actor: str,
        reason: str,
    ) -> InvestigationCase:
        case = self._require_mutable_case(case_id)
        normalized_reason = self._reason(reason)
        if case.priority is priority:
            return case
        now = require_later(self._clock(), case.updated_at)
        updated = case.model_copy(update={"priority": priority, "updated_at": now})
        return self._cases.update(
            updated,
            actor=self._actor(actor),
            action="update_case_priority",
            details={
                "operation_id": f"case-priority:{case_id}:{now.isoformat()}",
                "before": case.priority.value,
                "after": priority.value,
                "reason": normalized_reason,
                "source": "case_service",
            },
            changed_at=now,
        )

    def assign(
        self,
        case_id: UUID,
        assigned_to: str | None,
        *,
        actor: str,
        reason: str,
    ) -> InvestigationCase:
        case = self._require_mutable_case(case_id)
        normalized_reason = self._reason(reason)
        assignee = None if assigned_to is None else assigned_to.strip()
        if assigned_to is not None and (not assignee or len(assignee) > 255):
            raise CaseEligibilityError("assignee must be a bounded local identifier")
        if case.assigned_to == assignee:
            return case
        now = require_later(self._clock(), case.updated_at)
        updated = case.model_copy(update={"assigned_to": assignee, "updated_at": now})
        return self._cases.update(
            updated,
            actor=self._actor(actor),
            action="unassign_case" if assignee is None else "assign_case",
            details={
                "operation_id": f"case-assignment:{case_id}:{now.isoformat()}",
                "before": case.assigned_to,
                "after": assignee,
                "reason": normalized_reason,
                "source": "case_service",
            },
            changed_at=now,
        )

    def add_note(
        self,
        case_id: UUID,
        body: str,
        *,
        actor: str,
        note_type: Literal["investigation", "closure", "correction"] = "investigation",
    ) -> CaseNote:
        case = self._require_mutable_case(case_id)
        author = self._actor(actor)
        normalized = body.strip()
        policy = self._loaded.policy
        if not normalized or len(normalized) > policy.maximum_note_length:
            raise CaseEligibilityError("case note is empty or exceeds policy length")
        note_count = len(self._notes.list_by_case(case_id))
        if note_count >= policy.maximum_notes_per_case:
            raise CaseEligibilityError("case note count exceeds policy")
        now = require_later(self._clock(), case.updated_at)
        note = CaseNote(
            note_id=note_identity(
                case_id,
                author=author,
                body=normalized,
                note_type=note_type,
                created_at=now,
            ),
            case_id=case_id,
            author=author,
            body=normalized,
            note_type=note_type,
            created_at=now,
        )
        persisted = self._notes.add(note)
        touched = case.model_copy(update={"updated_at": now})
        self._cases.update(
            touched,
            actor=author,
            action="add_case_note",
            details={
                "operation_id": f"case-note:{note.note_id}",
                "before": {"note_count": note_count},
                "after": {"note_count": note_count + 1},
                "reason": "append analyst case note",
                "source": "case_service",
                "note_id": str(note.note_id),
                "note_type": note.note_type,
            },
            changed_at=now,
        )
        return persisted

    def add_evidence(
        self,
        case_id: UUID,
        object_type: CaseEvidenceObjectType,
        object_id: str,
        *,
        description: str,
        actor: str,
    ) -> CaseEvidenceReference:
        case = self._require_mutable_case(case_id)
        existing = self._references.get_by_object(
            case_id, object_type=object_type, object_id=object_id
        )
        if existing is not None:
            return existing
        if len(case.evidence_references) >= self._loaded.policy.maximum_evidence_references:
            raise CaseEligibilityError("case evidence reference count exceeds policy")
        if len(description) > self._loaded.policy.maximum_reference_description_length:
            raise CaseEligibilityError("evidence description exceeds policy")
        normalized_actor = self._actor(actor)
        now = require_later(self._clock(), case.updated_at)
        reference = self._resolver.reference(
            case_id=case_id,
            object_type=object_type,
            object_id=object_id,
            description=description,
            actor=normalized_actor,
            added_at=now,
        )
        persisted = self._references.add(reference)
        updated = case.model_copy(
            update={
                "evidence_references": sorted(
                    [*case.evidence_references, str(reference.reference_id)]
                ),
                "related_object_ids": sorted(
                    [*case.related_object_ids, f"{object_type.value}:{object_id}"]
                ),
                "updated_at": now,
            }
        )
        self._cases.update(
            updated,
            actor=normalized_actor,
            action="add_evidence_reference",
            details={
                "operation_id": f"case-evidence:{reference.reference_id}",
                "before": {"reference_count": len(case.evidence_references)},
                "after": {"reference_count": len(updated.evidence_references)},
                "reason": "append explicit typed evidence reference",
                "source": "case_service",
                "reference_id": str(reference.reference_id),
                "object_type": object_type.value,
                "object_id": object_id,
                "checksum": reference.snapshot_checksum,
            },
            changed_at=now,
        )
        return persisted

    def set_verdict(
        self,
        case_id: UUID,
        verdict: AnalystVerdict,
        *,
        confidence: float,
        reason: str,
        actor: str,
        allow_update: bool = False,
    ) -> InvestigationCase:
        case = self._require_mutable_case(case_id)
        normalized_actor = self._actor(actor)
        normalized_reason = reason.strip()
        if not normalized_reason:
            raise CaseEligibilityError("case verdict reason is required")
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise CaseEligibilityError("case verdict confidence must be finite in [0, 1]")
        same = (
            case.verdict is verdict
            and case.verdict_confidence == confidence
            and case.verdict_reason == normalized_reason
        )
        if same:
            return case
        if case.verdict is not None and not allow_update:
            raise CaseConflictError("conflicting case verdict requires explicit update")
        now = require_later(self._clock(), case.updated_at)
        updated = case.model_copy(
            update={
                "verdict": verdict,
                "verdict_confidence": confidence,
                "verdict_reason": normalized_reason,
                "updated_at": now,
            }
        )
        persisted = self._cases.update(
            updated,
            actor=normalized_actor,
            action="set_case_verdict" if case.verdict is None else "update_case_verdict",
            details={
                "operation_id": f"case-verdict:{case_id}:{now.isoformat()}",
                "before": {
                    "verdict": None if case.verdict is None else case.verdict.value,
                    "confidence": case.verdict_confidence,
                },
                "after": {"verdict": verdict.value, "confidence": confidence},
                "reason": normalized_reason,
                "source": "case_service",
                "semantics": "analyst judgment; not ground truth",
            },
            changed_at=now,
        )
        AnalystFeedbackService(
            self._session,
            self._loaded,
            clock=lambda: now,
        ).record_case(
            case_id,
            verdict,
            confidence=confidence,
            notes=normalized_reason,
            actor=normalized_actor,
            allow_update=allow_update,
            correction_reason=normalized_reason if allow_update else None,
        )
        return persisted

    def close(self, case_id: UUID, *, closure_note: str, actor: str) -> InvestigationCase:
        case = self._require_mutable_case(case_id)
        if case.verdict not in self._loaded.policy.final_verdicts:
            raise CaseTransitionError("case closure requires an explicit final verdict")
        require_transition(self._loaded, case.status, CaseStatus.CLOSED)
        note_body = closure_note.strip()
        if not note_body or len(note_body) > self._loaded.policy.maximum_note_length:
            raise CaseTransitionError("case closure requires a bounded closure note")
        note_count = len(self._notes.list_by_case(case_id))
        if note_count >= self._loaded.policy.maximum_notes_per_case:
            raise CaseTransitionError("case note count exceeds policy")
        normalized_actor = self._actor(actor)
        now = require_later(self._clock(), case.updated_at)
        note = CaseNote(
            note_id=note_identity(
                case_id,
                author=normalized_actor,
                body=note_body,
                note_type="closure",
                created_at=now,
            ),
            case_id=case_id,
            author=normalized_actor,
            body=note_body,
            note_type="closure",
            created_at=now,
        )
        self._notes.add(note)
        self._audit.record(
            actor=normalized_actor,
            action="add_case_note",
            object_type="investigation_cases",
            object_id=str(case_id),
            details={
                "operation_id": f"case-note:{note.note_id}",
                "before": {"note_count": note_count},
                "after": {"note_count": note_count + 1},
                "reason": "append required case closure note",
                "source": "case_service",
                "note_id": str(note.note_id),
                "note_type": "closure",
            },
            created_at=now,
        )
        updated = case.model_copy(
            update={"status": CaseStatus.CLOSED, "updated_at": now, "closed_at": now}
        )
        return self._cases.update(
            updated,
            actor=normalized_actor,
            action="close_case",
            details={
                "operation_id": f"case-close:{case_id}:{now.isoformat()}",
                "before": case.status.value,
                "after": CaseStatus.CLOSED.value,
                "note_id": str(note.note_id),
                "verdict": case.verdict.value,
                "reason": note_body,
                "source": "case_service",
            },
            changed_at=now,
        )

    def describe(
        self, case_id: UUID
    ) -> tuple[InvestigationCase, list[CaseNote], list[CaseEvidenceReference]]:
        case = self._require_case(case_id)
        return (
            case,
            self._notes.list_by_case(case_id),
            self._references.list_by_case(case_id),
        )

    def _require_case(self, case_id: UUID) -> InvestigationCase:
        case = self._cases.get(case_id)
        if case is None:
            raise CaseEligibilityError("investigation case does not exist")
        return case

    def _require_mutable_case(self, case_id: UUID) -> InvestigationCase:
        case = self._require_case(case_id)
        if case.status is CaseStatus.CLOSED:
            raise CaseTransitionError("closed cases are terminal")
        return case
