"""Small typed repository adapters for core entities."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegishunt.errors import RepositoryIntegrityError, RepositoryRecordNotFoundError
from aegishunt.hunting.errors import HypothesisTransitionError
from aegishunt.schemas import (
    AlertGroup,
    AnalystFeedback,
    CaseEvidenceReference,
    CaseNote,
    DetectionResult,
    InvestigationCase,
    ModelVersion,
    NetworkFlow,
    SecurityAlert,
    TelemetrySource,
    ThreatHypothesis,
)
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import AnalystVerdict, HypothesisStatus
from aegishunt.storage.models import (
    AlertGroupRecord,
    AnalystFeedbackRecord,
    CaseEvidenceReferenceRecord,
    CaseNoteRecord,
    DetectionResultRecord,
    InvestigationCaseRecord,
    ModelVersionRecord,
    NetworkFlowRecord,
    SecurityAlertRecord,
    TelemetrySourceRecord,
    ThreatHypothesisRecord,
)
from aegishunt.storage.repositories.audit import AuditLogRepository
from aegishunt.storage.repositories.base import SqlAlchemyRepository


class TelemetrySourceRepository(SqlAlchemyRepository[TelemetrySource, TelemetrySourceRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=TelemetrySource,
            record_type=TelemetrySourceRecord,
            id_attribute="source_id",
            audit_log=audit_log,
        )

    def update(self, entity: TelemetrySource, *, actor: str = "system") -> TelemetrySource:
        """Persist one validated ingestion lifecycle transition and audit it."""

        row = self._session.get(TelemetrySourceRecord, entity.source_id)
        if row is None:
            raise RepositoryRecordNotFoundError("telemetry source no longer exists")
        row.source_type = entity.source_type
        row.filename_or_interface = entity.filename_or_interface
        row.ingestion_mode = entity.ingestion_mode
        row.status = entity.status
        row.started_at = entity.started_at
        row.completed_at = entity.completed_at
        row.records_processed = entity.records_processed
        row.checksum = entity.checksum
        row.source_metadata = dict(entity.source_metadata)
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="update",
                object_type=TelemetrySourceRecord.__tablename__,
                object_id=str(entity.source_id),
                details={
                    "status": entity.status.value,
                    "records_processed": entity.records_processed,
                },
            )
        return TelemetrySource.model_validate(row)

    def list_page(self, *, limit: int, offset: int) -> tuple[list[TelemetrySource], int]:
        """Return a stable page and total count for ingestion-job APIs."""

        rows = self._session.scalars(
            select(TelemetrySourceRecord)
            .order_by(TelemetrySourceRecord.source_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(select(func.count(TelemetrySourceRecord.source_id))) or 0
        return [TelemetrySource.model_validate(row) for row in rows], total


class NetworkFlowRepository(SqlAlchemyRepository[NetworkFlow, NetworkFlowRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=NetworkFlow,
            record_type=NetworkFlowRecord,
            id_attribute="flow_id",
            audit_log=audit_log,
        )

    def list_by_source(self, source_id: UUID) -> list[NetworkFlow]:
        """Return one source's flows in stable time and identifier order."""

        rows = self._session.scalars(
            select(NetworkFlowRecord)
            .where(NetworkFlowRecord.source_id == source_id)
            .order_by(NetworkFlowRecord.first_seen, NetworkFlowRecord.flow_id)
        ).all()
        return [NetworkFlow.model_validate(row) for row in rows]


class DetectionResultRepository(SqlAlchemyRepository[DetectionResult, DetectionResultRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=DetectionResult,
            record_type=DetectionResultRecord,
            id_attribute="detection_id",
            audit_log=audit_log,
        )


class SecurityAlertRepository(SqlAlchemyRepository[SecurityAlert, SecurityAlertRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=SecurityAlert,
            record_type=SecurityAlertRecord,
            id_attribute="alert_id",
            audit_log=audit_log,
        )

    def update_verdict(
        self,
        alert_id: UUID,
        verdict: AnalystVerdict,
        *,
        actor: str,
        changed_at: datetime | None = None,
        reason: str = "explicit analyst verdict update",
        source: str = "security_alert_repository",
    ) -> SecurityAlert:
        """Update only an analyst verdict and preserve immutable alert evidence."""

        row = self._session.get(SecurityAlertRecord, alert_id)
        if row is None:
            raise RepositoryRecordNotFoundError("security alert does not exist")
        if row.analyst_verdict == verdict:
            return SecurityAlert.model_validate(row)
        previous = row.analyst_verdict
        row.analyst_verdict = verdict
        lifecycle_time = utc_now() if changed_at is None else require_aware_utc(changed_at)
        if changed_at is not None and lifecycle_time <= row.updated_at:
            raise ValueError("alert verdict time must follow its previous lifecycle time")
        row.updated_at = max(lifecycle_time, row.created_at, row.updated_at)
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="update_verdict",
                object_type=SecurityAlertRecord.__tablename__,
                object_id=str(alert_id),
                details={
                    "operation_id": f"alert-verdict:{alert_id}:{row.updated_at.isoformat()}",
                    "before": None if previous is None else previous.value,
                    "after": verdict.value,
                    "reason": reason,
                    "source": source,
                },
                created_at=row.updated_at,
            )
        return SecurityAlert.model_validate(row)


class AlertGroupRepository(SqlAlchemyRepository[AlertGroup, AlertGroupRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=AlertGroup,
            record_type=AlertGroupRecord,
            id_attribute="group_id",
            audit_log=audit_log,
        )

    def list_open(self) -> list[AlertGroup]:
        """Return Phase 9 open groups in stable event-time order."""

        rows = self._session.scalars(
            select(AlertGroupRecord)
            .where(AlertGroupRecord.status == "open")
            .order_by(AlertGroupRecord.first_seen, AlertGroupRecord.group_id)
        ).all()
        return [AlertGroup.model_validate(row) for row in rows]

    def list_page(self, *, limit: int, offset: int) -> tuple[list[AlertGroup], int]:
        """Return a stable bounded group page and total count."""

        rows = self._session.scalars(
            select(AlertGroupRecord)
            .order_by(AlertGroupRecord.first_seen, AlertGroupRecord.group_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(select(func.count(AlertGroupRecord.group_id))) or 0
        return [AlertGroup.model_validate(row) for row in rows], total

    def list_members(self, group_id: UUID) -> list[SecurityAlert]:
        """Resolve all referenced alerts in the group's deterministic member order."""

        group = self.get(group_id)
        if group is None:
            raise RepositoryRecordNotFoundError("alert group does not exist")
        identifiers = [UUID(value) for value in group.alert_ids]
        rows = self._session.scalars(
            select(SecurityAlertRecord).where(SecurityAlertRecord.alert_id.in_(identifiers))
        ).all()
        by_id = {row.alert_id: SecurityAlert.model_validate(row) for row in rows}
        if set(by_id) != set(identifiers):
            raise RepositoryRecordNotFoundError("alert group references a missing member")
        return [by_id[identifier] for identifier in identifiers]


class ThreatHypothesisRepository(SqlAlchemyRepository[ThreatHypothesis, ThreatHypothesisRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=ThreatHypothesis,
            record_type=ThreatHypothesisRecord,
            id_attribute="hypothesis_id",
            audit_log=audit_log,
        )

    def get_by_group(self, group_id: UUID) -> ThreatHypothesis | None:
        """Return the unique deterministic hypothesis for one group, if present."""

        row = self._session.scalar(
            select(ThreatHypothesisRecord).where(
                ThreatHypothesisRecord.group_id == group_id
            )
        )
        return None if row is None else ThreatHypothesis.model_validate(row)

    def list_page(self, *, limit: int, offset: int) -> tuple[list[ThreatHypothesis], int]:
        """Return a stable bounded hypothesis page and total count."""

        rows = self._session.scalars(
            select(ThreatHypothesisRecord)
            .order_by(ThreatHypothesisRecord.first_seen, ThreatHypothesisRecord.hypothesis_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = (
            self._session.scalar(select(func.count(ThreatHypothesisRecord.hypothesis_id)))
            or 0
        )
        return [ThreatHypothesis.model_validate(row) for row in rows], total

    def update_status(
        self,
        hypothesis_id: UUID,
        status: HypothesisStatus,
        *,
        actor: str,
        changed_at: datetime,
    ) -> ThreatHypothesis:
        """Apply an analyst-controlled safe transition and audit it."""

        row = self._session.get(ThreatHypothesisRecord, hypothesis_id)
        if row is None:
            raise RepositoryRecordNotFoundError("threat hypothesis does not exist")
        if status is HypothesisStatus.CONFIRMED:
            raise HypothesisTransitionError(
                "hypotheses cannot be automatically or directly confirmed"
            )
        allowed = {
            HypothesisStatus.PROPOSED: {
                HypothesisStatus.UNDER_REVIEW,
                HypothesisStatus.NEEDS_MORE_INFORMATION,
                HypothesisStatus.DISMISSED,
                HypothesisStatus.CLOSED_UNRESOLVED,
                HypothesisStatus.REJECTED,
            },
            HypothesisStatus.UNDER_REVIEW: {
                HypothesisStatus.NEEDS_MORE_INFORMATION,
                HypothesisStatus.DISMISSED,
                HypothesisStatus.CLOSED_UNRESOLVED,
                HypothesisStatus.REJECTED,
            },
            HypothesisStatus.NEEDS_MORE_INFORMATION: {
                HypothesisStatus.UNDER_REVIEW,
                HypothesisStatus.DISMISSED,
                HypothesisStatus.CLOSED_UNRESOLVED,
                HypothesisStatus.REJECTED,
            },
        }
        if row.status == status:
            return ThreatHypothesis.model_validate(row)
        if status not in allowed.get(row.status, set()):
            raise HypothesisTransitionError("hypothesis status transition is not allowed")
        previous = row.status
        lifecycle_time = require_aware_utc(changed_at)
        previous_time = row.updated_at or row.created_at
        if lifecycle_time <= row.created_at or lifecycle_time <= previous_time:
            raise HypothesisTransitionError(
                "hypothesis status time must follow its previous lifecycle time"
            )
        row.status = status
        row.updated_at = lifecycle_time
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="update_status",
                object_type=ThreatHypothesisRecord.__tablename__,
                object_id=str(hypothesis_id),
                details={"previous_status": previous.value, "status": status.value},
            )
        return ThreatHypothesis.model_validate(row)


class InvestigationCaseRepository(SqlAlchemyRepository[InvestigationCase, InvestigationCaseRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=InvestigationCase,
            record_type=InvestigationCaseRecord,
            id_attribute="case_id",
            audit_log=audit_log,
        )

    def get_by_hypothesis(self, hypothesis_id: UUID) -> InvestigationCase | None:
        row = self._session.scalar(
            select(InvestigationCaseRecord).where(
                InvestigationCaseRecord.hypothesis_id == hypothesis_id
            )
        )
        return None if row is None else InvestigationCase.model_validate(row)

    def list_page(
        self,
        *,
        limit: int,
        offset: int,
        status: object | None = None,
        priority: object | None = None,
        assigned_to: str | None = None,
    ) -> tuple[list[InvestigationCase], int]:
        query = select(InvestigationCaseRecord)
        count_query = select(func.count(InvestigationCaseRecord.case_id))
        conditions = []
        if status is not None:
            conditions.append(InvestigationCaseRecord.status == status)
        if priority is not None:
            conditions.append(InvestigationCaseRecord.priority == priority)
        if assigned_to is not None:
            conditions.append(InvestigationCaseRecord.assigned_to == assigned_to)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(
                InvestigationCaseRecord.created_at,
                InvestigationCaseRecord.case_id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [InvestigationCase.model_validate(row) for row in rows], total

    def update(
        self,
        entity: InvestigationCase,
        *,
        actor: str,
        action: str,
        details: JsonObject,
        changed_at: datetime,
    ) -> InvestigationCase:
        row = self._session.get(InvestigationCaseRecord, entity.case_id)
        if row is None:
            raise RepositoryRecordNotFoundError("investigation case does not exist")
        immutable = (
            row.hypothesis_id,
            row.related_hypothesis_ids,
            row.related_alert_ids,
            row.title,
            row.description,
            row.evidence_snapshot,
            row.created_by,
            row.case_schema_version,
            row.policy_id,
            row.policy_version,
            row.policy_checksum,
            row.created_at,
        )
        expected = (
            entity.hypothesis_id,
            entity.related_hypothesis_ids,
            entity.related_alert_ids,
            entity.title,
            entity.description,
            entity.evidence_snapshot,
            entity.created_by,
            entity.case_schema_version,
            entity.policy_id,
            entity.policy_version,
            entity.policy_checksum,
            entity.created_at,
        )
        if immutable != expected:
            raise RepositoryIntegrityError("investigation case core evidence is immutable")
        if not set(row.evidence_references).issubset(entity.evidence_references) or not set(
            row.related_object_ids
        ).issubset(entity.related_object_ids):
            raise RepositoryIntegrityError("investigation case references are append-only")
        row.priority = entity.priority
        row.status = entity.status
        row.assigned_to = entity.assigned_to
        row.evidence_references = list(entity.evidence_references)
        row.related_object_ids = list(entity.related_object_ids)
        row.verdict = entity.verdict
        row.verdict_confidence = entity.verdict_confidence
        row.verdict_reason = entity.verdict_reason
        row.updated_at = entity.updated_at
        row.closed_at = entity.closed_at
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action=action,
                object_type=InvestigationCaseRecord.__tablename__,
                object_id=str(entity.case_id),
                details=details,
                created_at=changed_at,
            )
        return InvestigationCase.model_validate(row)


class CaseNoteRepository(SqlAlchemyRepository[CaseNote, CaseNoteRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=CaseNote,
            record_type=CaseNoteRecord,
            id_attribute="note_id",
            audit_log=audit_log,
        )

    def list_by_case(self, case_id: UUID) -> list[CaseNote]:
        rows = self._session.scalars(
            select(CaseNoteRecord)
            .where(CaseNoteRecord.case_id == case_id)
            .order_by(CaseNoteRecord.created_at, CaseNoteRecord.note_id)
        ).all()
        return [CaseNote.model_validate(row) for row in rows]


class CaseEvidenceReferenceRepository(
    SqlAlchemyRepository[CaseEvidenceReference, CaseEvidenceReferenceRecord]
):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=CaseEvidenceReference,
            record_type=CaseEvidenceReferenceRecord,
            id_attribute="reference_id",
            audit_log=audit_log,
        )

    def list_by_case(self, case_id: UUID) -> list[CaseEvidenceReference]:
        rows = self._session.scalars(
            select(CaseEvidenceReferenceRecord)
            .where(CaseEvidenceReferenceRecord.case_id == case_id)
            .order_by(
                CaseEvidenceReferenceRecord.object_type,
                CaseEvidenceReferenceRecord.object_id,
            )
        ).all()
        return [CaseEvidenceReference.model_validate(row) for row in rows]

    def get_by_object(
        self,
        case_id: UUID,
        *,
        object_type: object,
        object_id: str,
    ) -> CaseEvidenceReference | None:
        row = self._session.scalar(
            select(CaseEvidenceReferenceRecord).where(
                CaseEvidenceReferenceRecord.case_id == case_id,
                CaseEvidenceReferenceRecord.object_type == object_type,
                CaseEvidenceReferenceRecord.object_id == object_id,
            )
        )
        return None if row is None else CaseEvidenceReference.model_validate(row)


class AnalystFeedbackRepository(SqlAlchemyRepository[AnalystFeedback, AnalystFeedbackRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=AnalystFeedback,
            record_type=AnalystFeedbackRecord,
            id_attribute="feedback_id",
            audit_log=audit_log,
        )

    def add(self, entity: AnalystFeedback, *, actor: str = "system") -> AnalystFeedback:
        """Create feedback with a Phase 10-specific audit record."""

        row = AnalystFeedbackRecord(**entity.model_dump(mode="python"))
        self._session.add(row)
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="create_feedback",
                object_type=AnalystFeedbackRecord.__tablename__,
                object_id=str(entity.feedback_id),
                details={
                    "operation_id": f"feedback-create:{entity.feedback_id}",
                    "before": None,
                    "after": {
                        "verdict": entity.verdict.value,
                        "confidence": entity.confidence,
                    },
                    "object_type": entity.object_type.value,
                    "object_id": entity.object_id,
                    "verdict": entity.verdict.value,
                    "reason": "explicit analyst feedback creation",
                    "source": entity.source,
                    "semantics": "human supplied; potentially noisy",
                },
                created_at=entity.created_at,
            )
        return AnalystFeedback.model_validate(row)

    def get_by_identity(
        self,
        *,
        object_type: object,
        object_id: str,
        actor: str,
        source: str,
    ) -> AnalystFeedback | None:
        row = self._session.scalar(
            select(AnalystFeedbackRecord).where(
                AnalystFeedbackRecord.object_type == object_type,
                AnalystFeedbackRecord.object_id == object_id,
                AnalystFeedbackRecord.actor == actor,
                AnalystFeedbackRecord.source == source,
            )
        )
        return None if row is None else AnalystFeedback.model_validate(row)

    def update(
        self,
        entity: AnalystFeedback,
        *,
        actor: str,
        changed_at: datetime,
    ) -> AnalystFeedback:
        row = self._session.get(AnalystFeedbackRecord, entity.feedback_id)
        if row is None:
            raise RepositoryRecordNotFoundError("analyst feedback does not exist")
        if (row.object_type, row.object_id, row.actor, row.source, row.created_at) != (
            entity.object_type,
            entity.object_id,
            entity.actor,
            entity.source,
            entity.created_at,
        ):
            raise RepositoryIntegrityError("analyst feedback identity is immutable")
        previous = row.verdict
        previous_confidence = row.confidence
        row.verdict = entity.verdict
        row.confidence = entity.confidence
        row.notes = entity.notes
        row.updated_at = entity.updated_at
        row.related_case_id = entity.related_case_id
        row.provenance = dict(entity.provenance)
        row.correction_reason = entity.correction_reason
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="update_feedback",
                object_type=AnalystFeedbackRecord.__tablename__,
                object_id=str(entity.feedback_id),
                details={
                    "operation_id": (
                        f"feedback-update:{entity.feedback_id}:"
                        f"{changed_at.isoformat()}"
                    ),
                    "before": {
                        "verdict": previous.value,
                        "confidence": previous_confidence,
                    },
                    "after": {
                        "verdict": entity.verdict.value,
                        "confidence": entity.confidence,
                    },
                    "reason": entity.correction_reason,
                    "source": entity.source,
                },
                created_at=changed_at,
            )
        return AnalystFeedback.model_validate(row)

    def list_filtered(
        self,
        *,
        limit: int,
        offset: int,
        object_type: object | None = None,
        object_id: str | None = None,
        verdict: object | None = None,
        actor: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
    ) -> tuple[list[AnalystFeedback], int]:
        query = select(AnalystFeedbackRecord)
        count_query = select(func.count(AnalystFeedbackRecord.feedback_id))
        conditions = []
        if object_type is not None:
            conditions.append(AnalystFeedbackRecord.object_type == object_type)
        if object_id is not None:
            conditions.append(AnalystFeedbackRecord.object_id == object_id)
        if verdict is not None:
            conditions.append(AnalystFeedbackRecord.verdict == verdict)
        if actor is not None:
            conditions.append(AnalystFeedbackRecord.actor == actor)
        if created_from is not None:
            conditions.append(AnalystFeedbackRecord.created_at >= created_from)
        if created_to is not None:
            conditions.append(AnalystFeedbackRecord.created_at <= created_to)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(
                AnalystFeedbackRecord.created_at,
                AnalystFeedbackRecord.feedback_id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [AnalystFeedback.model_validate(row) for row in rows], total


class ModelVersionRepository(SqlAlchemyRepository[ModelVersion, ModelVersionRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=ModelVersion,
            record_type=ModelVersionRecord,
            id_attribute="model_id",
            audit_log=audit_log,
        )
