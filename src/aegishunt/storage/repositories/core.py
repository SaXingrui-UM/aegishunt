"""Small typed repository adapters for core entities."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegishunt.errors import RepositoryRecordNotFoundError
from aegishunt.hunting.errors import HypothesisTransitionError
from aegishunt.schemas import (
    AlertGroup,
    AnalystFeedback,
    DetectionResult,
    InvestigationCase,
    ModelVersion,
    NetworkFlow,
    SecurityAlert,
    TelemetrySource,
    ThreatHypothesis,
)
from aegishunt.schemas.base import require_aware_utc, utc_now
from aegishunt.schemas.enums import AnalystVerdict, HypothesisStatus
from aegishunt.storage.models import (
    AlertGroupRecord,
    AnalystFeedbackRecord,
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
    ) -> SecurityAlert:
        """Update only an analyst verdict and preserve immutable alert evidence."""

        row = self._session.get(SecurityAlertRecord, alert_id)
        if row is None:
            raise RepositoryRecordNotFoundError("security alert does not exist")
        if row.analyst_verdict == verdict:
            return SecurityAlert.model_validate(row)
        previous = row.analyst_verdict
        row.analyst_verdict = verdict
        row.updated_at = max(utc_now(), row.created_at, row.updated_at)
        self._session.flush()
        if self._audit_log is not None:
            self._audit_log.record(
                actor=actor,
                action="update_verdict",
                object_type=SecurityAlertRecord.__tablename__,
                object_id=str(alert_id),
                details={
                    "previous_verdict": None if previous is None else previous.value,
                    "analyst_verdict": verdict.value,
                },
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


class AnalystFeedbackRepository(SqlAlchemyRepository[AnalystFeedback, AnalystFeedbackRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=AnalystFeedback,
            record_type=AnalystFeedbackRecord,
            id_attribute="feedback_id",
            audit_log=audit_log,
        )


class ModelVersionRepository(SqlAlchemyRepository[ModelVersion, ModelVersionRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=ModelVersion,
            record_type=ModelVersionRecord,
            id_attribute="model_id",
            audit_log=audit_log,
        )
