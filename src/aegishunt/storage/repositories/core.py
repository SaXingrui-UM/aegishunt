"""Small typed repository adapters for core entities."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegishunt.errors import RepositoryRecordNotFoundError
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
from aegishunt.schemas.base import utc_now
from aegishunt.schemas.enums import AnalystVerdict
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


class ThreatHypothesisRepository(SqlAlchemyRepository[ThreatHypothesis, ThreatHypothesisRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=ThreatHypothesis,
            record_type=ThreatHypothesisRecord,
            id_attribute="hypothesis_id",
            audit_log=audit_log,
        )


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
