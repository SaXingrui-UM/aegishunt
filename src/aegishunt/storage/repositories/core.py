"""Small typed repository adapters for every Phase 1 core entity."""

from sqlalchemy.orm import Session

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


class NetworkFlowRepository(SqlAlchemyRepository[NetworkFlow, NetworkFlowRecord]):
    def __init__(self, session: Session, audit_log: AuditLogRepository | None = None) -> None:
        super().__init__(
            session,
            schema_type=NetworkFlow,
            record_type=NetworkFlowRecord,
            id_attribute="flow_id",
            audit_log=audit_log,
        )


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
