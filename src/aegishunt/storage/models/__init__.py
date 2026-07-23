"""ORM records imported together so SQLAlchemy metadata is complete."""

from aegishunt.storage.models.audit import AuditEventRecord
from aegishunt.storage.models.detection import (
    AlertGroupRecord,
    DetectionResultRecord,
    SecurityAlertRecord,
)
from aegishunt.storage.models.hunting import (
    AnalystFeedbackRecord,
    CaseEvidenceReferenceRecord,
    CaseNoteRecord,
    InvestigationCaseRecord,
    ThreatHypothesisRecord,
)
from aegishunt.storage.models.model import ModelVersionRecord
from aegishunt.storage.models.runtime import (
    RuntimeAttemptRecord,
    RuntimeJobRecord,
    RuntimeOutputLedgerRecord,
    RuntimeResourceSampleRecord,
    RuntimeWorkerRecord,
)
from aegishunt.storage.models.schema import SchemaVersionRecord
from aegishunt.storage.models.telemetry import NetworkFlowRecord, TelemetrySourceRecord

__all__ = [
    "AlertGroupRecord",
    "AnalystFeedbackRecord",
    "AuditEventRecord",
    "CaseEvidenceReferenceRecord",
    "CaseNoteRecord",
    "DetectionResultRecord",
    "InvestigationCaseRecord",
    "ModelVersionRecord",
    "NetworkFlowRecord",
    "RuntimeAttemptRecord",
    "RuntimeJobRecord",
    "RuntimeOutputLedgerRecord",
    "RuntimeResourceSampleRecord",
    "RuntimeWorkerRecord",
    "SchemaVersionRecord",
    "SecurityAlertRecord",
    "TelemetrySourceRecord",
    "ThreatHypothesisRecord",
]
