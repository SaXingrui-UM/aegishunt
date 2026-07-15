"""ORM records imported together so SQLAlchemy metadata is complete."""

from aegishunt.storage.models.audit import AuditEventRecord
from aegishunt.storage.models.detection import (
    AlertGroupRecord,
    DetectionResultRecord,
    SecurityAlertRecord,
)
from aegishunt.storage.models.hunting import (
    AnalystFeedbackRecord,
    InvestigationCaseRecord,
    ThreatHypothesisRecord,
)
from aegishunt.storage.models.model import ModelVersionRecord
from aegishunt.storage.models.schema import SchemaVersionRecord
from aegishunt.storage.models.telemetry import NetworkFlowRecord, TelemetrySourceRecord

__all__ = [
    "AlertGroupRecord",
    "AnalystFeedbackRecord",
    "AuditEventRecord",
    "DetectionResultRecord",
    "InvestigationCaseRecord",
    "ModelVersionRecord",
    "NetworkFlowRecord",
    "SchemaVersionRecord",
    "SecurityAlertRecord",
    "TelemetrySourceRecord",
    "ThreatHypothesisRecord",
]
