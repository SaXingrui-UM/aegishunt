"""Typed repositories used instead of business-layer SQL."""

from aegishunt.storage.repositories.audit import AuditLogRepository
from aegishunt.storage.repositories.core import (
    AlertGroupRepository,
    AnalystFeedbackRepository,
    CaseEvidenceReferenceRepository,
    CaseNoteRepository,
    DetectionResultRepository,
    InvestigationCaseRepository,
    ModelVersionRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
    ThreatHypothesisRepository,
)

__all__ = [
    "AlertGroupRepository",
    "AnalystFeedbackRepository",
    "AuditLogRepository",
    "CaseEvidenceReferenceRepository",
    "CaseNoteRepository",
    "DetectionResultRepository",
    "InvestigationCaseRepository",
    "ModelVersionRepository",
    "NetworkFlowRepository",
    "SecurityAlertRepository",
    "TelemetrySourceRepository",
    "ThreatHypothesisRepository",
]
