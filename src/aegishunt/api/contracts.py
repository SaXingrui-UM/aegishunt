"""Stable Phase 12 web contracts separated from persistence schemas."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegishunt.runtime.contracts import RuntimeAttempt, RuntimeJob, RuntimeStatus, RuntimeWorker
from aegishunt.schemas import (
    AlertGroup,
    AnalystFeedback,
    CaseEvidenceReference,
    CaseNote,
    DetectionResult,
    InvestigationCase,
    NetworkFlow,
    SecurityAlert,
    TelemetrySource,
    ThreatHypothesis,
)
from aegishunt.schemas.base import JsonObject
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
    HypothesisStatus,
)

ItemT = TypeVar("ItemT")


class ApiContract(BaseModel):
    """Strict base for public request and response payloads."""

    model_config = ConfigDict(extra="forbid")


class Page(ApiContract, Generic[ItemT]):
    """Uniform bounded offset pagination response."""

    items: list[ItemT]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)
    next_offset: int | None
    has_more: bool = False

    @model_validator(mode="before")
    @classmethod
    def derive_has_more(cls, value: Any) -> Any:
        """Derive the stable pagination flag when a producer supplies only an offset."""

        if isinstance(value, Mapping) and "has_more" not in value:
            updated = dict(value)
            updated["has_more"] = value.get("next_offset") is not None
            return updated
        return value

    @model_validator(mode="after")
    def validate_has_more(self) -> Page[ItemT]:
        """Reject contradictory pagination metadata."""

        if self.has_more != (self.next_offset is not None):
            raise ValueError("has_more must match next_offset")
        return self


class Pagination(ApiContract):
    """Request-scoped pagination resolved from validated web configuration."""

    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0)


class ErrorResponse(ApiContract):
    """Sanitized error envelope returned by every exception handler."""

    error_code: str
    message: str
    request_id: str
    details: JsonObject | None = None
    retryable: bool = False
    status_code: int


class MutationRequest(ApiContract):
    """Explicit audit attribution for state-changing calls."""

    actor: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("actor", "reason")
    @classmethod
    def strip_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value must not be blank")
        return normalized


class ConfirmedMutationRequest(MutationRequest):
    """Mutation requiring an explicit affirmative confirmation."""

    confirm: Literal[True]


class RuntimeReplayRequest(ConfirmedMutationRequest):
    """Create one pinned offline replay job from a stored source."""

    source_id: UUID
    speed: float | None = Field(default=None, gt=0.0)
    run_now: bool = False


class SampleIngestRequest(ConfirmedMutationRequest):
    """Ingest one checksum-declared packaged sample."""

    sample_id: str = Field(min_length=1, max_length=128)


class RuntimeMutationRequest(MutationRequest):
    """Pause, resume, or recover one existing runtime job."""


class RuntimeRunOnceRequest(ConfirmedMutationRequest):
    """Claim and execute at most one queued local replay job."""


class RuntimeRunOnceResult(ApiContract):
    """Bounded worker result without implying that a job was available."""

    claimed_job: bool
    worker: RuntimeWorker
    execution_semantics: Literal["claim_at_most_one_then_stop"] = (
        "claim_at_most_one_then_stop"
    )


class RuntimeJobDetail(ApiContract):
    """Runtime job with its durable attempt history."""

    job: RuntimeJob
    attempts: tuple[RuntimeAttempt, ...]
    recovery_semantics: Literal["deterministic_restart_from_origin"] = (
        "deterministic_restart_from_origin"
    )


class RuntimeLatencySummary(ApiContract):
    """Observed latest-job wall-clock duration; never a benchmark claim."""

    status: Literal["available", "unavailable"]
    metric_name: Literal["runtime_job_start_to_completion_duration"]
    p50_ms: float | None = Field(default=None, ge=0.0)
    p95_ms: float | None = Field(default=None, ge=0.0)
    observation_count: int = Field(ge=0)
    window_start: datetime | None
    window_end: datetime | None
    source: Literal["runtime_jobs.started_at/completed_at"]
    unit: Literal["ms"]
    calculated_at: datetime
    runtime_job_id: UUID | None
    unavailable_reason: str | None
    limitation: Literal["controlled runtime observation; not a performance benchmark"] = (
        "controlled runtime observation; not a performance benchmark"
    )


class RuntimeResourceObservation(ApiContract):
    """Latest persisted worker-process sample with explicit support state."""

    status: Literal["available", "unavailable"]
    worker_id: str | None
    runtime_job_id: UUID | None
    process_id: int | None = Field(default=None, ge=1)
    process_cpu_percent: float | None = Field(default=None, ge=0.0)
    process_rss_bytes: int | None = Field(default=None, ge=0)
    active_thread_count: int | None = Field(default=None, ge=1)
    captured_at: datetime | None
    metric_source: Literal["runtime_resource_samples+runtime_workers.process_identity_summary"]
    unavailable_reason: str | None
    limitation: Literal["point-in-time process observation; not a performance benchmark"] = (
        "point-in-time process observation; not a performance benchmark"
    )


class RuntimeOverview(ApiContract):
    """Truthful status with explicit progress semantics."""

    status: RuntimeStatus
    latency: RuntimeLatencySummary
    resource: RuntimeResourceObservation
    observed_progress_semantics: Literal["non_durable_live_observation"] = (
        "non_durable_live_observation"
    )
    durable_progress_semantics: Literal["durable_committed_evidence"] = (
        "durable_committed_evidence"
    )


class SystemStatus(ApiContract):
    """Bounded database, runtime, and prototype status."""

    application: str
    version: str
    environment: str
    database: Literal["ready"]
    schema_version: int
    runtime: RuntimeStatus
    authentication: Literal["not_implemented_local_single_user"]
    phase: Literal["12"]
    research_prototype: Literal[True] = True


class FlowSummary(ApiContract):
    """Bounded database-side flow aggregation."""

    total: int = Field(ge=0)
    protocol_distribution: dict[str, int]
    total_packets: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    first_seen: datetime | None
    last_seen: datetime | None
    top_source_destination_pairs: list[JsonObject]


class AlertDetail(ApiContract):
    """Alert evidence plus bounded related-object identifiers."""

    alert: SecurityAlert
    related_group_ids: list[UUID]
    related_hypothesis_ids: list[UUID]
    limitations: tuple[str, ...] = (
        "risk score is not attack probability",
        "severity is not attack certainty",
        "an alert is not a confirmed attack",
        "feature contributions are non-causal",
    )


class DetectionDetail(ApiContract):
    """Immutable detection evidence with its optional generated alert."""

    detection: DetectionResult
    alert_id: UUID | None
    limitations: tuple[str, ...] = (
        "risk score is not attack probability",
        "model output is inference, not an observed fact",
        "controlled evidence is not public benchmark or production validation",
    )


class AlertVerdictRequest(MutationRequest):
    """The only mutable field exposed for a persisted alert."""

    analyst_verdict: AnalystVerdict


class AlertGroupDetail(ApiContract):
    """Correlated group with members and related hypothesis."""

    group: AlertGroup
    alerts: list[SecurityAlert]
    hypothesis_id: UUID | None
    limitation: Literal["correlation score is not attack probability"] = (
        "correlation score is not attack probability"
    )


class HypothesisDetail(ApiContract):
    """Hypothesis with its optional primary investigation case."""

    hypothesis: ThreatHypothesis
    case_id: UUID | None
    limitations: tuple[str, ...] = (
        "hypothesis confidence is not attack probability",
        "a hypothesis is a reviewable lead, not a fact",
        "MITRE mappings are possible mappings, not attribution",
        "recommended queries are structured and not executed",
    )


class HypothesisStatusRequest(MutationRequest):
    """Analyst-controlled safe hypothesis status transition."""

    status: HypothesisStatus


class CreateCaseFromHypothesisRequest(ConfirmedMutationRequest):
    """Explicit case creation from immutable hypothesis evidence."""


class CaseCreateRequest(ConfirmedMutationRequest):
    """Create a deterministic primary case from a hypothesis."""

    hypothesis_id: UUID


class CaseUpdateRequest(MutationRequest):
    """One bounded analyst-driven case update."""

    status: CaseStatus | None = None
    priority: CasePriority | None = None
    assigned_to: str | None = Field(default=None, max_length=255)
    verdict: AnalystVerdict | None = None
    verdict_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class CaseNoteRequest(MutationRequest):
    """Append-only case note."""

    body: str = Field(min_length=1, max_length=8_000)
    note_type: Literal["investigation", "closure", "correction"] = "investigation"


class CaseEvidenceRequest(MutationRequest):
    """Append-only typed evidence reference."""

    object_type: CaseEvidenceObjectType
    object_id: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1, max_length=1_000)


class FeedbackRequest(MutationRequest):
    """Human-supplied, potentially noisy analyst feedback."""

    verdict: AnalystVerdict
    confidence: float = Field(ge=0.0, le=1.0)
    notes: str = Field(default="", max_length=4_000)


class CaseCloseRequest(ConfirmedMutationRequest):
    """Close one case after a final verdict has been recorded."""

    closure_note: str = Field(min_length=1, max_length=8_000)


class CaseReportRequest(ConfirmedMutationRequest):
    """Generate one versioned, checksummed case report."""

    version: str = Field(min_length=1, max_length=64)


class CaseDetail(ApiContract):
    """Complete bounded case investigation view."""

    case: InvestigationCase
    hypothesis: ThreatHypothesis | None
    notes: list[CaseNote]
    evidence: list[CaseEvidenceReference]
    feedback: list[AnalystFeedback]


class CaseAuditEvent(ApiContract):
    """Bounded read-only projection of one immutable audit event."""

    audit_event_id: UUID
    object_type: str
    object_id: str | None
    action: str
    actor: str
    reason: str | None
    timestamp: datetime
    before_summary: JsonObject | None
    after_summary: JsonObject | None
    metadata_summary: JsonObject


class CaseAuditEventPage(Page[CaseAuditEvent]):
    """Page-number view layered over the common bounded offset contract."""

    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total_pages: int = Field(ge=0)


class ArtifactRequest(ConfirmedMutationRequest):
    """Versioned data-only artifact operation."""

    version: str = Field(min_length=1, max_length=64)


class ArtifactResult(ApiContract):
    """Verified data-only artifact metadata without filesystem disclosure."""

    artifact_type: str
    version: str
    manifest: JsonObject


class ModelDescriptor(ApiContract):
    """Verified model bundle or explicit unavailable state."""

    model_id: str
    engine: Literal["supervised", "anomaly", "fusion"]
    version: str
    state: Literal["verified", "validation_qualified", "unavailable"]
    active: bool
    checksum: str | None
    artifact_available: bool
    activation_eligible: bool
    activation_ineligibility_reason: str | None = None
    limitations: tuple[str, ...] = ()


class EffectiveModelDescriptor(ApiContract):
    """One model actually pinned to the latest completed runtime job."""

    model_id: str
    engine_type: Literal["supervised", "anomaly"]
    algorithm: str | None
    version: str
    registry_status: Literal["verified", "validation_qualified", "unavailable"]
    source: Literal["global_active", "runtime_job_snapshot"]
    runtime_job_id: UUID
    feature_schema_version: str
    artifact_hash: str
    threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    snapshot_created_at: datetime
    global_pointer_active: bool
    qualification: str
    limitations: tuple[str, ...]


class FusionPolicyDescriptor(ApiContract):
    """A verified JSON fusion policy, never represented as an sklearn model."""

    policy_id: str
    policy_version: str
    status: str
    source: Literal["configured_policy", "runtime_job_snapshot"]
    runtime_job_id: UUID | None
    artifact_source: str
    artifact_hash: str
    supervised_weight: float = Field(ge=0.0, le=1.0)
    anomaly_weight: float = Field(ge=0.0, le=1.0)
    rule_weight: float | None = Field(default=None, ge=0.0, le=1.0)
    context_weight: float | None = Field(default=None, ge=0.0, le=1.0)
    fusion_threshold: float = Field(gt=0.0, lt=1.0)
    feature_schema_version: str
    evaluation_source: str
    recommendation: str
    configured_for_new_jobs: bool
    effective_for_latest_job: bool
    limitations: tuple[str, ...]


class EffectiveModelState(ApiContract):
    """Global pointers and latest-job effective artifacts with separate semantics."""

    status: Literal["available", "unavailable"]
    latest_runtime_job_id: UUID | None
    latest_runtime_job_status: str | None
    snapshot_created_at: datetime | None
    global_active_models: list[ModelDescriptor]
    effective_models: list[EffectiveModelDescriptor]
    configured_fusion_policy: FusionPolicyDescriptor | None
    effective_fusion_policy: FusionPolicyDescriptor | None
    unavailable_reason: str | None
    limitations: tuple[str, ...]


class ModelTrainRequest(ConfirmedMutationRequest):
    """Allowlisted controlled training adapter; never activates automatically."""

    engine: Literal["supervised", "anomaly"]
    profile: Literal[
        "supervised-default",
        "supervised-corrective",
        "anomaly-default",
        "anomaly-lof-candidate",
    ]
    new_version: str = Field(min_length=1, max_length=128)
    approved_dataset_identity: str = Field(min_length=1, max_length=255)


class ModelActivateRequest(ConfirmedMutationRequest):
    """Explicit verified activation with optimistic version protection."""

    expected_active_version: str | None = Field(default=None, max_length=128)


class ModelImportanceEntry(ApiContract):
    """One verified global model-sensitivity value."""

    feature_name: str
    mean: float
    standard_deviation: float = Field(ge=0.0)


class ModelImportance(ApiContract):
    """Verified non-causal importance or an explicit unavailable state."""

    model_id: str
    available: bool
    method: str | None
    importance: tuple[ModelImportanceEntry, ...] | None
    message: str
    limitation: Literal["feature importance is non-causal"] = (
        "feature importance is non-causal"
    )


class EvaluationDescriptor(ApiContract):
    """Read-only evaluation evidence state."""

    run_id: str
    engine: Literal["supervised", "anomaly", "fusion"]
    version: str
    available: bool
    verification: Literal["verified", "unavailable"]
    metrics: JsonObject | None
    provenance: JsonObject
    limitations: tuple[str, ...]


class FusionEvaluationDiscovery(ApiContract):
    """Availability of registered Phase 7 evidence without a fabricated row."""

    status: Literal["available", "unavailable", "invalid"]
    experiment_id: str
    run_id: str | None
    recommendation: Literal[
        "inconclusive",
        "fusion_recommended",
        "fusion_not_recommended",
    ]
    metrics_available: bool
    expected_artifacts: tuple[str, ...]
    missing_artifacts: tuple[str, ...]
    invalid_reason: str | None
    artifact_hash: str | None
    dataset_reference: str | None
    split_reference: str | None
    limitations: tuple[str, ...]


class DemoStatus(ApiContract):
    """Sample-demo readiness without triggering work."""

    available: bool
    sample_ids: list[str]
    previous_run: JsonObject | None
    limitations: tuple[str, ...]


class DemoRequest(ConfirmedMutationRequest):
    """Explicit idempotent controlled demonstration request."""

    sample_id: str = Field(min_length=1, max_length=128)
    create_case: bool = False


class DemoResult(ApiContract):
    """Actual identifiers created or reused by the controlled demo."""

    namespace: str
    source_id: UUID
    runtime_job_id: UUID | None
    flow_ids: list[UUID]
    alert_ids: list[UUID]
    group_ids: list[UUID]
    hypothesis_ids: list[UUID]
    case_id: UUID | None
    state: Literal["ingested", "completed", "partial"]
    limitations: tuple[str, ...]


TelemetrySourcePage = Page[TelemetrySource]
RuntimeJobPage = Page[RuntimeJob]
RuntimeWorkerPage = Page[RuntimeWorker]
NetworkFlowPage = Page[NetworkFlow]
DetectionResultPage = Page[DetectionResult]
SecurityAlertPage = Page[SecurityAlert]
AlertGroupPage = Page[AlertGroup]
ThreatHypothesisPage = Page[ThreatHypothesis]
InvestigationCasePage = Page[InvestigationCase]
AnalystFeedbackPage = Page[AnalystFeedback]
ModelPage = Page[ModelDescriptor]
EvaluationPage = Page[EvaluationDescriptor]
