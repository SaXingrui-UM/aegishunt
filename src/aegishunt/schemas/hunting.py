"""Threat-hypothesis, investigation-case, and analyst-feedback schemas."""

from __future__ import annotations

import math
import re
from datetime import datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import Field, field_validator, model_validator

from aegishunt.schemas.base import (
    CoreSchema,
    JsonObject,
    Probability,
    require_aware_utc,
    utc_now,
)
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
    FeedbackObjectType,
    HypothesisStatus,
    Severity,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PossibleMitreMapping(CoreSchema):
    """Cautious local technique mapping that never asserts attribution."""

    technique_id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")
    technique_name: str = Field(min_length=1, max_length=255)
    mapping_catalog_version: Literal["1.0.0"] = "1.0.0"
    attack_catalog_version: Literal["ATT&CK v19.1"] = "ATT&CK v19.1"
    catalog_accessed_at: Literal["2026-07-22"] = "2026-07-22"
    source_url: str = Field(pattern=r"^https://attack\.mitre\.org/techniques/T[0-9]{4}/$")
    confidence: Literal["low", "medium"] = "low"
    support: str = Field(min_length=1)
    limitation: str = Field(min_length=1)
    semantics: Literal["possible mapping for analyst review; not attribution"] = (
        "possible mapping for analyst review; not attribution"
    )


class InvestigationQuery(CoreSchema):
    """Structured query suggestion; the core engine never executes it."""

    data_source: str = Field(min_length=1, max_length=128)
    objective: str = Field(min_length=1, max_length=512)
    query_template: str = Field(min_length=1)
    parameters: JsonObject = Field(default_factory=dict)
    execution: Literal["not_executed"] = "not_executed"


class ThreatHypothesis(CoreSchema):
    """Structured, explicitly uncertain threat-hunting hypothesis."""

    hypothesis_id: UUID = Field(default_factory=uuid4)
    group_id: UUID | None = None
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    confidence: Probability
    confidence_components: dict[str, float] = Field(default_factory=dict)
    severity: Severity
    involved_entities: list[str] = Field(default_factory=list)
    supporting_alert_ids: list[str] = Field(default_factory=list)
    supporting_features: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    possible_attack_category: str | None = Field(default=None, max_length=255)
    possible_mitre_mappings: list[str | PossibleMitreMapping] = Field(default_factory=list)
    observed_facts: list[str] = Field(default_factory=list)
    derived_inferences: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    alternative_explanations: list[str] = Field(default_factory=list)
    recommended_queries: list[str | InvestigationQuery] = Field(default_factory=list)
    recommended_steps: list[str] = Field(default_factory=list)
    primary_template_id: str | None = Field(default=None, max_length=255)
    template_catalog_version: Literal["1.0.0"] | None = None
    candidate_template_ids: list[str] = Field(default_factory=list)
    source_group_snapshot: JsonObject = Field(default_factory=dict)
    policy_id: str | None = Field(default=None, max_length=255)
    policy_version: str | None = Field(default=None, max_length=64)
    policy_checksum: str | None = Field(default=None, max_length=64)
    hypothesis_schema_version: Literal["1.0.0"] | None = None
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None

    @field_validator("first_seen", "last_seen", "created_at", "updated_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if self.updated_at is not None and self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.policy_checksum is not None and not _SHA256_PATTERN.fullmatch(
            self.policy_checksum
        ):
            raise ValueError("hypothesis policy checksum must be SHA-256")
        if self.hypothesis_schema_version == "1.0.0":
            expected_components = {
                "correlation",
                "rule_specificity",
                "evidence_diversity",
                "entity_coherence",
            }
            if set(self.confidence_components) != expected_components or any(
                not math.isfinite(value) or value < 0.0 or value > 1.0
                for value in self.confidence_components.values()
            ):
                raise ValueError(
                    "Phase 9 confidence components must be finite values in [0, 1]"
                )
            if self.group_id is None or len(self.supporting_alert_ids) < 2:
                raise ValueError("Phase 9 hypotheses require one alert group")
            if self.supporting_alert_ids != sorted(set(self.supporting_alert_ids)):
                raise ValueError("supporting alert IDs must be distinct and ordered")
            required_lists = (
                self.observed_facts,
                self.derived_inferences,
                self.assumptions,
                self.alternative_explanations,
                self.recommended_queries,
                self.recommended_steps,
                self.candidate_template_ids,
            )
            if any(not values for values in required_lists):
                raise ValueError("Phase 9 hypothesis evidence sections cannot be empty")
            if len(set(self.candidate_template_ids)) != len(self.candidate_template_ids):
                raise ValueError("candidate template IDs must be distinct")
            if self.primary_template_id not in self.candidate_template_ids:
                raise ValueError("primary template must be retained in candidate IDs")
            if any(isinstance(item, str) for item in self.possible_mitre_mappings):
                raise ValueError("Phase 9 possible mappings must be structured")
            if any(isinstance(item, str) for item in self.recommended_queries):
                raise ValueError("Phase 9 hypotheses require structured query suggestions")
            identity = (
                self.primary_template_id,
                self.template_catalog_version,
                self.policy_id,
                self.policy_version,
                self.policy_checksum,
                self.updated_at,
            )
            if (
                not all(identity)
                or not self.confidence_components
                or not self.source_group_snapshot
            ):
                raise ValueError("Phase 9 hypothesis identity and provenance are required")
            if self.source_group_snapshot.get(
                "hypothesis_generated_at"
            ) != self.created_at.isoformat() or not isinstance(
                self.source_group_snapshot.get("group_generated_at"), str
            ):
                raise ValueError(
                    "Phase 9 hypothesis evidence must retain lifecycle generation times"
                )
        return self


class InvestigationCase(CoreSchema):
    """Analyst-controlled investigation state and evidence references."""

    case_id: UUID = Field(default_factory=uuid4)
    hypothesis_id: UUID | None = None
    related_hypothesis_ids: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(min_length=1)
    priority: CasePriority = CasePriority.MEDIUM
    status: CaseStatus = CaseStatus.OPEN
    assigned_to: str | None = Field(default=None, max_length=255)
    evidence_references: list[str] = Field(default_factory=list)
    evidence_snapshot: JsonObject = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    related_object_ids: list[str] = Field(default_factory=list)
    verdict: AnalystVerdict | None = None
    verdict_confidence: Probability | None = None
    verdict_reason: str | None = Field(default=None, max_length=4_000)
    created_by: str | None = Field(default=None, min_length=1, max_length=255)
    case_schema_version: Literal["1.0.0"] | None = None
    policy_id: str | None = Field(default=None, max_length=255)
    policy_version: str | None = Field(default=None, max_length=64)
    policy_checksum: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    closed_at: datetime | None = None

    @field_validator("created_at", "updated_at", "closed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if self.closed_at and self.closed_at < self.created_at:
            raise ValueError("closed_at must not precede created_at")
        if self.case_schema_version == "1.0.0":
            if self.hypothesis_id is None or self.related_hypothesis_ids != sorted(
                set(self.related_hypothesis_ids)
            ):
                raise ValueError("Phase 10 cases require ordered hypothesis references")
            if str(self.hypothesis_id) not in self.related_hypothesis_ids:
                raise ValueError("primary hypothesis must be retained in related hypotheses")
            ordered_fields = (
                self.related_alert_ids,
                self.evidence_references,
                self.related_object_ids,
            )
            if any(values != sorted(set(values)) for values in ordered_fields):
                raise ValueError("Phase 10 case references must be distinct and ordered")
            identity = (
                self.created_by,
                self.policy_id,
                self.policy_version,
                self.policy_checksum,
            )
            if not all(identity) or not self.evidence_references or not self.evidence_snapshot:
                raise ValueError("Phase 10 case identity and evidence are required")
            if self.policy_checksum is None or not _SHA256_PATTERN.fullmatch(
                self.policy_checksum
            ):
                raise ValueError("case policy checksum must be SHA-256")
            if self.status is CaseStatus.CLOSED:
                if self.closed_at is None or self.verdict not in {
                    AnalystVerdict.TRUE_POSITIVE,
                    AnalystVerdict.FALSE_POSITIVE,
                    AnalystVerdict.BENIGN_EXPECTED,
                }:
                    raise ValueError("closed cases require a final analyst verdict")
            elif self.closed_at is not None:
                raise ValueError("closed_at is valid only for a closed case")
            if (self.verdict is None) != (self.verdict_confidence is None):
                raise ValueError("case verdict and confidence must be recorded together")
        return self


class CaseNote(CoreSchema):
    """Append-only analyst note associated with one investigation case."""

    note_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    author: str = Field(min_length=1, max_length=255)
    body: str = Field(min_length=1, max_length=8_000)
    note_type: Literal["investigation", "closure", "correction"] = "investigation"
    created_at: datetime = Field(default_factory=utc_now)
    note_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class CaseEvidenceReference(CoreSchema):
    """Immutable typed reference and canonical evidence snapshot."""

    reference_id: UUID = Field(default_factory=uuid4)
    case_id: UUID
    object_type: CaseEvidenceObjectType
    object_id: str = Field(min_length=1, max_length=255)
    object_schema_version: str | None = Field(default=None, max_length=64)
    snapshot: JsonObject = Field(min_length=1)
    snapshot_checksum: str = Field(min_length=64, max_length=64)
    description: str = Field(min_length=1, max_length=1_000)
    added_by: str = Field(min_length=1, max_length=255)
    added_at: datetime = Field(default_factory=utc_now)
    evidence_reference_schema_version: Literal["1.0.0"] = "1.0.0"

    @field_validator("snapshot_checksum")
    @classmethod
    def validate_snapshot_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not _SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("evidence snapshot checksum must be SHA-256")
        return normalized

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str) -> str:
        normalized = value.strip()
        if "://" in normalized or "<" in normalized or ">" in normalized:
            raise ValueError("evidence description must be plain text without URLs")
        return normalized

    @field_validator("added_at")
    @classmethod
    def validate_added_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class AnalystFeedback(CoreSchema):
    """Explicit analyst verdict attached to a persisted object."""

    feedback_id: UUID = Field(default_factory=uuid4)
    object_type: FeedbackObjectType
    object_id: str = Field(min_length=1, max_length=255)
    verdict: AnalystVerdict
    confidence: Probability
    notes: str = Field(default="", max_length=4_000)
    actor: str | None = Field(default=None, min_length=1, max_length=255)
    source: str | None = Field(default=None, min_length=1, max_length=255)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime | None = None
    feedback_schema_version: Literal["1.0.0"] | None = None
    related_case_id: UUID | None = None
    provenance: JsonObject = Field(default_factory=dict)
    correction_reason: str | None = Field(default=None, max_length=4_000)

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamp(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_phase_ten_feedback(self) -> Self:
        if self.updated_at is not None and self.updated_at < self.created_at:
            raise ValueError("feedback updated_at must not precede created_at")
        if self.feedback_schema_version == "1.0.0":
            if self.actor is None or self.source is None or self.updated_at is None:
                raise ValueError("Phase 10 feedback requires actor, source, and updated_at")
            if not self.provenance:
                raise ValueError("Phase 10 feedback requires explicit provenance")
        return self
