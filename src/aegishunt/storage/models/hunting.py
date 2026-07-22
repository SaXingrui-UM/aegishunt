"""ORM records for hypotheses, cases, and feedback."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
    FeedbackObjectType,
    HypothesisStatus,
    Severity,
)
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class ThreatHypothesisRecord(Base):
    __tablename__ = "threat_hypotheses"

    hypothesis_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    group_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("alert_groups.group_id"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    confidence_components: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    severity: Mapped[Severity] = mapped_column(
        string_enum(Severity, name="hypothesis_severity"), nullable=False, index=True
    )
    involved_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_features: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    possible_attack_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    possible_mitre_mappings: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    observed_facts: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    derived_inferences: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assumptions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternative_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_queries: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    recommended_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    primary_template_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    template_catalog_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    candidate_template_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_group_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    policy_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hypothesis_schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[HypothesisStatus] = mapped_column(
        string_enum(HypothesisStatus, name="hypothesis_status"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class InvestigationCaseRecord(Base):
    __tablename__ = "investigation_cases"

    case_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    hypothesis_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("threat_hypotheses.hypothesis_id"), nullable=True
    )
    related_hypothesis_ids: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )
    related_alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    priority: Mapped[CasePriority] = mapped_column(
        string_enum(CasePriority, name="case_priority"), nullable=False, index=True
    )
    status: Mapped[CaseStatus] = mapped_column(
        string_enum(CaseStatus, name="case_status"), nullable=False, index=True
    )
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_references: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    notes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    related_object_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    verdict: Mapped[AnalystVerdict | None] = mapped_column(
        string_enum(AnalystVerdict, name="case_verdict"), nullable=True
    )
    verdict_confidence: Mapped[float | None] = mapped_column(nullable=True)
    verdict_reason: Mapped[str | None] = mapped_column(nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    case_schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_checksum: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)


class AnalystFeedbackRecord(Base):
    __tablename__ = "analyst_feedback"

    feedback_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    object_type: Mapped[FeedbackObjectType] = mapped_column(
        string_enum(FeedbackObjectType, name="feedback_object_type"), nullable=False, index=True
    )
    object_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    verdict: Mapped[AnalystVerdict] = mapped_column(
        string_enum(AnalystVerdict, name="analyst_verdict"), nullable=False, index=True
    )
    confidence: Mapped[float] = mapped_column(nullable=False)
    notes: Mapped[str] = mapped_column(nullable=False, default="")
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    updated_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    feedback_schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    related_case_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigation_cases.case_id"), nullable=True, index=True
    )
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    correction_reason: Mapped[str | None] = mapped_column(nullable=True)


class CaseNoteRecord(Base):
    __tablename__ = "case_notes"

    note_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigation_cases.case_id"), nullable=False, index=True
    )
    author: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    body: Mapped[str] = mapped_column(nullable=False)
    note_type: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    note_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)


class CaseEvidenceReferenceRecord(Base):
    __tablename__ = "case_evidence_references"

    reference_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    case_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("investigation_cases.case_id"), nullable=False, index=True
    )
    object_type: Mapped[CaseEvidenceObjectType] = mapped_column(
        string_enum(CaseEvidenceObjectType, name="case_evidence_object_type"),
        nullable=False,
        index=True,
    )
    object_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    object_schema_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    snapshot_checksum: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    description: Mapped[str] = mapped_column(nullable=False)
    added_by: Mapped[str] = mapped_column(String(255), nullable=False)
    added_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    evidence_reference_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
