"""ORM records for hypotheses, cases, and feedback."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import (
    AnalystVerdict,
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
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    severity: Mapped[Severity] = mapped_column(
        string_enum(Severity, name="hypothesis_severity"), nullable=False, index=True
    )
    involved_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_features: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    possible_attack_category: Mapped[str | None] = mapped_column(String(255), nullable=True)
    possible_mitre_mappings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    assumptions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternative_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_queries: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_steps: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[HypothesisStatus] = mapped_column(
        string_enum(HypothesisStatus, name="hypothesis_status"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)


class InvestigationCaseRecord(Base):
    __tablename__ = "investigation_cases"

    case_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    hypothesis_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("threat_hypotheses.hypothesis_id"), nullable=True
    )
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
    notes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    related_object_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    verdict: Mapped[AnalystVerdict | None] = mapped_column(
        string_enum(AnalystVerdict, name="case_verdict"), nullable=True
    )
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
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
