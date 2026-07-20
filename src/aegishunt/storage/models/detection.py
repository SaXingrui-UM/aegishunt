"""ORM records for detection, alerts, and alert groups."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import AlertStatus, AnalystVerdict, Severity
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class DetectionResultRecord(Base):
    __tablename__ = "detection_results"

    detection_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    flow_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("network_flows.flow_id"), nullable=False, index=True
    )
    supervised_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    supervised_probability: Mapped[float | None] = mapped_column(nullable=True)
    supervised_threshold: Mapped[float] = mapped_column(nullable=False)
    anomaly_raw_score: Mapped[float] = mapped_column("anomaly_score", nullable=False)
    normalized_anomaly_score: Mapped[float] = mapped_column(nullable=False)
    anomaly_threshold: Mapped[float] = mapped_column(nullable=False)
    fusion_score: Mapped[float] = mapped_column(nullable=False)
    fusion_threshold: Mapped[float] = mapped_column(nullable=False)
    behavioral_rule_score: Mapped[float | None] = mapped_column(nullable=True)
    risk_score: Mapped[float] = mapped_column("combined_risk_score", nullable=False)
    risk_source: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[Severity] = mapped_column(
        string_enum(Severity, name="severity"), nullable=False, index=True
    )
    alert_threshold: Mapped[float] = mapped_column(nullable=False)
    model_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_checksums: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    feature_schema_version: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)


class SecurityAlertRecord(Base):
    __tablename__ = "security_alerts"

    alert_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    detection_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("detection_results.detection_id"), nullable=False, index=True
    )
    alert_type: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    severity: Mapped[Severity] = mapped_column(
        string_enum(Severity, name="alert_severity"), nullable=False, index=True
    )
    risk_score: Mapped[float] = mapped_column(nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    involved_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    explanation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    model_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    policy_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[AlertStatus] = mapped_column(
        string_enum(AlertStatus, name="alert_status"), nullable=False, index=True
    )
    analyst_verdict: Mapped[AnalystVerdict | None] = mapped_column(
        string_enum(AnalystVerdict, name="analyst_verdict"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)


class AlertGroupRecord(Base):
    __tablename__ = "alert_groups"

    group_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    entity_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    correlation_score: Mapped[float] = mapped_column(nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    summary: Mapped[str] = mapped_column(nullable=False)
