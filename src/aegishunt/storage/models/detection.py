"""ORM records for detection, alerts, and alert groups."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import AlertStatus, Severity
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class DetectionResultRecord(Base):
    __tablename__ = "detection_results"

    detection_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    flow_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("network_flows.flow_id"), nullable=False, index=True
    )
    supervised_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    supervised_probability: Mapped[float | None] = mapped_column(nullable=True)
    anomaly_score: Mapped[float | None] = mapped_column(nullable=True)
    normalized_anomaly_score: Mapped[float | None] = mapped_column(nullable=True)
    behavioral_rule_score: Mapped[float | None] = mapped_column(nullable=True)
    combined_risk_score: Mapped[float] = mapped_column(nullable=False)
    severity: Mapped[Severity] = mapped_column(
        string_enum(Severity, name="severity"), nullable=False, index=True
    )
    model_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
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
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(nullable=False)
    involved_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[AlertStatus] = mapped_column(
        string_enum(AlertStatus, name="alert_status"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)


class AlertGroupRecord(Base):
    __tablename__ = "alert_groups"

    group_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    alert_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    entity_keys: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    correlation_score: Mapped[float] = mapped_column(nullable=False)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    summary: Mapped[str] = mapped_column(nullable=False)
