"""ORM records for telemetry sources and canonical network flows."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, ForeignKey, Index, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, NetworkProtocol, SourceType
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class TelemetrySourceRecord(Base):
    """Persistent source provenance without ingestion implementation."""

    __tablename__ = "telemetry_sources"

    source_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    source_type: Mapped[SourceType] = mapped_column(
        string_enum(SourceType, name="source_type"), nullable=False
    )
    filename_or_interface: Mapped[str] = mapped_column(String(512), nullable=False)
    ingestion_mode: Mapped[IngestionMode] = mapped_column(
        string_enum(IngestionMode, name="ingestion_mode"), nullable=False
    )
    status: Mapped[LifecycleStatus] = mapped_column(
        string_enum(LifecycleStatus, name="lifecycle_status"), nullable=False, index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    records_processed: Mapped[int] = mapped_column(nullable=False, default=0)
    checksum: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    source_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON, nullable=False, default=dict
    )


class NetworkFlowRecord(Base):
    """Persistent canonical flow contract for Phase 3 producers."""

    __tablename__ = "network_flows"
    __table_args__ = (Index("ix_network_flows_source_time", "source_id", "first_seen"),)

    flow_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    source_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("telemetry_sources.source_id"), nullable=False
    )
    capture_session_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False)
    duration: Mapped[float] = mapped_column(nullable=False)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_port: Mapped[int | None] = mapped_column(nullable=True)
    destination_port: Mapped[int | None] = mapped_column(nullable=True)
    protocol: Mapped[NetworkProtocol] = mapped_column(
        string_enum(NetworkProtocol, name="network_protocol"), nullable=False
    )
    forward_packet_count: Mapped[int] = mapped_column(nullable=False)
    backward_packet_count: Mapped[int] = mapped_column(nullable=False)
    forward_bytes: Mapped[int] = mapped_column(nullable=False)
    backward_bytes: Mapped[int] = mapped_column(nullable=False)
    behavioral_features: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    ground_truth_label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attack_family: Mapped[str | None] = mapped_column(String(255), nullable=True)
