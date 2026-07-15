"""Telemetry source and network-flow schemas."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Self
from uuid import UUID, uuid4

from pydantic import AliasChoices, Field, field_validator, model_validator

from aegishunt.schemas.base import (
    CoreSchema,
    JsonObject,
    NonNegativeFloat,
    NonNegativeInt,
    Port,
    require_aware_utc,
)
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, NetworkProtocol, SourceType

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class TelemetrySource(CoreSchema):
    """Validated provenance for one future telemetry ingestion operation."""

    source_id: UUID = Field(default_factory=uuid4)
    source_type: SourceType
    filename_or_interface: str = Field(min_length=1, max_length=512)
    ingestion_mode: IngestionMode
    status: LifecycleStatus = LifecycleStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    records_processed: NonNegativeInt = 0
    checksum: str | None = None
    source_metadata: JsonObject = Field(
        default_factory=dict,
        validation_alias=AliasChoices("source_metadata", "metadata"),
        serialization_alias="metadata",
    )

    @field_validator("started_at", "completed_at")
    @classmethod
    def validate_timestamps(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @field_validator("checksum")
    @classmethod
    def validate_checksum(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("checksum must be a lowercase SHA-256 hex digest")
        return normalized

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.started_at and self.completed_at and self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class NetworkFlow(CoreSchema):
    """Canonical bidirectional flow record contract for later processing."""

    flow_id: UUID = Field(default_factory=uuid4)
    source_id: UUID
    capture_session_id: str = Field(min_length=1, max_length=255)
    first_seen: datetime
    last_seen: datetime
    duration: NonNegativeFloat
    source_ip: str
    destination_ip: str
    source_port: Port | None = None
    destination_port: Port | None = None
    protocol: NetworkProtocol
    forward_packet_count: NonNegativeInt
    backward_packet_count: NonNegativeInt
    forward_bytes: NonNegativeInt
    backward_bytes: NonNegativeInt
    behavioral_features: JsonObject = Field(default_factory=dict)
    ground_truth_label: str | None = Field(default=None, max_length=255)
    attack_family: str | None = Field(default=None, max_length=255)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def validate_timestamps(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("invalid IP address") from exc

    @model_validator(mode="after")
    def validate_time_order(self) -> Self:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        return self
