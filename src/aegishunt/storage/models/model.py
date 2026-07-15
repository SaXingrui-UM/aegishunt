"""ORM record for controlled model-version metadata."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from aegishunt.schemas.enums import ModelStatus, ModelType
from aegishunt.storage.base import Base, UTCDateTime, string_enum


class ModelVersionRecord(Base):
    __tablename__ = "model_versions"
    __table_args__ = (UniqueConstraint("model_type", "version", name="uq_model_type_version"),)

    model_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    model_type: Mapped[ModelType] = mapped_column(
        string_enum(ModelType, name="model_type"), nullable=False, index=True
    )
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(255), nullable=False)
    feature_schema: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    training_dataset: Mapped[str] = mapped_column(String(512), nullable=False)
    training_config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    artifact_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, index=True)
    status: Mapped[ModelStatus] = mapped_column(
        string_enum(ModelStatus, name="model_status"), nullable=False, index=True
    )
