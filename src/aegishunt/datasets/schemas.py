"""Strict serializable contracts for Phase 4 dataset operations."""

from __future__ import annotations

import math
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from aegishunt.flows.registry import FEATURE_DEFINITIONS, FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.schemas.base import require_aware_utc

DATASET_SCHEMA_VERSION = "1.0.0"
CANONICAL_SCHEMA_VERSION = "1.0.0"
CONVERSION_VERSION = "1.0.0"
LABEL_SCHEMA_VERSION = "1.0.0"
DATASET_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class DatasetModel(BaseModel):
    """Immutable strict base for registry and canonical records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class DatasetFileDefinition(DatasetModel):
    """One expected provider file without a local machine path."""

    filename: str = Field(min_length=1, max_length=512)
    checksum_sha256: str | None = None
    required: bool = True

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
            raise ValueError("expected dataset filename must be a safe basename")
        return value

    @field_validator("checksum_sha256")
    @classmethod
    def validate_checksum(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("checksum must be a lowercase SHA-256 digest")
        return normalized


class DatasetDefinition(DatasetModel):
    """Static official-source definition stored in the project registry."""

    dataset_id: str
    name: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=64)
    dataset_type: Literal["public_benchmark", "controlled_demo"]
    source_url: HttpUrl | None
    official_page: HttpUrl | None
    provider: str = Field(min_length=1, max_length=255)
    license_name: str = Field(min_length=1, max_length=255)
    license_url: HttpUrl | None
    academic_use_status: Literal["permitted", "manual_review_required", "not_applicable"]
    expected_format: tuple[Literal["pcap", "pcapng", "csv", "json", "jsonl", "archive"], ...]
    expected_files: tuple[DatasetFileDefinition, ...]
    expected_checksum: str | None = None
    locally_computed_checksum: str | None = None
    raw_schema_reference: str = Field(min_length=1, max_length=512)
    canonical_schema_version: str
    feature_schema_version: str
    label_schema: str = Field(min_length=1, max_length=512)
    group_fields: tuple[str, ...]
    download_status: Literal["automatic", "manual_required", "generated_offline", "unavailable"]
    conversion_status: Literal["supported", "provisional", "blocked"]
    known_limitations: tuple[str, ...]
    citation: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime

    @field_validator("dataset_id")
    @classmethod
    def validate_dataset_id(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not DATASET_ID_PATTERN.fullmatch(normalized):
            raise ValueError("dataset_id must be stable lowercase kebab-case")
        return normalized

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @field_validator("expected_checksum", "locally_computed_checksum")
    @classmethod
    def validate_optional_checksum(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("registry checksum must be a lowercase SHA-256 digest")
        return normalized

    @model_validator(mode="after")
    def validate_definition(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("updated_at must not precede created_at")
        if len(set(self.group_fields)) != len(self.group_fields) or not self.group_fields:
            raise ValueError("group_fields must contain unique values")
        if self.dataset_type == "public_benchmark" and self.official_page is None:
            raise ValueError("public benchmarks require an official page")
        if self.academic_use_status == "permitted" and self.license_url is None:
            raise ValueError("permitted academic use requires official license evidence")
        if self.download_status == "automatic" and self.source_url is None:
            raise ValueError("automatic downloads require a source URL")
        if self.canonical_schema_version != CANONICAL_SCHEMA_VERSION:
            raise ValueError("unsupported canonical schema version")
        if self.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError("dataset feature schema must match Phase 3")
        return self


class DatasetRegistryDocument(DatasetModel):
    """Versioned registry file containing unique definitions."""

    registry_schema_version: str
    datasets: tuple[DatasetDefinition, ...]

    @model_validator(mode="after")
    def validate_registry(self) -> Self:
        if self.registry_schema_version != DATASET_SCHEMA_VERSION:
            raise ValueError("unsupported dataset registry schema version")
        identifiers = [entry.dataset_id for entry in self.datasets]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("dataset registry IDs must be unique")
        return self


class LocalDatasetState(DatasetModel):
    """Machine-local status intentionally stored separately from definitions."""

    dataset_id: str
    status: Literal["not_present", "downloaded", "verified", "converted", "failed"]
    computed_checksums: dict[str, str] = Field(default_factory=dict)
    last_error_code: str | None = None
    updated_at: datetime

    @field_validator("updated_at")
    @classmethod
    def validate_updated_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class CanonicalMetadata(DatasetModel):
    """Non-feature provenance retained for grouping and reproducibility."""

    dataset_id: str
    dataset_version: str
    record_id: str = Field(min_length=1, max_length=255)
    source_file: str = Field(min_length=1, max_length=512)
    source_file_checksum: str
    capture_session_id: str = Field(min_length=1, max_length=255)
    scenario_id: str = Field(min_length=1, max_length=255)
    group_id: str = Field(min_length=1, max_length=255)
    original_row_id: str = Field(min_length=1, max_length=255)
    observed_at: datetime | None = None
    provenance: dict[str, str]
    conversion_version: str

    @field_validator("source_file")
    @classmethod
    def validate_source_file(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("source_file must be a safe relative identifier")
        return path.as_posix()

    @field_validator("source_file_checksum")
    @classmethod
    def validate_source_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("source_file_checksum must be a SHA-256 digest")
        return normalized

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime | None) -> datetime | None:
        return None if value is None else require_aware_utc(value)

    @model_validator(mode="after")
    def validate_versions(self) -> Self:
        if self.conversion_version != CONVERSION_VERSION:
            raise ValueError("unsupported conversion version")
        if any(not key.strip() or not value.strip() for key, value in self.provenance.items()):
            raise ValueError("provenance keys and values must be non-empty")
        return self


class CanonicalFeatureVector(DatasetModel):
    """The only model-eligible columns, bound to the Phase 3 order."""

    schema_version: str
    names: tuple[str, ...]
    values: tuple[float, ...]

    @model_validator(mode="after")
    def validate_vector(self) -> Self:
        if self.schema_version != FEATURE_SCHEMA_VERSION:
            raise ValueError("feature schema version does not match Phase 3")
        if self.names != feature_names():
            raise ValueError("feature names or order do not match Phase 3")
        if len(self.values) != len(FEATURE_DEFINITIONS):
            raise ValueError("feature vector length does not match Phase 3")
        for definition, value in zip(FEATURE_DEFINITIONS, self.values, strict=True):
            if not math.isfinite(value):
                raise ValueError(f"feature must be finite: {definition.name}")
            if definition.data_type == "integer" and not value.is_integer():
                raise ValueError(f"feature must be integer-valued: {definition.name}")
            if definition.minimum is not None and value < definition.minimum:
                raise ValueError(f"feature is below its minimum: {definition.name}")
            if definition.maximum is not None and value > definition.maximum:
                raise ValueError(f"feature is above its maximum: {definition.name}")
        return self


BinaryLabel = Annotated[int, Field(ge=0, le=1)]


class CanonicalLabels(DatasetModel):
    """Ground truth kept outside the model feature vector."""

    ground_truth_label: str = Field(min_length=1, max_length=255)
    binary_label: BinaryLabel | None
    attack_family: str = Field(min_length=1, max_length=255)
    original_label: str = Field(min_length=1, max_length=255)
    label_mapping_version: str = Field(min_length=1, max_length=64)


class CanonicalDatasetRow(DatasetModel):
    """One deterministic canonical row with sealed metadata/feature/label sections."""

    canonical_schema_version: str
    metadata: CanonicalMetadata
    features: CanonicalFeatureVector
    labels: CanonicalLabels

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if self.canonical_schema_version != CANONICAL_SCHEMA_VERSION:
            raise ValueError("unsupported canonical dataset schema version")
        return self


class LabelMappingRule(DatasetModel):
    """One normalized alias-to-label rule."""

    aliases: tuple[str, ...]
    ground_truth_label: str
    binary_label: BinaryLabel
    attack_family: str

    @field_validator("aliases")
    @classmethod
    def validate_aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(alias.strip().casefold() for alias in value if alias.strip())
        if not normalized or len(normalized) != len(set(normalized)):
            raise ValueError("label aliases must be unique and non-empty")
        return normalized


class LabelMappingDocument(DatasetModel):
    """Versioned auditable label normalization configuration."""

    dataset_id: str
    mapping_version: str
    unknown_label_policy: Literal["fail", "unmapped"]
    rules: tuple[LabelMappingRule, ...]

    @model_validator(mode="after")
    def validate_mapping(self) -> Self:
        aliases = [alias for rule in self.rules for alias in rule.aliases]
        if len(aliases) != len(set(aliases)):
            raise ValueError("label aliases must not map to multiple rules")
        return self


class SplitAssignment(DatasetModel):
    """One canonical row assigned to a named immutable partition."""

    split: Literal["train", "validation", "test"]
    row: CanonicalDatasetRow
