"""Machine-readable Phase 4 report and manifest contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from aegishunt.datasets.schemas import DatasetModel
from aegishunt.schemas.base import require_aware_utc

ReportStatus = Literal["pass", "fail", "warning"]
Severity = Literal["blocking", "high", "medium", "low", "informational"]


class QualityFinding(DatasetModel):
    """One evidence-backed quality or leakage observation."""

    code: str
    severity: Severity
    message: str
    evidence: tuple[str, ...] = ()
    remediation: str


class QualityReport(DatasetModel):
    """Deterministic summary of canonical schema and statistical quality."""

    report_schema_version: str
    canonical_schema_version: str
    feature_schema_version: str
    status: ReportStatus
    row_count: int = Field(ge=0)
    group_count: int = Field(ge=0)
    missing_counts: dict[str, int]
    missing_percentages: dict[str, float]
    exact_duplicate_count: int = Field(ge=0)
    feature_duplicate_count: int = Field(ge=0)
    conflicting_label_fingerprint_count: int = Field(ge=0)
    provenance_duplicate_count: int = Field(ge=0)
    near_duplicate_count: int = Field(ge=0)
    near_duplicate_groups: tuple[str, ...]
    near_duplicate_tolerance: float = Field(gt=0.0)
    constant_features: tuple[str, ...]
    near_constant_features: tuple[str, ...]
    all_zero_features: tuple[str, ...]
    invalid_features: tuple[str, ...]
    binary_class_distribution: dict[str, int]
    binary_class_percentages: dict[str, float]
    attack_family_distribution: dict[str, int]
    attack_family_percentages: dict[str, float]
    group_class_distribution: dict[str, dict[str, int]]
    findings: tuple[QualityFinding, ...]


class LeakageReport(DatasetModel):
    """Fail-closed split leakage validation evidence."""

    report_schema_version: str
    status: Literal["pass", "fail"]
    group_overlap: tuple[str, ...]
    source_file_overlap: tuple[str, ...]
    session_overlap: tuple[str, ...]
    scenario_overlap: tuple[str, ...]
    exact_duplicate_overlap: tuple[str, ...]
    near_duplicate_overlap: tuple[str, ...]
    label_derived_features: tuple[str, ...]
    suspicious_metadata: tuple[str, ...]
    filename_leakage: tuple[str, ...]
    timestamp_leakage: tuple[str, ...]
    record_id_leakage: tuple[str, ...]
    correlation_warnings: tuple[str, ...]
    unique_value_label_warnings: tuple[str, ...]
    attack_family_considerations: tuple[str, ...]
    findings: tuple[QualityFinding, ...]


class SplitManifest(DatasetModel):
    """Reproducible group-exclusive split contract."""

    manifest_schema_version: str
    dataset_id: str
    dataset_version: str
    split_strategy: str
    group_key: str
    random_seed: int
    configured_ratios: dict[str, float]
    actual_ratios: dict[str, float]
    train_groups: tuple[str, ...]
    validation_groups: tuple[str, ...]
    test_groups: tuple[str, ...]
    row_counts: dict[str, int]
    group_counts: dict[str, int]
    class_distributions: dict[str, dict[str, int]]
    attack_family_distributions: dict[str, dict[str, int]]
    overlap_validation_result: Literal["pass", "fail"]
    source_file_overlap_result: Literal["pass", "fail"]
    frozen_test: bool
    test_usage_policy: str
    dataset_checksum: str
    canonical_schema_version: str
    feature_schema_version: str


class DatasetManifest(DatasetModel):
    """Auditable provenance and generation manifest for one processed dataset."""

    manifest_schema_version: str
    dataset_id: str
    dataset_version: str
    dataset_type: str
    source: str
    provider: str
    license_name: str
    access_date: str
    raw_files: tuple[str, ...]
    raw_checksums: dict[str, str]
    processed_files: tuple[str, ...]
    processed_checksums: dict[str, str]
    row_count: int = Field(ge=0)
    group_count: int = Field(ge=0)
    feature_schema_version: str
    canonical_schema_version: str
    label_mapping_version: str
    conversion_version: str
    generation_config: dict[str, object]
    random_seed: int
    quality_status: ReportStatus
    known_limitations: tuple[str, ...]
    creation_timestamp: datetime
    tool_version: str
    git_commit_sha: str | None

    @field_validator("creation_timestamp")
    @classmethod
    def validate_creation_timestamp(cls, value: datetime) -> datetime:
        return require_aware_utc(value)
