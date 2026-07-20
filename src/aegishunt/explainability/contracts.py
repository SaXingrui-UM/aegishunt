"""Versioned, serializable explanation and artifact contracts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.schemas.base import JsonObject, require_aware_utc

EffectDirection = Literal["increases_suspicion", "decreases_suspicion", "neutral"]
FactInferenceClass = Literal["observed_fact", "model_inference"]


class ExplanationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class FeatureReference(ExplanationModel):
    feature_name: str
    dtype: Literal["float64"]
    count: int = Field(ge=1)
    minimum: float
    q05: float
    q25: float
    median: float
    q75: float
    q95: float
    maximum: float
    finite: Literal[True]

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        values = (
            self.minimum,
            self.q05,
            self.q25,
            self.median,
            self.q75,
            self.q95,
            self.maximum,
        )
        if any(left > right for left, right in zip(values, values[1:], strict=False)):
            raise ValueError("reference quantiles are not monotonic")
        return self


class ReferenceProfile(ExplanationModel):
    profile_schema_version: Literal["1.0.0"]
    profile_id: str
    profile_version: str
    dataset_id: str
    dataset_version: str
    dataset_checksum: str
    split_checksum: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    source_partition: Literal["train"]
    benign_only: Literal[True]
    test_data_used: Literal[False]
    benign_row_count: int = Field(ge=1)
    benign_group_count: int = Field(ge=1)
    reference_range: Literal["q05_q95"]
    features: tuple[FeatureReference, ...]
    generation_config: JsonObject
    git_commit_sha: str | None
    created_at: datetime

    @field_validator("dataset_checksum", "split_checksum")
    @classmethod
    def validate_checksum(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("reference-profile checksum must be SHA-256")
        return normalized

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_features(self) -> Self:
        names = tuple(item.feature_name for item in self.features)
        if names != self.feature_names or len(names) != len(set(names)):
            raise ValueError("reference profile feature order is invalid")
        if any(item.count != self.benign_row_count for item in self.features):
            raise ValueError("reference profile feature counts are inconsistent")
        return self


class ImportanceEntry(ExplanationModel):
    feature_name: str
    mean: float
    standard_deviation: float = Field(ge=0.0)


class GlobalImportanceReport(ExplanationModel):
    report_schema_version: Literal["1.0.0"]
    report_id: str
    method: Literal["native_tree_importance"]
    status: Literal["available", "not_applicable"]
    model_id: str
    model_version: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    entries: tuple[ImportanceEntry, ...]
    semantics: Literal["model association or sensitivity; not causation"]
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        if self.status == "not_applicable":
            if self.entries:
                raise ValueError("unavailable native importance cannot contain values")
            return self
        if tuple(item.feature_name for item in self.entries) != self.feature_names:
            raise ValueError("native importance feature order is invalid")
        if any(item.mean < 0.0 for item in self.entries):
            raise ValueError("native tree importance cannot be negative")
        return self


class PermutationImportanceReport(ExplanationModel):
    report_schema_version: Literal["1.0.0"]
    report_id: str
    method: Literal["permutation_importance"]
    model_id: str
    model_version: str
    feature_schema_version: str
    feature_names: tuple[str, ...]
    source_partition: Literal["validation"]
    test_data_used: Literal[False]
    scoring_metric: str
    random_seed: int
    repeats: int = Field(ge=1, le=100)
    row_count: int = Field(ge=2)
    group_count: int = Field(ge=1)
    entries: tuple[ImportanceEntry, ...]
    semantics: Literal["model sensitivity to feature permutation; not causation"]
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        if tuple(item.feature_name for item in self.entries) != self.feature_names:
            raise ValueError("permutation importance feature order is invalid")
        return self


class LocalContribution(ExplanationModel):
    feature_name: str
    observed_value: float
    reference_median: float
    reference_low: float
    reference_high: float
    risk_with_observed: float = Field(ge=0.0, le=1.0)
    risk_with_reference_replacement: float = Field(ge=0.0, le=1.0)
    effect_delta: float = Field(ge=-1.0, le=1.0)
    effect_direction: EffectDirection
    method: Literal["single_feature_reference_replacement"]
    limitations: tuple[str, ...]


class ReasonCatalogEntry(ExplanationModel):
    code: str
    version: str
    category: Literal["flow_behavior", "supervised", "anomaly", "multi_engine", "risk"]
    trigger_source: str
    trigger_condition: str
    evidence_type: Literal["feature_reference", "configured_threshold", "boolean_feature"]
    classification: FactInferenceClass
    description_template: str
    limitations: tuple[str, ...]
    enabled_in_phase_8: bool


class ReasonCodeCatalog(ExplanationModel):
    catalog_schema_version: Literal["1.0.0"]
    catalog_id: Literal["aegishunt-phase-08-reason-codes"]
    catalog_version: Literal["1.0.0"]
    entries: tuple[ReasonCatalogEntry, ...]

    @model_validator(mode="after")
    def validate_entries(self) -> Self:
        codes = tuple(item.code for item in self.entries)
        if len(codes) != len(set(codes)):
            raise ValueError("reason-code catalog entries must be unique")
        return self


class ReasonEvidence(ExplanationModel):
    code: str
    version: str
    observed_value: float | int | bool
    reference_low: float | None = None
    reference_high: float | None = None
    configured_threshold: float | None = None
    description: str
    evidence_type: str
    classification: FactInferenceClass
    limitations: tuple[str, ...]


class Explanation(ExplanationModel):
    explanation_schema_version: Literal["1.0.0"]
    observed_facts: JsonObject
    model_inferences: tuple[str, ...]
    local_contributions: tuple[LocalContribution, ...]
    reason_evidence: tuple[ReasonEvidence, ...]
    limitations: tuple[str, ...]

    @model_validator(mode="after")
    def validate_truthfulness(self) -> Self:
        required = {
            "Risk score is operational suspiciousness, not attack probability.",
            "Feature importance and local contributions are non-causal model sensitivity evidence.",
            "An alert is suspicious activity requiring analyst review, not a confirmed attack.",
            "Phase 7 fusion recommendation remains inconclusive.",
            "Phase 6 LOF remains validation-qualified without an untouched independent holdout.",
        }
        if not required.issubset(self.limitations):
            raise ValueError("explanation limitations are incomplete")
        return self


class ExplanationArtifactManifest(ExplanationModel):
    manifest_schema_version: Literal["1.0.0"]
    artifact_id: str
    artifact_version: str
    file_inventory: tuple[str, ...]
    reference_profile_id: str
    reference_profile_version: str
    native_importance_report_id: str
    permutation_importance_report_id: str
    reason_catalog_id: str
    reason_catalog_version: str
    supervised_model_id: str
    supervised_model_version: str
    anomaly_model_id: str
    anomaly_model_version: str
    fusion_policy_id: str
    fusion_policy_version: str
    risk_policy_id: str
    risk_policy_version: str
    feature_schema_version: str
    pipeline_verification_only: Literal[True]
    public_benchmark: Literal[False]
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        return require_aware_utc(value)


class ExplanationArtifactChecksums(ExplanationModel):
    checksum_schema_version: Literal["1.0.0"]
    checksums: dict[str, str]

    @field_validator("checksums")
    @classmethod
    def validate_checksums(cls, values: dict[str, str]) -> dict[str, str]:
        if not values:
            raise ValueError("artifact checksums cannot be empty")
        normalized: dict[str, str] = {}
        for name, value in values.items():
            digest = value.strip().lower()
            if not SHA256_PATTERN.fullmatch(digest):
                raise ValueError("artifact checksum must be SHA-256")
            normalized[name] = digest
        return normalized


class LoadedExplanationArtifact(ExplanationModel):
    manifest: ExplanationArtifactManifest
    reference_profile: ReferenceProfile
    native_importance: GlobalImportanceReport
    permutation_importance: PermutationImportanceReport
    reason_catalog: ReasonCodeCatalog
    protocol: str
