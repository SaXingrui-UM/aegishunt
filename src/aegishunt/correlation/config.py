"""Validated, checksummed Phase 9 correlation policy loading."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from aegishunt.correlation.contracts import EntityType
from aegishunt.correlation.errors import CorrelationConfigError
from aegishunt.datasets.schemas import SHA256_PATTERN
from aegishunt.schemas.enums import Severity

RULE_IDS = (
    "source_centered_reconnaissance",
    "repeated_source_destination_failures",
    "source_fan_out",
    "destination_fan_in",
    "periodic_beacon_like_activity",
    "multi_engine_evidence",
    "multi_alert_accumulation",
)


class PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class ScoreWeights(PolicyModel):
    risk: float = Field(ge=0.0, le=1.0)
    alert_count: float = Field(ge=0.0, le=1.0)
    evidence_diversity: float = Field(ge=0.0, le=1.0)
    temporal_density: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def sum_to_one(self) -> Self:
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-9:
            raise ValueError("correlation score weights must sum to 1.0")
        return self


class ConfidenceWeights(PolicyModel):
    correlation: float = Field(ge=0.0, le=1.0)
    rule_specificity: float = Field(ge=0.0, le=1.0)
    evidence_diversity: float = Field(ge=0.0, le=1.0)
    entity_coherence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def sum_to_one(self) -> Self:
        if abs(sum(self.model_dump().values()) - 1.0) > 1e-9:
            raise ValueError("hypothesis confidence weights must sum to 1.0")
        return self


class SeverityBand(PolicyModel):
    minimum_score: float = Field(ge=0.0, le=1.0)
    severity: Severity


class CorrelationPolicy(PolicyModel):
    """Complete critical policy; missing values fail closed."""

    policy_schema_version: Literal["1.0.0"]
    policy_id: str = Field(min_length=1, max_length=255)
    policy_version: str = Field(min_length=1, max_length=64)
    correlation_window_seconds: float = Field(gt=0.0, le=86_400.0)
    minimum_alerts: int = Field(ge=2, le=1_000)
    maximum_alerts_per_group: int = Field(ge=2, le=10_000)
    maximum_alerts_per_run: int = Field(ge=2, le=1_000_000)
    maximum_entities_per_alert: int = Field(ge=1, le=128)
    maximum_entity_value_length: int = Field(ge=1, le=1_024)
    enabled_entity_keys: tuple[EntityType, ...] = Field(min_length=1)
    score_weights: ScoreWeights
    risk_aggregation: Literal["mean", "maximum"]
    alert_count_reference: int = Field(ge=2, le=1_000)
    evidence_diversity_reference: int = Field(ge=1, le=100)
    temporal_decay_factor: float = Field(gt=0.0, le=100.0)
    group_score_threshold: float = Field(ge=0.0, le=1.0)
    hypothesis_generation_threshold: float = Field(ge=0.0, le=1.0)
    minimum_distinct_reason_codes: int = Field(ge=1, le=100)
    minimum_distinct_destinations: int = Field(ge=2, le=1_000)
    minimum_distinct_sources: int = Field(ge=2, le=1_000)
    included_verdicts: tuple[str, ...] = Field(min_length=1)
    excluded_verdicts: tuple[str, ...] = Field(min_length=1)
    rule_versions: dict[str, str]
    severity_bands: tuple[SeverityBand, ...] = Field(min_length=1)
    hypothesis_confidence_weights: ConfidenceWeights
    score_semantics: Literal[
        "correlation evidence strength for analyst triage; not attack probability"
    ]

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if self.minimum_alerts > self.maximum_alerts_per_group:
            raise ValueError("minimum alerts cannot exceed maximum group size")
        if self.maximum_alerts_per_group > self.maximum_alerts_per_run:
            raise ValueError("maximum group size cannot exceed maximum run size")
        if set(self.included_verdicts) & set(self.excluded_verdicts):
            raise ValueError("verdict inclusion and exclusion policies must not overlap")
        if set(self.rule_versions) != set(RULE_IDS) or any(
            not version.strip() for version in self.rule_versions.values()
        ):
            raise ValueError("every Phase 9 correlation rule requires one version")
        minimums = tuple(item.minimum_score for item in self.severity_bands)
        severities = tuple(item.severity for item in self.severity_bands)
        if minimums[0] != 0.0 or any(
            left >= right for left, right in zip(minimums, minimums[1:], strict=False)
        ):
            raise ValueError("severity bands must start at zero and increase")
        if severities != tuple(Severity):
            raise ValueError("severity bands must declare all severities in stable order")
        return self


class LoadedCorrelationPolicy(PolicyModel):
    policy: CorrelationPolicy
    configuration_checksum: str

    @model_validator(mode="after")
    def validate_checksum(self) -> Self:
        if not SHA256_PATTERN.fullmatch(self.configuration_checksum):
            raise ValueError("correlation policy checksum must be SHA-256")
        return self


def load_correlation_policy(path: Path) -> LoadedCorrelationPolicy:
    """Load a regular YAML file and bind policy identity to exact bytes."""

    if not path.is_file() or path.is_symlink():
        raise CorrelationConfigError("correlation policy must be a regular file")
    try:
        payload_bytes = path.read_bytes()
        payload = yaml.safe_load(payload_bytes)
        if not isinstance(payload, dict):
            raise CorrelationConfigError("correlation policy root must be a mapping")
        policy = CorrelationPolicy.model_validate(payload)
    except CorrelationConfigError:
        raise
    except (OSError, ValidationError, yaml.YAMLError) as exc:
        raise CorrelationConfigError("correlation policy is invalid") from exc
    return LoadedCorrelationPolicy(
        policy=policy,
        configuration_checksum=hashlib.sha256(payload_bytes).hexdigest(),
    )
