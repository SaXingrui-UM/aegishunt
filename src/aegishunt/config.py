"""Validated YAML and environment-variable configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.errors import ConfigurationError

DEFAULT_CONFIG_PATH = Path("configs/application.yaml")
ENV_PREFIX = "AEGISHUNT_"


class ApplicationSection(BaseModel):
    """Application-level runtime settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: str = "development"

    @field_validator("environment")
    @classmethod
    def validate_environment(cls, value: str) -> str:
        """Reject blank environment labels."""

        normalized = value.strip()
        if not normalized:
            raise ValueError("environment must not be blank")
        return normalized


class DatabaseSettings(BaseModel):
    """Database engine and SQLite reliability settings."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str = Field(default="sqlite:///data/aegishunt.db", repr=False)
    echo: bool = False
    busy_timeout_ms: int = Field(default=5_000, ge=1, le=120_000)
    enable_wal: bool = True
    enable_foreign_keys: bool = True

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Require a non-empty SQLAlchemy URL without logging its contents."""

        normalized = value.strip()
        if not normalized or "://" not in normalized:
            raise ValueError("database URL must be a valid SQLAlchemy URL")
        return normalized


class IngestionSettings(BaseModel):
    """Safety and storage policy for untrusted telemetry uploads."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    storage_root: Path = Path("data/raw")
    sample_root: Path = Path("data/sample")
    max_upload_bytes: int = Field(default=52_428_800, ge=1)
    chunk_size_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    max_records: int = Field(default=100_000, ge=1)


class FlowSettings(BaseModel):
    """Deterministic packet-to-flow aggregation and memory bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    idle_timeout_seconds: float = Field(default=60.0, gt=0.0, le=86_400.0)
    active_timeout_seconds: float = Field(default=300.0, gt=0.0, le=86_400.0)
    max_packets_per_flow: int = Field(default=10_000, ge=1, le=1_000_000)
    max_active_flows: int = Field(default=100_000, ge=1, le=1_000_000)
    max_packet_bytes: int = Field(default=262_144, ge=64, le=16_777_216)


class DatasetSettings(BaseModel):
    """Filesystem and deterministic-policy settings for Phase 4 datasets."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    registry_path: Path = Path("configs/datasets/registry.yaml")
    label_mapping_root: Path = Path("configs/label_mappings")
    raw_root: Path = Path("data/raw/datasets")
    interim_root: Path = Path("data/interim/datasets")
    processed_root: Path = Path("data/processed/datasets")
    reports_root: Path = Path("reports/datasets")
    max_download_bytes: int = Field(default=10_737_418_240, ge=1)
    max_archive_members: int = Field(default=10_000, ge=1, le=1_000_000)
    max_extracted_bytes: int = Field(default=21_474_836_480, ge=1)
    near_duplicate_tolerance: float = Field(default=1e-6, gt=0.0, le=1.0)
    demo_seed: int = 4_204
    train_ratio: float = Field(default=0.6, gt=0.0, lt=1.0)
    validation_ratio: float = Field(default=0.2, gt=0.0, lt=1.0)
    test_ratio: float = Field(default=0.2, gt=0.0, lt=1.0)

    @model_validator(mode="after")
    def validate_split_ratios(self) -> DatasetSettings:
        """Require a complete partition without hidden row-level fallback."""

        total = self.train_ratio + self.validation_ratio + self.test_ratio
        if abs(total - 1.0) > 1e-9:
            raise ValueError("dataset split ratios must sum to 1.0")
        return self


class SupervisedSettings(BaseModel):
    """Configured Phase 5 policy and ignored artifact roots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    training_config_path: Path = Path("configs/models/supervised.yaml")
    artifact_root: Path = Path("artifacts/models/supervised")
    reports_root: Path = Path("reports/models/supervised")


class AnomalySettings(BaseModel):
    """Configured Phase 6 policy and ignored anomaly artifact roots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    training_config_path: Path = Path("configs/models/anomaly.yaml")
    artifact_root: Path = Path("artifacts/models/anomaly")
    reports_root: Path = Path("reports/models/anomaly")


class DetectionSettings(BaseModel):
    """Configured Phase 8 risk policy and data-only explanation storage."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_policy_path: Path = Path("configs/models/detection.yaml")
    explanation_artifact_root: Path = Path("artifacts/explainability")
    local_explanation_top_k: int = Field(default=5, ge=1, le=20)
    local_explanation_max_features: int = Field(default=43, ge=1, le=256)


class CorrelationSettings(BaseModel):
    """Configured Phase 9 correlation policy location."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_path: Path = Path("configs/correlation.yaml")


class CaseFeedbackSettings(BaseModel):
    """Configured Phase 10 case and analyst-feedback policy location."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_path: Path = Path("configs/case_feedback.yaml")


class RuntimeSettings(BaseModel):
    """Configured Phase 11 runtime policy and verified artifact roots."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_path: Path = Path("configs/runtime.yaml")
    fusion_policy_root: Path = Path("artifacts/models/fusion")


class ApplicationSettings(BaseModel):
    """Complete validated settings assembled from YAML and environment values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    application: ApplicationSection = Field(default_factory=ApplicationSection)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    ingestion: IngestionSettings = Field(default_factory=IngestionSettings)
    flows: FlowSettings = Field(default_factory=FlowSettings)
    datasets: DatasetSettings = Field(default_factory=DatasetSettings)
    supervised: SupervisedSettings = Field(default_factory=SupervisedSettings)
    anomaly: AnomalySettings = Field(default_factory=AnomalySettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    correlation: CorrelationSettings = Field(default_factory=CorrelationSettings)
    case_feedback: CaseFeedbackSettings = Field(default_factory=CaseFeedbackSettings)
    runtime: RuntimeSettings = Field(default_factory=RuntimeSettings)

    @property
    def environment(self) -> str:
        """Expose the environment label used by health responses."""

        return self.application.environment


class FoundationSettings(BaseModel):
    """Backward-compatible Phase 0 environment-only settings contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    environment: str = "development"

    @classmethod
    def from_environment(cls) -> FoundationSettings:
        """Retain the Phase 0 API while new code uses `load_settings`."""

        value = os.getenv("AEGISHUNT_ENV", "development").strip()
        return cls(environment=value or "development")


def _read_yaml(path: Path, *, required: bool) -> dict[str, Any]:
    """Read one YAML mapping with safe parsing and explicit failures."""

    if not path.exists():
        if required:
            raise ConfigurationError(f"configuration file does not exist: {path}")
        return {}
    if not path.is_file():
        raise ConfigurationError(f"configuration path is not a file: {path}")

    try:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigurationError(f"unable to read configuration file: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"invalid YAML configuration: {path}") from exc

    if loaded is None:
        return {}
    if not isinstance(loaded, dict):
        raise ConfigurationError("configuration root must be a YAML mapping")
    return dict(loaded)


def _set_nested(target: MutableMapping[str, Any], path: tuple[str, ...], value: str) -> None:
    """Set one environment override in a nested mapping."""

    current = target
    for segment in path[:-1]:
        existing = current.get(segment)
        if existing is None:
            child: dict[str, Any] = {}
            current[segment] = child
            current = child
        elif isinstance(existing, dict):
            current = existing
        else:
            raise ConfigurationError(f"configuration key cannot contain nested values: {segment}")
    current[path[-1]] = value


def _environment_overrides(environ: Mapping[str, str]) -> dict[str, Any]:
    """Translate declared `AEGISHUNT_*` values into nested settings."""

    overrides: dict[str, Any] = {}
    compatibility_keys = {
        "AEGISHUNT_ENV": ("application", "environment"),
        "AEGISHUNT_ENVIRONMENT": ("application", "environment"),
        "AEGISHUNT_DATABASE_URL": ("database", "url"),
    }
    for key, value in environ.items():
        if key == "AEGISHUNT_CONFIG":
            continue
        if key in compatibility_keys:
            _set_nested(overrides, compatibility_keys[key], value)
            continue
        if not key.startswith(ENV_PREFIX):
            continue
        remainder = key.removeprefix(ENV_PREFIX)
        if "__" not in remainder:
            continue
        segments = tuple(part.lower() for part in remainder.split("__") if part)
        if len(segments) < 2:
            raise ConfigurationError(f"invalid nested environment key: {key}")
        _set_nested(overrides, segments, value)
    return overrides


def _merge(target: MutableMapping[str, Any], overrides: Mapping[str, Any]) -> None:
    """Recursively merge environment overrides over YAML values."""

    for key, value in overrides.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), MutableMapping):
            nested = target[key]
            assert isinstance(nested, MutableMapping)
            _merge(nested, value)
        else:
            target[key] = value


def load_settings(
    config_path: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> ApplicationSettings:
    """Load settings with precedence: defaults, YAML, then environment."""

    source_environment = os.environ if environ is None else environ
    environment_path = source_environment.get("AEGISHUNT_CONFIG")
    selected_path = config_path or (
        Path(environment_path) if environment_path else DEFAULT_CONFIG_PATH
    )
    raw = _read_yaml(
        selected_path,
        required=config_path is not None or environment_path is not None,
    )
    _merge(raw, _environment_overrides(source_environment))
    try:
        return ApplicationSettings.model_validate(raw)
    except ValidationError as exc:
        errors = exc.errors(include_input=False, include_url=False)
        raise ConfigurationError(f"configuration validation failed: {errors}") from exc
