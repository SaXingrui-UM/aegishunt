"""Validated YAML and environment-variable configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from aegishunt.errors import ConfigurationError

DEFAULT_CONFIG_PATH = Path("configs/application.yaml")
ENV_PREFIX = "AEGISHUNT_"
CONTAINER_WILDCARD_HOST = str(IPv4Address(0))


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
    max_json_record_bytes: int = Field(default=1_048_576, ge=1, le=52_428_800)
    max_json_nesting_depth: int = Field(default=64, ge=1, le=256)


class FlowSettings(BaseModel):
    """Deterministic packet-to-flow aggregation and memory bounds."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    idle_timeout_seconds: float = Field(default=60.0, gt=0.0, le=86_400.0)
    active_timeout_seconds: float = Field(default=300.0, gt=0.0, le=86_400.0)
    max_packets_per_flow: int = Field(default=10_000, ge=1, le=1_000_000)
    max_active_flows: int = Field(default=100_000, ge=1, le=1_000_000)
    max_packet_bytes: int = Field(default=262_144, ge=64, le=16_777_216)
    max_pcapng_interfaces: int = Field(default=256, ge=1, le=65_535)


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
    fusion_evaluation_root: Path = Path("reports/models/fusion")
    fusion_evaluation_experiment_id: str = Field(
        default="phase-07-controlled-fusion-001",
        pattern=r"^[a-z0-9][a-z0-9-]{2,127}$",
    )


class WebSettings(BaseModel):
    """Local-only API and Streamlit integration policy."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    container_network_enabled: bool = False
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8_000, ge=1, le=65_535)
    docs_enabled: bool = True
    api_base_url: str = "http://127.0.0.1:8000"
    allowed_origins: tuple[str, ...] = ()
    request_id_header: str = Field(
        default="X-Request-ID",
        pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$",
    )
    actor_header: str = Field(
        default="X-AegisHunt-Actor",
        pattern=r"^[A-Za-z][A-Za-z0-9-]{0,63}$",
    )
    frontend_origin: str = "http://127.0.0.1:8501"
    request_id_max_length: int = Field(default=64, ge=8, le=128)
    default_page_size: int = Field(default=50, ge=1, le=100)
    maximum_page_size: int = Field(default=100, ge=1, le=100)
    request_timeout_seconds: float = Field(default=15.0, gt=0.0, le=120.0)
    runtime_worker_timeout_seconds: float = Field(
        default=600.0,
        gt=0.0,
        le=3_600.0,
    )
    upload_chunk_size_bytes: int = Field(default=65_536, ge=1, le=1_048_576)
    auto_refresh_enabled: bool = True
    auto_refresh_seconds: int = Field(default=5, ge=1, le=300)
    minimum_refresh_seconds: int = Field(default=1, ge=1, le=300)
    maximum_refresh_seconds: int = Field(default=300, ge=1, le=300)
    sample_mode_enabled: bool = True
    maximum_table_rows: int = Field(default=50, ge=1, le=100)
    default_actor: str = Field(default="local-analyst", min_length=1, max_length=128)
    page_title: str = Field(default="AegisHunt", min_length=1, max_length=128)
    safe_download_types: tuple[str, ...] = (
        "case_report",
        "feedback_export",
        "retraining_candidate",
    )
    maximum_pcap_upload_bytes: int = Field(default=52_428_800, ge=1)
    maximum_csv_upload_bytes: int = Field(default=10_485_760, ge=1)
    maximum_json_upload_bytes: int = Field(default=10_485_760, ge=1)
    maximum_multipart_overhead_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=8_388_608,
    )
    demo_sample_ids: tuple[str, ...] = ("phase12-demo-pcap",)
    demo_dataset_version: str = Field(
        default="1.0.0",
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$",
    )
    demo_replay_speed: float = Field(default=1.0, gt=0.0, le=1_000.0)
    demo_artifact_root: Path = Path("artifacts/demo/phase12")
    demo_namespace: str = Field(
        default="phase12-controlled-demo",
        pattern=r"^[a-z0-9][a-z0-9-]{2,63}$",
    )
    demo_operation_version: str = Field(
        default="1.1.0",
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$",
    )
    demo_worker_id: str = Field(
        default="phase12-demo-worker",
        pattern=r"^[a-z0-9][a-z0-9-]{2,63}$",
    )
    web_worker_id_prefix: str = Field(
        default="phase12-web-worker",
        pattern=r"^[a-z0-9][a-z0-9-]{2,63}$",
    )

    @field_validator("api_base_url")
    @classmethod
    def validate_api_base_url(cls, value: str) -> str:
        """Normalize one credential-free HTTP API endpoint."""

        normalized = value.rstrip("/")
        parsed = urlsplit(normalized)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("web API base URL must be a credential-free origin")
        return normalized

    @field_validator("allowed_origins", "frontend_origin")
    @classmethod
    def validate_origins(cls, values: tuple[str, ...] | str) -> tuple[str, ...] | str:
        """Limit CORS to explicit local HTTP origins."""

        origins = (values,) if isinstance(values, str) else values
        for value in origins:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in {"http", "https"}
                or parsed.hostname not in {"127.0.0.1", "localhost"}
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("web origins must be credential-free loopback URLs")
        return values

    @field_validator("api_host")
    @classmethod
    def validate_api_host(cls, value: str) -> str:
        """Normalize the API bind interface before joint deployment validation."""

        normalized = value.strip().lower()
        if normalized not in {"127.0.0.1", "localhost", CONTAINER_WILDCARD_HOST}:
            raise ValueError("web API host must be loopback or the container wildcard")
        return normalized

    @field_validator("safe_download_types")
    @classmethod
    def validate_safe_download_types(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Reject arbitrary artifact download categories."""

        allowed = {"case_report", "feedback_export", "retraining_candidate"}
        if not values or any(value not in allowed for value in values):
            raise ValueError("safe download types must use the declared allowlist")
        return values

    @field_validator("demo_sample_ids")
    @classmethod
    def validate_demo_sample_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        """Require one or more stable packaged sample identifiers."""

        if not values:
            raise ValueError("at least one demo sample ID is required")
        for value in values:
            if not value or len(value) > 64 or not all(
                character.islower() or character.isdigit() or character == "-"
                for character in value
            ):
                raise ValueError("demo sample IDs must be lowercase slug values")
        return values

    @model_validator(mode="after")
    def validate_web_bounds(self) -> WebSettings:
        """Keep bounds coherent and container-only network exceptions explicit."""

        if self.default_page_size > self.maximum_page_size:
            raise ValueError("default page size must not exceed the maximum page size")
        if self.maximum_table_rows > self.maximum_page_size:
            raise ValueError("maximum table rows must not exceed the maximum page size")
        if self.runtime_worker_timeout_seconds < self.request_timeout_seconds:
            raise ValueError(
                "runtime worker timeout must not be shorter than the request timeout"
            )
        if self.minimum_refresh_seconds > self.maximum_refresh_seconds:
            raise ValueError("minimum refresh interval must not exceed the maximum")
        if not (
            self.minimum_refresh_seconds
            <= self.auto_refresh_seconds
            <= self.maximum_refresh_seconds
        ):
            raise ValueError("auto-refresh interval must be within configured bounds")
        parsed_api = urlsplit(self.api_base_url)
        api_hostname = parsed_api.hostname
        if self.container_network_enabled:
            if self.api_host != CONTAINER_WILDCARD_HOST:
                raise ValueError("container API host must bind the container wildcard")
            if api_hostname != "api":
                raise ValueError("container frontend must use the declared API service")
        elif (
            self.api_host not in {"127.0.0.1", "localhost"}
            or api_hostname not in {"127.0.0.1", "localhost"}
        ):
            raise ValueError("local web endpoints must use loopback interfaces")
        return self


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
    web: WebSettings = Field(default_factory=WebSettings)

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
