"""Validated YAML and environment-variable configuration."""

from __future__ import annotations

import os
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

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

    url: str = "sqlite:///data/aegishunt.db"
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


class ApplicationSettings(BaseModel):
    """Complete Phase 1 settings assembled from YAML and environment values."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    application: ApplicationSection = Field(default_factory=ApplicationSection)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)

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
