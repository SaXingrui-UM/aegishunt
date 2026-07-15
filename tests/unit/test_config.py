"""Tests for validated YAML and environment-variable configuration."""

from pathlib import Path

import pytest

from aegishunt.config import ApplicationSettings, load_settings
from aegishunt.errors import ConfigurationError


def test_defaults_load_without_optional_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    settings = load_settings(environ={})

    assert settings == ApplicationSettings()
    assert settings.environment == "development"


def test_environment_overrides_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / "application.yaml"
    config_path.write_text(
        """
application:
  environment: yaml-environment
database:
  url: sqlite:///yaml.db
  busy_timeout_ms: 3000
""".strip(),
        encoding="utf-8",
    )

    settings = load_settings(
        config_path,
        environ={
            "AEGISHUNT_APPLICATION__ENVIRONMENT": "test",
            "AEGISHUNT_DATABASE__URL": "sqlite:///environment.db",
            "AEGISHUNT_DATABASE__BUSY_TIMEOUT_MS": "7000",
            "AEGISHUNT_INGESTION__MAX_UPLOAD_BYTES": "4096",
            "AEGISHUNT_FLOWS__IDLE_TIMEOUT_SECONDS": "15.5",
            "AEGISHUNT_FLOWS__ACTIVE_TIMEOUT_SECONDS": "90",
            "AEGISHUNT_DATASETS__DEMO_SEED": "99",
        },
    )

    assert settings.environment == "test"
    assert settings.database.url == "sqlite:///environment.db"
    assert settings.database.busy_timeout_ms == 7000
    assert settings.ingestion.max_upload_bytes == 4096
    assert settings.flows.idle_timeout_seconds == 15.5
    assert settings.flows.active_timeout_seconds == 90.0
    assert settings.datasets.demo_seed == 99


def test_legacy_environment_label_remains_supported() -> None:
    settings = load_settings(environ={"AEGISHUNT_ENV": "compatibility"})

    assert settings.environment == "compatibility"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("- not-a-mapping", "root must be a YAML mapping"),
        ("application: [", "invalid YAML configuration"),
    ],
)
def test_invalid_yaml_has_explicit_error(tmp_path: Path, content: str, message: str) -> None:
    config_path = tmp_path / "invalid.yaml"
    config_path.write_text(content, encoding="utf-8")

    with pytest.raises(ConfigurationError, match=message):
        load_settings(config_path, environ={})


def test_unknown_nested_environment_key_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="configuration validation failed"):
        load_settings(environ={"AEGISHUNT_DATABASE__UNKNOWN": "value"})


def test_non_positive_flow_timeout_is_rejected() -> None:
    with pytest.raises(ConfigurationError, match="configuration validation failed"):
        load_settings(environ={"AEGISHUNT_FLOWS__IDLE_TIMEOUT_SECONDS": "0"})


def test_database_credentials_are_redacted_from_repr_and_validation_errors() -> None:
    secret = "phase-verification-secret"
    settings = load_settings(
        environ={
            "AEGISHUNT_DATABASE__URL": f"postgresql://analyst:{secret}@localhost/aegis"
        }
    )

    assert secret not in repr(settings)
    assert secret not in repr(settings.database)

    with pytest.raises(ConfigurationError) as failure:
        load_settings(environ={"AEGISHUNT_DATABASE__URL": secret})
    assert secret not in str(failure.value)
