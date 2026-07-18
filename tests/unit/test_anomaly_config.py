"""Phase 6 configuration validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.errors import AnomalyTrainingError
from tests.fixtures.anomaly import ANOMALY_CONFIG_PATH


def _payload() -> dict[str, object]:
    value = yaml.safe_load(ANOMALY_CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_anomaly_configuration_loads_complete_bounded_policy() -> None:
    config = AnomalyTrainingConfig.load(ANOMALY_CONFIG_PATH)

    assert config.config_schema_version == "1.0.0"
    assert config.false_positive_rate_limit == 0.25
    assert len(config.isolation_forest_candidates) == 3
    assert config.lof.enabled is True
    assert config.one_class_svm_status == "not_implemented"
    assert config.bootstrap_iterations == 1000


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("config_schema_version", "99.0.0"),
        ("threshold_candidates", [0.8, 0.4]),
        ("threshold_candidates", [0.5, 0.5]),
        ("false_positive_rate_limit", 1.0),
        ("bootstrap_iterations", 999),
    ),
)
def test_invalid_anomaly_policy_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    payload = _payload()
    payload[field] = value
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AnomalyTrainingError, match="configuration is invalid"):
        AnomalyTrainingConfig.load(path)


def test_duplicate_candidate_identifier_is_rejected(tmp_path: Path) -> None:
    payload = _payload()
    candidates = payload["isolation_forest_candidates"]
    assert isinstance(candidates, list)
    assert isinstance(candidates[1], dict)
    assert isinstance(candidates[0], dict)
    candidates[1]["candidate_id"] = candidates[0]["candidate_id"]
    path = tmp_path / "duplicate.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AnomalyTrainingError, match="configuration is invalid"):
        AnomalyTrainingConfig.load(path)


def test_unknown_configuration_field_fails_closed(tmp_path: Path) -> None:
    payload = _payload()
    payload["best_threshold"] = 0.9
    path = tmp_path / "extra.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AnomalyTrainingError, match="configuration is invalid"):
        AnomalyTrainingConfig.load(path)
