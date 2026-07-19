"""Phase 6 configuration validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.errors import AnomalyTrainingError
from tests.fixtures.anomaly import (
    ANOMALY_CONFIG_PATH,
    CORRECTIVE_CONFIG_PATH,
    LOF_CANDIDATE_CONFIG_PATH,
)


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


def test_corrective_configuration_is_exactly_pre_registered() -> None:
    config = AnomalyTrainingConfig.load(CORRECTIVE_CONFIG_PATH)

    assert config.experiment_id == "phase-06-controlled-demo-validation-corrective-001"
    assert config.model_version == "1.0.1-candidate"
    assert config.selection_policy_version == "1.0.1"
    assert config.candidate_status == "validation_qualified"
    assert len(config.isolation_forest_candidates) == 8
    assert config.normalization_strategies == (
        "benign_training_quantile_cdf",
        "smoothed_empirical_cdf",
        "robust_percentile_scaling",
    )
    assert config.threshold_candidates == (0.4, 0.5, 0.6, 0.7, 0.75, 0.8, 0.85, 0.9, 0.95)
    assert config.false_positive_rate_limit == 0.25
    assert config.corrective_protocol is not None
    assert config.corrective_protocol.original_test_access_permitted is False
    assert config.corrective_protocol.smoke_fixture_affects_selection is False


def test_lof_candidate_configuration_is_exactly_pre_registered() -> None:
    config = AnomalyTrainingConfig.load(LOF_CANDIDATE_CONFIG_PATH)

    assert config.config_schema_version == "2.0.0"
    assert config.experiment_id == "phase-06-controlled-demo-lof-production-candidate-001"
    assert config.model_version == "1.1.0-candidate"
    assert config.selection_policy_version == "2.0.0"
    assert config.candidate_status == "validation_qualified"
    assert config.lof_production_eligible is True
    assert config.lof.enabled is True
    assert config.lof.n_neighbors == 5
    assert config.corrective_protocol is not None
    assert config.corrective_protocol.original_test_access_permitted is False
    assert config.corrective_protocol.smoke_fixture_affects_selection is False
    assert config.corrective_protocol.untouched_independent_holdout_required is True


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        (None, "experiment_id", "post-result-expansion"),
        (None, "random_seed", 6107),
        (None, "false_positive_rate_limit", 0.5),
        ("lof", "n_neighbors", 4),
        ("corrective_protocol", "lof_production_eligible", False),
        ("corrective_protocol", "original_test_access_permitted", True),
    ),
)
def test_lof_candidate_registration_rejects_post_result_changes(
    tmp_path: Path,
    section: str | None,
    field: str,
    value: object,
) -> None:
    payload = yaml.safe_load(LOF_CANDIDATE_CONFIG_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    target = payload if section is None else payload[section]
    assert isinstance(target, dict)
    target[field] = value
    path = tmp_path / "changed.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AnomalyTrainingError, match="configuration is invalid"):
        AnomalyTrainingConfig.load(path)


@pytest.mark.parametrize("config_path", (CORRECTIVE_CONFIG_PATH, LOF_CANDIDATE_CONFIG_PATH))
def test_corrective_forest_matrix_rejects_parameter_substitution(
    tmp_path: Path,
    config_path: Path,
) -> None:
    payload = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    candidates = payload["isolation_forest_candidates"]
    assert isinstance(candidates, list)
    assert isinstance(candidates[0], dict)
    candidates[0]["n_estimators"] = 65
    path = tmp_path / "changed-matrix.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(AnomalyTrainingError, match="configuration is invalid"):
        AnomalyTrainingConfig.load(path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("config_schema_version", "99.0.0"),
        ("threshold_candidates", [0.8, 0.4]),
        ("threshold_candidates", [0.5, 0.5]),
        ("threshold_candidates", [None]),
        ("threshold_candidates", [float("nan")]),
        ("threshold_candidates", [float("inf")]),
        ("threshold_candidates", [float("-inf")]),
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
