"""Phase 5 training policy must be complete, bounded, and reproducible."""

from pathlib import Path

import pytest
import yaml

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.errors import TrainingError
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH, TRAINING_CONFIG_PATH


def test_supervised_config_declares_every_required_candidate() -> None:
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)

    assert config.cv_folds == 3
    assert config.bootstrap_iterations == 1_000
    assert {candidate.algorithm for candidate in config.candidates} == {
        "dummy",
        "logistic_regression",
        "decision_tree",
        "random_forest",
        "hist_gradient_boosting",
    }
    assert all(candidate.combinations() for candidate in config.candidates)


def test_corrective_config_versions_evidence_without_changing_training_policy() -> None:
    original = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    corrective = SupervisedTrainingConfig.load(CORRECTIVE_CONFIG_PATH)

    assert corrective.corrective_run is not None
    assert corrective.corrective_run.defect_id == "PM-DEF-001"
    assert corrective.experiment_id != original.experiment_id
    assert corrective.model_version != original.model_version
    assert corrective.random_seed == original.random_seed
    assert corrective.cv_folds == original.cv_folds
    assert corrective.calibration_methods == original.calibration_methods
    assert corrective.threshold_candidates == original.threshold_candidates
    assert corrective.candidates == original.candidates
    assert corrective.model_dump(
        exclude={
            "config_schema_version",
            "experiment_id",
            "model_version",
            "selection_policy_version",
            "corrective_run",
        }
    ) == original.model_dump(
        exclude={
            "config_schema_version",
            "experiment_id",
            "model_version",
            "selection_policy_version",
            "corrective_run",
        }
    )


def test_corrective_config_rejects_reused_evidence_identity(tmp_path: Path) -> None:
    payload = yaml.safe_load(CORRECTIVE_CONFIG_PATH.read_text(encoding="utf-8"))
    payload["experiment_id"] = payload["corrective_run"]["supersedes_experiment_id"]
    path = tmp_path / "invalid-corrective.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(TrainingError, match="new experiment ID"):
        SupervisedTrainingConfig.load(path)


def test_supervised_config_rejects_missing_candidate(tmp_path: Path) -> None:
    payload = yaml.safe_load(TRAINING_CONFIG_PATH.read_text(encoding="utf-8"))
    payload["candidates"] = payload["candidates"][:-1]
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(TrainingError, match="all required supervised candidates"):
        SupervisedTrainingConfig.load(path)


def test_supervised_config_rejects_unbounded_grid(tmp_path: Path) -> None:
    payload = yaml.safe_load(TRAINING_CONFIG_PATH.read_text(encoding="utf-8"))
    payload["candidates"][0]["parameters"] = {
        "strategy": [f"candidate-{index}" for index in range(65)]
    }
    path = tmp_path / "invalid.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(TrainingError, match="bounded search limit"):
        SupervisedTrainingConfig.load(path)
