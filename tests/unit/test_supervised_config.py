"""Phase 5 training policy must be complete, bounded, and reproducible."""

from pathlib import Path

import pytest
import yaml

from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.errors import TrainingError
from tests.fixtures.supervised import TRAINING_CONFIG_PATH


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
