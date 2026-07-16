"""Train-only supervised candidate and group-CV regression coverage."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from aegishunt.ml.supervised.candidates import build_candidate, raw_positive_scores
from aegishunt.ml.supervised.config import CandidateConfig, SupervisedTrainingConfig
from aegishunt.ml.supervised.cross_validation import (
    build_group_folds,
    fit_best_candidate,
    tune_candidate,
)
from aegishunt.ml.supervised.data import PartitionData, SupervisedDatasetGate
from aegishunt.ml.supervised.errors import TrainingError
from tests.fixtures.supervised import TRAINING_CONFIG_PATH, build_phase4_bundle


def _training_data(tmp_path: Path) -> tuple[SupervisedTrainingConfig, PartitionData]:
    data_root, report_root = build_phase4_bundle(tmp_path)
    config = SupervisedTrainingConfig.load(TRAINING_CONFIG_PATH)
    data = SupervisedDatasetGate(data_root, report_root).load_training_validation(
        cv_folds=config.cv_folds
    )
    return config, data.train


def test_every_required_candidate_fits_and_scores(tmp_path: Path) -> None:
    config, train = _training_data(tmp_path)

    for candidate in config.candidates:
        estimator = build_candidate(
            candidate.algorithm,
            candidate.combinations()[0],
            random_seed=config.random_seed,
        )
        estimator.fit(train.features, train.labels)
        first = raw_positive_scores(estimator, train.features)
        second = raw_positive_scores(estimator, train.features)

        assert first.shape == train.labels.shape
        assert np.isfinite(first).all()
        assert np.array_equal(first, second)
        if candidate.algorithm == "logistic_regression":
            assert tuple(estimator.named_steps) == ("scale", "model")
        else:
            assert tuple(estimator.named_steps) == ("model",)


def test_group_folds_are_deterministic_and_isolated(tmp_path: Path) -> None:
    config, train = _training_data(tmp_path)

    first = build_group_folds(
        train,
        fold_count=config.cv_folds,
        random_seed=config.random_seed,
    )
    second = build_group_folds(
        train,
        fold_count=config.cv_folds,
        random_seed=config.random_seed,
    )

    assert [fold.evidence for fold in first] == [fold.evidence for fold in second]
    assert all(not fold.evidence.group_overlap for fold in first)
    assert all(not fold.evidence.source_overlap for fold in first)
    assert all(not fold.evidence.session_overlap for fold in first)
    assert all(not fold.evidence.scenario_overlap for fold in first)
    validation_rows = sorted(index for fold in first for index in fold.validation.tolist())
    assert validation_rows == list(range(len(train.rows)))


def test_group_folds_reject_insufficient_groups(tmp_path: Path) -> None:
    config, train = _training_data(tmp_path)
    reduced = PartitionData(name="train", rows=train.rows[:2])

    with pytest.raises(TrainingError, match="insufficient"):
        build_group_folds(reduced, fold_count=3, random_seed=config.random_seed)


def test_candidate_tuning_records_all_parameters_and_refits(tmp_path: Path) -> None:
    config, train = _training_data(tmp_path)
    candidate = CandidateConfig(
        algorithm="decision_tree",
        parameters={"max_depth": (2, 3), "class_weight": (None, "balanced")},
    )

    best, evidence = tune_candidate(candidate, train, config)
    estimator, duration = fit_best_candidate(best, train, config)

    assert len(evidence) == 4
    assert all(result.status == "passed" for result in evidence)
    assert all(len(result.folds) == config.cv_folds for result in evidence)
    assert best in evidence
    assert duration >= 0.0
    assert raw_positive_scores(estimator, train.features).shape == train.labels.shape


def test_candidate_tuning_records_failed_parameter_without_hiding_it(tmp_path: Path) -> None:
    config, train = _training_data(tmp_path)
    candidate = CandidateConfig(
        algorithm="decision_tree",
        parameters={"max_depth": (2, "invalid")},
    )

    best, evidence = tune_candidate(candidate, train, config)

    assert best.status == "passed"
    assert [result.status for result in evidence] == ["passed", "failed"]
    assert evidence[1].failure_code == "candidate_fit_or_score_failed"
