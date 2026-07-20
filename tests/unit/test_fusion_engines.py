"""Fixed-engine refit and operational-adapter tests."""

from datetime import UTC, datetime

import numpy as np
import pytest
from pydantic import ValidationError

from aegishunt.datasets.labels import LabelMapper
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import AnomalyPredictionResult
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.dataset import (
    ControlledExperimentDataset,
    build_controlled_experiment_dataset,
)
from aegishunt.ml.fusion.engines import (
    EngineScoreVectors,
    FittedExperimentalEngines,
    adapt_verified_predictions,
    fit_experimental_engines,
)
from aegishunt.ml.fusion.errors import FusionContractError
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import PredictionResult
from tests.fixtures.anomaly import LOF_CANDIDATE_CONFIG_PATH
from tests.fixtures.datasets import LABEL_ROOT
from tests.fixtures.fusion import FUSION_CONFIG_PATH, fusion_config
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH


def _fitted() -> tuple[
    tuple[FittedExperimentalEngines, EngineScoreVectors], ControlledExperimentDataset
]:
    config = FusionExperimentConfig.load(FUSION_CONFIG_PATH)
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")
    dataset = build_controlled_experiment_dataset(config, mapper)
    return fit_experimental_engines(
        dataset.stage("early"),
        dataset.stage("middle"),
        fusion_config=config,
        supervised_config=SupervisedTrainingConfig.load(CORRECTIVE_CONFIG_PATH),
        anomaly_config=AnomalyTrainingConfig.load(LOF_CANDIDATE_CONFIG_PATH),
    ), dataset


def test_fixed_research_engines_fit_only_train_and_validation_contracts() -> None:
    (engines, validation_scores), dataset = _fitted()
    evaluation_scores = engines.score(dataset.stage("late"))

    assert 0.0 < engines.supervised_threshold < 1.0
    assert 0.0 < engines.anomaly_threshold <= 1.0
    assert validation_scores.supervised.shape == (48,)
    assert evaluation_scores.anomaly.shape == (48,)
    assert np.isfinite(evaluation_scores.supervised).all()
    assert np.isfinite(evaluation_scores.anomaly).all()
    assert np.array_equal(
        evaluation_scores.supervised,
        engines.score(dataset.stage("late")).supervised,
    )


def test_fixed_research_engine_config_rejects_phase_five_drift() -> None:
    config = FusionExperimentConfig.load(FUSION_CONFIG_PATH)

    with pytest.raises(ValidationError, match="Phase 5 configuration"):
        fusion_config(
            supervised_hyperparameters={
                **config.supervised_hyperparameters,
                "max_depth": 3,
            }
        )


def test_operational_adapter_requires_both_verified_engine_identities() -> None:
    timestamp = datetime(2026, 7, 20, tzinfo=UTC)
    supervised = (
        PredictionResult(
            predicted_label=1,
            raw_score=0.8,
            calibrated_probability=0.75,
            selected_threshold=0.5,
            model_id="aegishunt-supervised-1.0.1",
            model_version="1.0.1",
            feature_schema_version="1.0.0",
            prediction_timestamp=timestamp,
        ),
    )
    anomaly = (
        AnomalyPredictionResult(
            raw_model_score=-0.2,
            canonical_anomaly_score=0.2,
            normalized_anomaly_score=0.8,
            selected_threshold=0.9,
            is_anomaly=False,
            model_id="aegishunt-anomaly-1.1.0-candidate",
            model_version="1.1.0-candidate",
            feature_schema_version="1.0.0",
            scored_at=timestamp,
        ),
    )

    scores = adapt_verified_predictions(supervised, anomaly, fusion_config())
    assert scores.supervised.tolist() == [0.75]
    assert scores.anomaly.tolist() == [0.8]
    with pytest.raises(FusionContractError, match="both engine"):
        adapt_verified_predictions(supervised, (), fusion_config())
    with pytest.raises(FusionContractError, match="identity"):
        adapt_verified_predictions(
            supervised,
            (anomaly[0].model_copy(update={"model_version": "wrong"}),),
            fusion_config(),
        )
