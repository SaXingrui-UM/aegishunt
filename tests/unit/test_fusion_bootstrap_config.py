"""Pre-registration and group-bootstrap regression tests."""

import numpy as np
import pytest
from pydantic import ValidationError

from aegishunt.ml.fusion.bootstrap import (
    group_bootstrap_delta_intervals,
    group_bootstrap_intervals,
)
from aegishunt.ml.fusion.config import FusionExperimentConfig, WeightCandidate
from aegishunt.ml.fusion.errors import FusionContractError
from tests.fixtures.fusion import FUSION_CONFIG_PATH, fusion_config


def test_config_requires_dual_weights_fixed_axes_and_protocol_order() -> None:
    config = FusionExperimentConfig.load(FUSION_CONFIG_PATH)

    assert len(config.weight_candidates) == 3
    assert {shift.axis for shift in config.parameter_shifts} == {
        "flow_duration",
        "packet_rate",
        "packet_size_pattern",
        "connection_frequency",
    }
    with pytest.raises(ValidationError):
        WeightCandidate(
            candidate_id="invalid-endpoint",
            supervised_weight=1.0,
            anomaly_weight=0.0,
        )
    with pytest.raises(ValidationError, match="tie-break"):
        fusion_config(tie_break_order=("accuracy",))


def test_group_bootstrap_and_paired_delta_are_deterministic() -> None:
    labels = np.asarray([0, 1, 0, 1, 0, 1, 0, 1], dtype=np.int64)
    groups = np.asarray(["a", "a", "b", "b", "c", "c", "d", "d"])
    fusion = np.asarray([0.1, 0.9, 0.2, 0.8, 0.3, 0.7, 0.4, 0.6])
    baseline = np.asarray([0.2, 0.8, 0.3, 0.7, 0.4, 0.6, 0.45, 0.55])

    intervals = group_bootstrap_intervals(
        labels,
        fusion,
        groups,
        threshold=0.5,
        draws=1000,
        random_seed=77,
    )
    repeated = group_bootstrap_intervals(
        labels,
        fusion,
        groups,
        threshold=0.5,
        draws=1000,
        random_seed=77,
    )
    deltas = group_bootstrap_delta_intervals(
        labels,
        fusion,
        baseline,
        groups,
        fusion_threshold=0.5,
        baseline_threshold=0.5,
        draws=1000,
        random_seed=78,
    )

    assert intervals == repeated
    assert intervals["recall"].successful_draws == 1000
    assert deltas["f1"].lower == pytest.approx(0.0)
    assert deltas["f1"].upper == pytest.approx(0.0)


def test_group_bootstrap_rejects_row_level_or_too_few_draws() -> None:
    labels = np.asarray([0, 1], dtype=np.int64)
    scores = np.asarray([0.1, 0.9])
    with pytest.raises(FusionContractError, match="1,000"):
        group_bootstrap_intervals(
            labels,
            scores,
            np.asarray(["a", "b"]),
            threshold=0.5,
            draws=999,
            random_seed=1,
        )
    with pytest.raises(FusionContractError, match="two groups"):
        group_bootstrap_intervals(
            labels,
            scores,
            np.asarray(["a", "a"]),
            threshold=0.5,
            draws=1000,
            random_seed=1,
        )
