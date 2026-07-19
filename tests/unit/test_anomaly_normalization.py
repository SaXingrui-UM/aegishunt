"""Corrective anomaly normalizer contract tests."""

from __future__ import annotations

import numpy as np
import pytest

from aegishunt.ml.anomaly.config import NormalizationStrategy
from aegishunt.ml.anomaly.errors import AnomalyTrainingError
from aegishunt.ml.anomaly.normalization import fit_score_normalizer, normalize_scores


@pytest.mark.parametrize(
    "strategy",
    (
        "benign_training_quantile_cdf",
        "smoothed_empirical_cdf",
        "robust_percentile_scaling",
    ),
)
def test_corrective_normalizers_are_deterministic_finite_and_bounded(
    strategy: NormalizationStrategy,
) -> None:
    reference = np.asarray([0.1, 0.1, 0.2, 0.4, 0.8], dtype=np.float64)
    scores = np.asarray([-1.0, 0.1, 0.3, 0.8, 2.0], dtype=np.float64)
    first = fit_score_normalizer(
        reference,
        version="1.0.1",
        quantile_count=101,
        strategy=strategy,
    )
    second = fit_score_normalizer(
        reference,
        version="1.0.1",
        quantile_count=101,
        strategy=strategy,
    )
    normalized = normalize_scores(scores, first)

    assert first == second
    assert first.reference_partition == "benign_training"
    assert first.score_direction == "higher_is_more_anomalous"
    assert np.isfinite(normalized).all()
    assert np.all((normalized >= 0.0) & (normalized <= 1.0))
    assert normalized[0] == 0.0
    assert normalized[-1] == 1.0
    assert np.all(np.diff(normalized) >= 0.0)


@pytest.mark.parametrize(
    "strategy",
    (
        "benign_training_quantile_cdf",
        "smoothed_empirical_cdf",
        "robust_percentile_scaling",
    ),
)
def test_corrective_normalizers_define_constant_reference_behavior(
    strategy: NormalizationStrategy,
) -> None:
    normalizer = fit_score_normalizer(
        np.asarray([0.5, 0.5, 0.5], dtype=np.float64),
        version="1.0.1",
        quantile_count=101,
        strategy=strategy,
    )

    assert normalize_scores(
        np.asarray([0.4, 0.5, 0.6], dtype=np.float64), normalizer
    ).tolist() == [0.0, 0.5, 1.0]


@pytest.mark.parametrize("invalid", (np.nan, np.inf, -np.inf))
def test_corrective_normalizers_reject_nonfinite_fit_evidence(invalid: float) -> None:
    with pytest.raises(AnomalyTrainingError, match="finite"):
        fit_score_normalizer(
            np.asarray([0.1, invalid], dtype=np.float64),
            version="1.0.1",
            quantile_count=101,
            strategy="smoothed_empirical_cdf",
        )
