"""Group-aware confidence interval reproducibility tests."""

import numpy as np
import pytest

from aegishunt.ml.supervised.bootstrap import group_bootstrap_intervals
from aegishunt.ml.supervised.errors import EvaluationError


def test_group_bootstrap_is_deterministic() -> None:
    labels = np.asarray([0, 0, 1, 1, 0, 1], dtype=np.int64)
    predictions = np.asarray([0, 1, 1, 1, 0, 0], dtype=np.int64)
    probabilities = np.asarray([0.1, 0.6, 0.8, 0.9, 0.2, 0.4], dtype=np.float64)
    groups = np.asarray(["a", "a", "b", "b", "c", "c"], dtype=np.str_)

    first = group_bootstrap_intervals(
        labels,
        predictions,
        probabilities,
        groups,
        iterations=1_000,
        random_seed=5_105,
    )
    second = group_bootstrap_intervals(
        labels,
        predictions,
        probabilities,
        groups,
        iterations=1_000,
        random_seed=5_105,
    )

    assert first == second
    assert first["macro_f1"].successful_iterations == 1_000
    assert 0.0 <= first["macro_f1"].lower <= first["macro_f1"].upper <= 1.0


def test_group_bootstrap_rejects_too_few_iterations() -> None:
    with pytest.raises(EvaluationError, match="at least 1,000"):
        group_bootstrap_intervals(
            np.asarray([0, 1], dtype=np.int64),
            np.asarray([0, 1], dtype=np.int64),
            np.asarray([0.1, 0.9], dtype=np.float64),
            np.asarray(["a", "b"], dtype=np.str_),
            iterations=999,
            random_seed=1,
        )
