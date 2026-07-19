"""Validation-only fusion policy selection tests."""

from datetime import UTC, datetime

import numpy as np
import pytest
from pydantic import ValidationError

from aegishunt.ml.fusion.errors import FusionSelectionError
from aegishunt.ml.fusion.selection import select_fusion_policy
from tests.fixtures.fusion import fusion_config


def _evidence() -> tuple[
    np.ndarray[tuple[int], np.dtype[np.int64]],
    np.ndarray[tuple[int], np.dtype[np.str_]],
    np.ndarray[tuple[int], np.dtype[np.float64]],
    np.ndarray[tuple[int], np.dtype[np.float64]],
]:
    labels = np.asarray([0, 0, 0, 0, 1, 1, 1, 1], dtype=np.int64)
    groups = np.asarray([f"g{index // 2}" for index in range(8)], dtype=np.str_)
    supervised = np.asarray([0.1, 0.2, 0.3, 0.4, 0.55, 0.6, 0.8, 0.9])
    anomaly = np.asarray([0.1, 0.3, 0.2, 0.6, 0.4, 0.7, 0.8, 0.9])
    return labels, groups, supervised, anomaly


def test_select_policy_uses_true_fusion_and_is_deterministic() -> None:
    labels, groups, supervised, anomaly = _evidence()
    timestamp = datetime(2026, 7, 20, tzinfo=UTC)

    first = select_fusion_policy(
        labels=labels,
        groups=groups,
        supervised_scores=supervised,
        anomaly_scores=anomaly,
        supervised_threshold=0.5,
        anomaly_threshold=0.6,
        config=fusion_config(),
        protocol_frozen_at=timestamp,
    )
    second = select_fusion_policy(
        labels=labels,
        groups=groups,
        supervised_scores=supervised,
        anomaly_scores=anomaly,
        supervised_threshold=0.5,
        anomaly_threshold=0.6,
        config=fusion_config(),
        protocol_frozen_at=timestamp,
    )

    assert first == second
    assert first.selected_weights.is_dual_engine
    assert first.evaluation_data_accessed is False
    assert first.held_out_family_accessed is False
    assert first.supervised_baseline.mode == "supervised_only"
    assert first.anomaly_baseline.mode == "anomaly_only"
    assert all(candidate.mode == "dual_engine_fusion" for candidate in first.candidates)
    inconsistent = first.model_copy(
        update={"selected_threshold": first.selected_threshold + 0.01}
    )
    with pytest.raises(ValidationError, match="internally inconsistent"):
        type(first).model_validate(inconsistent.model_dump())


def test_select_policy_respects_fpr_ceiling_and_negative_result_path() -> None:
    labels, groups, supervised, anomaly = _evidence()
    selection = select_fusion_policy(
        labels=labels,
        groups=groups,
        supervised_scores=supervised,
        anomaly_scores=anomaly,
        supervised_threshold=0.5,
        anomaly_threshold=0.6,
        config=fusion_config(recommendation_min_macro_f1_delta=1.0),
    )

    selected = next(
        item
        for item in selection.candidates
        if item.candidate_id == selection.selected_candidate_id
    )
    assert selected.satisfies_fpr_ceiling
    assert selection.recommendation_status in {"fusion_not_recommended", "inconclusive"}


def test_selection_fails_closed_without_both_classes_or_compliant_candidate() -> None:
    labels, groups, supervised, anomaly = _evidence()
    with pytest.raises(FusionSelectionError, match="both classes"):
        select_fusion_policy(
            labels=np.zeros_like(labels),
            groups=groups,
            supervised_scores=supervised,
            anomaly_scores=anomaly,
            supervised_threshold=0.5,
            anomaly_threshold=0.6,
            config=fusion_config(),
        )
    with pytest.raises(FusionSelectionError, match="no dual-engine"):
        select_fusion_policy(
            labels=labels,
            groups=groups,
            supervised_scores=np.ones_like(supervised),
            anomaly_scores=np.ones_like(anomaly),
            supervised_threshold=0.5,
            anomaly_threshold=0.6,
            config=fusion_config(false_positive_rate_ceiling=0.0),
        )
    with pytest.raises(FusionSelectionError, match="positive attack utility"):
        select_fusion_policy(
            labels=labels,
            groups=groups,
            supervised_scores=np.zeros_like(supervised),
            anomaly_scores=np.zeros_like(anomaly),
            supervised_threshold=0.5,
            anomaly_threshold=0.6,
            config=fusion_config(),
        )


def test_selection_records_fusion_not_recommended_without_more_search() -> None:
    labels, groups, _, _ = _evidence()
    supervised = np.asarray([0.1, 0.2, 0.3, 0.49, 0.51, 0.7, 0.8, 0.9])
    anomaly = np.asarray([0.1, 0.2, 0.3, 1.0, 0.0, 0.7, 0.8, 0.9])

    selection = select_fusion_policy(
        labels=labels,
        groups=groups,
        supervised_scores=supervised,
        anomaly_scores=anomaly,
        supervised_threshold=0.5,
        anomaly_threshold=0.6,
        config=fusion_config(false_positive_rate_ceiling=0.5),
    )

    selected = next(
        item
        for item in selection.candidates
        if item.candidate_id == selection.selected_candidate_id
    )
    assert selected.metrics.recall > 0.0
    assert selected.metrics.f1 > 0.0
    assert selection.supervised_baseline.metrics.macro_f1 == 1.0
    assert selection.recommendation_status == "fusion_not_recommended"
