"""Strict dual-engine score and identity contract tests."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegishunt.ml.fusion.contracts import (
    FusionScoreInput,
    FusionWeights,
    PolicyManifest,
)
from aegishunt.ml.fusion.errors import FusionContractError
from aegishunt.ml.fusion.scoring import fuse_score, weighted_score

CHECKSUM = "a" * 64


def _policy() -> PolicyManifest:
    return PolicyManifest(
        manifest_schema_version="1.0.0",
        policy_id="aegishunt-fusion-controlled",
        policy_version="1.0.0",
        status="controlled_experiment_evaluated",
        experiment_id="phase-07-controlled-fusion-001",
        dataset_id="aegishunt-phase-07-controlled",
        dataset_version="1.0.0",
        dataset_manifest_checksum=CHECKSUM,
        split_manifest_checksum=CHECKSUM,
        experiment_protocol_checksum=CHECKSUM,
        feature_schema_version="1.0.0",
        supervised_model_id="aegishunt-supervised-1.0.1",
        supervised_model_version="1.0.1",
        supervised_score_semantics="calibrated supervised probability",
        anomaly_model_id="aegishunt-anomaly-1.1.0-candidate",
        anomaly_model_version="1.1.0-candidate",
        anomaly_score_semantics="bounded normalized anomaly score; not probability",
        selected_candidate_id="supervised-50-anomaly-50-t0.500",
        candidate_weights=(FusionWeights(supervised_weight=0.5, anomaly_weight=0.5),),
        selected_weights=FusionWeights(supervised_weight=0.5, anomaly_weight=0.5),
        selected_threshold=0.5,
        selection_policy_version="1.0.0",
        false_positive_rate_ceiling=0.25,
        recommendation_status="inconclusive",
        selection_evidence_checksum=CHECKSUM,
        known_evidence_checksum=CHECKSUM,
        unseen_evidence_checksum=CHECKSUM,
        temporal_evidence_checksum=CHECKSUM,
        parameter_shift_evidence_checksum=CHECKSUM,
        confidence_interval_checksum=CHECKSUM,
        git_commit_sha="b" * 40,
        python_version="3.12",
        dependency_versions={"numpy": "1.26"},
        pipeline_verification_only=True,
        public_benchmark=False,
        fusion_score_semantics=(
            "experimental suspiciousness score; not probability, risk, severity, "
            "or attack confirmation"
        ),
        protocol_frozen_at=datetime(2026, 7, 19, tzinfo=UTC),
        created_at=datetime(2026, 7, 20, tzinfo=UTC),
    )


def _input() -> FusionScoreInput:
    return FusionScoreInput(
        supervised_probability=0.8,
        normalized_anomaly_score=0.2,
        supervised_model_id="aegishunt-supervised-1.0.1",
        supervised_model_version="1.0.1",
        anomaly_model_id="aegishunt-anomaly-1.1.0-candidate",
        anomaly_model_version="1.1.0-candidate",
        feature_schema_version="1.0.0",
    )


def test_weighted_score_is_bounded_deterministic_and_requires_true_fusion() -> None:
    weights = FusionWeights(supervised_weight=0.25, anomaly_weight=0.75)

    assert weighted_score(0.8, 0.2, weights) == pytest.approx(0.35)
    assert weighted_score(0.8, 0.2, weights) == weighted_score(0.8, 0.2, weights)
    with pytest.raises(FusionContractError, match="two positive"):
        weighted_score(
            0.8,
            0.2,
            FusionWeights(supervised_weight=1.0, anomaly_weight=0.0),
        )


@pytest.mark.parametrize(
    ("supervised", "anomaly"),
    ((float("nan"), 0.1), (0.1, float("inf")), (-0.1, 0.2), (0.2, 1.1)),
)
def test_weighted_score_rejects_nonfinite_or_out_of_range_inputs(
    supervised: float, anomaly: float
) -> None:
    with pytest.raises(FusionContractError):
        weighted_score(
            supervised,
            anomaly,
            FusionWeights(supervised_weight=0.5, anomaly_weight=0.5),
        )


def test_weights_and_missing_scores_fail_validation_without_fallback() -> None:
    with pytest.raises(ValidationError, match="sum to one"):
        FusionWeights(supervised_weight=0.4, anomaly_weight=0.4)
    with pytest.raises(ValidationError):
        FusionScoreInput.model_validate(
            {
                **_input().model_dump(),
                "supervised_probability": None,
            }
        )


def test_fuse_score_validates_engine_identity_and_truthful_semantics() -> None:
    timestamp = datetime(2026, 7, 20, 1, tzinfo=UTC)
    result = fuse_score(_input(), _policy(), scored_at=timestamp)

    assert result.fusion_score == 0.5
    assert result.fusion_positive is True
    assert result.scored_at == timestamp
    assert "not probability" in result.semantics
    assert not hasattr(result, "severity")
    with pytest.raises(FusionContractError, match="identity"):
        fuse_score(
            _input().model_copy(update={"anomaly_model_version": "wrong"}),
            _policy(),
        )


def test_policy_rejects_inconsistent_weight_and_protocol_evidence() -> None:
    policy = _policy()

    with pytest.raises(ValidationError, match="outside the declared candidates"):
        PolicyManifest.model_validate(
            {
                **policy.model_dump(),
                "selected_weights": {
                    "supervised_weight": 0.75,
                    "anomaly_weight": 0.25,
                },
            }
        )
    with pytest.raises(ValidationError, match="predates"):
        PolicyManifest.model_validate(
            {
                **policy.model_dump(),
                "created_at": datetime(2026, 7, 18, tzinfo=UTC),
            }
        )
