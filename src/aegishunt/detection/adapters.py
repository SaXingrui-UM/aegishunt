"""Adapters that preserve verified Phase 5–7 scoring identities."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol

from aegishunt.detection.contracts import VerifiedScores
from aegishunt.detection.errors import DetectionContractError
from aegishunt.ml.anomaly.bundle import LoadedAnomalyModel
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
from aegishunt.ml.fusion.contracts import FusionScoreInput, PolicyManifest
from aegishunt.ml.fusion.scoring import fuse_score
from aegishunt.ml.supervised.bundle import LoadedModel
from aegishunt.ml.supervised.prediction import PredictionBatch, predict_batch


class FeatureScoreAdapter(Protocol):
    """Bounded scoring boundary used for original and replacement rows."""

    def score(self, features: tuple[float, ...]) -> VerifiedScores: ...


class ModelBundleScoreAdapter:
    """Score through loaded supervised/anomaly bundles and one verified fusion policy."""

    def __init__(
        self,
        *,
        supervised_model: LoadedModel,
        anomaly_model: LoadedAnomalyModel,
        fusion_policy: PolicyManifest,
        fusion_policy_checksum: str,
        scored_at: datetime | None = None,
    ) -> None:
        if fusion_policy.recommendation_status != "inconclusive":
            raise DetectionContractError("Phase 8 requires the recorded inconclusive fusion policy")
        self._supervised = supervised_model
        self._anomaly = anomaly_model
        self._fusion_policy = fusion_policy
        self._fusion_policy_checksum = fusion_policy_checksum
        self._scored_at = scored_at or datetime.now(UTC)

    def score(self, features: tuple[float, ...]) -> VerifiedScores:
        supervised_manifest = self._supervised.manifest
        anomaly_manifest = self._anomaly.manifest
        if supervised_manifest.feature_names != anomaly_manifest.feature_names:
            raise DetectionContractError("model feature orders do not match")
        if supervised_manifest.feature_schema_version != anomaly_manifest.feature_schema_version:
            raise DetectionContractError("model feature schemas do not match")
        supervised = predict_batch(
            self._supervised,
            PredictionBatch(
                feature_schema_version=supervised_manifest.feature_schema_version,
                feature_names=supervised_manifest.feature_names,
                dtype="float64",
                rows=(features,),
            ),
        )[0]
        anomaly = score_batch(
            self._anomaly,
            AnomalyPredictionBatch(
                feature_schema_version=anomaly_manifest.feature_schema_version,
                feature_names=anomaly_manifest.feature_names,
                dtype="float64",
                rows=(features,),
            ),
        )[0]
        fusion = fuse_score(
            FusionScoreInput(
                supervised_probability=supervised.calibrated_probability,
                normalized_anomaly_score=anomaly.normalized_anomaly_score,
                supervised_model_id=supervised.model_id,
                supervised_model_version=supervised.model_version,
                anomaly_model_id=anomaly.model_id,
                anomaly_model_version=anomaly.model_version,
                feature_schema_version=supervised.feature_schema_version,
            ),
            self._fusion_policy,
            scored_at=self._scored_at,
        )
        return VerifiedScores(
            supervised_label=supervised.predicted_label,
            supervised_probability=supervised.calibrated_probability,
            supervised_threshold=supervised.selected_threshold,
            anomaly_raw_score=anomaly.raw_model_score,
            normalized_anomaly_score=anomaly.normalized_anomaly_score,
            anomaly_threshold=anomaly.selected_threshold,
            fusion_score=fusion.fusion_score,
            fusion_threshold=fusion.selected_fusion_threshold,
            supervised_model_id=supervised.model_id,
            supervised_model_version=supervised.model_version,
            anomaly_model_id=anomaly.model_id,
            anomaly_model_version=anomaly.model_version,
            fusion_policy_id=fusion.policy_id,
            fusion_policy_version=fusion.policy_version,
            fusion_policy_checksum=self._fusion_policy_checksum,
            fusion_recommendation="inconclusive",
            feature_schema_version=supervised.feature_schema_version,
            scored_at=self._scored_at,
        )
