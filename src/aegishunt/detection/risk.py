"""Fail-closed risk policy evaluation without score-source fallback."""

from __future__ import annotations

from aegishunt.detection.contracts import LoadedRiskPolicy, RiskDecision, VerifiedScores
from aegishunt.detection.errors import DetectionContractError
from aegishunt.detection.severity import map_severity


def evaluate_risk(scores: VerifiedScores, loaded_policy: LoadedRiskPolicy) -> RiskDecision:
    """Validate all upstream identities and map one configured score unchanged."""

    policy = loaded_policy.policy
    actual_identity = (
        scores.supervised_model_id,
        scores.supervised_model_version,
        scores.anomaly_model_id,
        scores.anomaly_model_version,
        scores.fusion_policy_id,
        scores.fusion_policy_version,
        scores.fusion_policy_checksum,
        scores.feature_schema_version,
        scores.fusion_recommendation,
    )
    required_identity = (
        policy.required_supervised_model_id,
        policy.required_supervised_model_version,
        policy.required_anomaly_model_id,
        policy.required_anomaly_model_version,
        policy.required_fusion_policy_id,
        policy.required_fusion_policy_version,
        policy.required_fusion_policy_checksum,
        policy.required_feature_schema_version,
        policy.required_fusion_recommendation,
    )
    if actual_identity != required_identity:
        raise DetectionContractError("score identities do not match the configured risk policy")

    score_by_source = {
        "fusion_score": scores.fusion_score,
        "supervised_probability": scores.supervised_probability,
        "normalized_anomaly_score": scores.normalized_anomaly_score,
    }
    risk_score = score_by_source[policy.score_source]
    return RiskDecision(
        risk_score=risk_score,
        score_source=policy.score_source,
        severity=map_severity(risk_score, policy.severity_bands),
        alert_threshold=policy.alert_threshold,
        alert_required=risk_score >= policy.alert_threshold,
        risk_policy_id=policy.policy_id,
        risk_policy_version=policy.policy_version,
        risk_policy_checksum=loaded_policy.configuration_checksum,
        semantics=policy.score_semantics,
    )
