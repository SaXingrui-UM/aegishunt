"""Deterministic analyst-facing alert construction without correlation or LLMs."""

from __future__ import annotations

from uuid import NAMESPACE_URL, uuid5

from pydantic import JsonValue

from aegishunt.detection.contracts import RiskDecision, VerifiedScores
from aegishunt.detection.errors import DetectionContractError
from aegishunt.explainability.contracts import Explanation
from aegishunt.schemas import DetectionResult, NetworkFlow, SecurityAlert
from aegishunt.schemas.base import JsonObject


def alert_type_for(scores: VerifiedScores) -> str:
    supervised = scores.supervised_probability >= scores.supervised_threshold
    anomaly = scores.normalized_anomaly_score >= scores.anomaly_threshold
    if supervised and anomaly:
        return "multi_engine_suspicion"
    if supervised:
        return "supervised_suspicion"
    if anomaly:
        return "anomalous_behavior"
    return "behavioral_pattern"


def create_security_alert(
    *,
    detection: DetectionResult,
    flow: NetworkFlow,
    scores: VerifiedScores,
    risk: RiskDecision,
    explanation: Explanation,
) -> SecurityAlert:
    """Create one alert only after the configured alert boundary is met."""

    if not risk.alert_required:
        raise DetectionContractError(
            "security alert cannot be created below the configured threshold"
        )
    codes = [item.code for item in explanation.reason_evidence]
    if not codes or "RISK_SCORE_ABOVE_ALERT_THRESHOLD" not in codes:
        raise DetectionContractError(
            "security alert requires threshold-backed reason evidence"
        )
    alert_type = alert_type_for(scores)
    alert_id = uuid5(NAMESPACE_URL, f"aegishunt-alert:{detection.detection_id}")
    evidence_model_versions: dict[str, JsonValue] = {
        key: value for key, value in detection.model_versions.items()
    }
    evidence_policy_versions: dict[str, JsonValue] = {
        key: value for key, value in detection.policy_versions.items()
    }
    evidence_reason_codes: list[JsonValue] = [code for code in codes]
    evidence: JsonObject = {
        "flow_id": str(flow.flow_id),
        "scoring_mode": risk.score_source,
        "risk_score": risk.risk_score,
        "risk_source": risk.score_source,
        "alert_threshold": risk.alert_threshold,
        "severity_band": risk.severity.value,
        "supervised_probability": scores.supervised_probability,
        "supervised_threshold": scores.supervised_threshold,
        "normalized_anomaly_score": scores.normalized_anomaly_score,
        "anomaly_threshold": scores.anomaly_threshold,
        "fusion_score": scores.fusion_score,
        "fusion_threshold": scores.fusion_threshold,
        "model_versions": evidence_model_versions,
        "policy_versions": evidence_policy_versions,
        "reason_codes": evidence_reason_codes,
        "top_local_contributions": [
            item.model_dump(mode="json") for item in explanation.local_contributions
        ],
        "observed_facts": explanation.observed_facts,
        "model_inferences": list(explanation.model_inferences),
        "generated_at": detection.detected_at.isoformat(),
        "uncertainty": "Suspiciousness evidence requires analyst review; it is not confirmation.",
    }
    description = (
        f"Configured {risk.score_source} risk {risk.risk_score:.6f} met the "
        f"{risk.alert_threshold:.6f} alert threshold at {risk.severity.value} triage "
        "severity. Review the recorded evidence; this is not a confirmed attack."
    )
    return SecurityAlert(
        alert_id=alert_id,
        detection_id=detection.detection_id,
        alert_type=alert_type,
        severity=risk.severity,
        risk_score=risk.risk_score,
        title="Suspicious network behavior detected",
        description=description,
        involved_entities=[
            f"source_ip:{flow.source_ip}",
            f"destination_ip:{flow.destination_ip}",
            f"flow_id:{flow.flow_id}",
        ],
        evidence=evidence,
        reason_codes=codes,
        explanation=explanation.model_dump(mode="json"),
        model_versions=detection.model_versions,
        policy_versions=detection.policy_versions,
        created_at=detection.detected_at,
        updated_at=detection.detected_at,
    )
