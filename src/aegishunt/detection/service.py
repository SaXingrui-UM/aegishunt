"""Transactional Phase 8 detection, explanation, alert, and verdict service."""

from __future__ import annotations

import hashlib
import json
from uuid import NAMESPACE_URL, UUID, uuid5

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from aegishunt.detection.adapters import FeatureScoreAdapter
from aegishunt.detection.alert_factory import create_security_alert
from aegishunt.detection.contracts import LoadedRiskPolicy, RiskDecision, VerifiedScores
from aegishunt.detection.errors import DetectionContractError, DetectionPersistenceError
from aegishunt.detection.risk import evaluate_risk
from aegishunt.explainability.contracts import Explanation, LoadedExplanationArtifact
from aegishunt.explainability.local_contributions import compute_local_contributions
from aegishunt.explainability.reason_codes import generate_reason_evidence
from aegishunt.flows.registry import feature_names
from aegishunt.schemas import DetectionResult, NetworkFlow, SecurityAlert
from aegishunt.schemas.enums import AnalystVerdict
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    SecurityAlertRepository,
)

_LIMITATIONS = (
    "Risk score is operational suspiciousness, not attack probability.",
    "Feature importance and local contributions are non-causal model sensitivity evidence.",
    "An alert is suspicious activity requiring analyst review, not a confirmed attack.",
    "Phase 7 fusion recommendation remains inconclusive.",
    "Phase 6 LOF remains validation-qualified without an untouched independent holdout.",
)


class DetectionAlertService:
    """Persist one complete scoring result and an optional alert atomically."""

    def __init__(
        self,
        session: Session,
        *,
        risk_policy: LoadedRiskPolicy,
        explanation_artifact: LoadedExplanationArtifact,
        local_top_k: int = 5,
        local_max_features: int = 43,
    ) -> None:
        self._session = session
        self._risk_policy = risk_policy
        self._artifact = explanation_artifact
        self._local_top_k = local_top_k
        self._local_max_features = local_max_features
        audit = AuditLogRepository(session)
        self._detections = DetectionResultRepository(session, audit)
        self._alerts = SecurityAlertRepository(session, audit)

    def evaluate_flow(
        self,
        flow: NetworkFlow,
        scorer: FeatureScoreAdapter,
        *,
        actor: str = "detection-service",
    ) -> tuple[DetectionResult, SecurityAlert | None]:
        """Score, explain, and persist one canonical flow within the caller transaction."""

        names = feature_names()
        if tuple(flow.behavioral_features) != names:
            raise DetectionContractError("flow feature names do not match the Phase 3 registry")
        values_list: list[float] = []
        for name in names:
            value = flow.behavioral_features[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise DetectionContractError("flow feature values must be numeric")
            values_list.append(float(value))
        values = tuple(values_list)
        scores = scorer.score(values)
        risk = evaluate_risk(scores, self._risk_policy)
        _validate_explanation_identities(self._artifact, scores, risk)
        profile = self._artifact.reference_profile
        if (
            profile.feature_names != names
            or profile.feature_schema_version != scores.feature_schema_version
        ):
            raise DetectionContractError("explanation profile does not match scored features")
        contributions = compute_local_contributions(
            values,
            feature_names=names,
            profile=profile,
            scorer=scorer,
            risk_policy=self._risk_policy,
            top_k=self._local_top_k,
            max_features=self._local_max_features,
        )
        reasons = generate_reason_evidence(
            {name: value for name, value in zip(names, values, strict=True)},
            profile=profile,
            scores=scores,
            risk=risk,
            catalog=self._artifact.reason_catalog,
        )
        explanation = Explanation(
            explanation_schema_version="1.0.0",
            observed_facts={
                "flow_id": str(flow.flow_id),
                "source_id": str(flow.source_id),
                "capture_session_id": flow.capture_session_id,
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "protocol": flow.protocol.value,
                "first_seen": flow.first_seen.isoformat(),
                "last_seen": flow.last_seen.isoformat(),
            },
            model_inferences=(
                f"Supervised probability={scores.supervised_probability:.6f}",
                f"Normalized anomaly score={scores.normalized_anomaly_score:.6f}",
                f"Fusion score={scores.fusion_score:.6f}",
                f"Operational risk={risk.risk_score:.6f} from {risk.score_source}",
            ),
            local_contributions=contributions,
            reason_evidence=reasons,
            limitations=_LIMITATIONS,
        )
        detection = _build_detection(flow, scores, risk, explanation)
        if self._detections.get(detection.detection_id) is not None:
            raise DetectionPersistenceError(
                "detection identity already exists; no overwrite occurred"
            )
        alert = (
            create_security_alert(
                detection=detection,
                flow=flow,
                scores=scores,
                risk=risk,
                explanation=explanation,
            )
            if risk.alert_required
            else None
        )
        try:
            stored_detection = self._detections.add(detection, actor=actor)
            stored_alert = None if alert is None else self._alerts.add(alert, actor=actor)
        except IntegrityError as exc:
            raise DetectionPersistenceError(
                "detection transaction violated persistence integrity"
            ) from exc
        return stored_detection, stored_alert

    def update_verdict(
        self,
        alert_id: UUID,
        verdict: AnalystVerdict,
        *,
        actor: str,
    ) -> SecurityAlert:
        """Update only the alert-level verdict; no training workflow is invoked."""

        return self._alerts.update_verdict(alert_id, verdict, actor=actor)


def _validate_explanation_identities(
    artifact: LoadedExplanationArtifact,
    scores: VerifiedScores,
    risk: RiskDecision,
) -> None:
    """Bind one explanation artifact to the exact models and policies in use."""

    manifest = artifact.manifest
    artifact_identity = (
        manifest.supervised_model_id,
        manifest.supervised_model_version,
        manifest.anomaly_model_id,
        manifest.anomaly_model_version,
        manifest.fusion_policy_id,
        manifest.fusion_policy_version,
        manifest.risk_policy_id,
        manifest.risk_policy_version,
        manifest.feature_schema_version,
    )
    scoring_identity = (
        scores.supervised_model_id,
        scores.supervised_model_version,
        scores.anomaly_model_id,
        scores.anomaly_model_version,
        scores.fusion_policy_id,
        scores.fusion_policy_version,
        risk.risk_policy_id,
        risk.risk_policy_version,
        scores.feature_schema_version,
    )
    if artifact_identity != scoring_identity:
        raise DetectionContractError(
            "explanation artifact identities do not match the scoring decision"
        )


def _build_detection(
    flow: NetworkFlow,
    scores: VerifiedScores,
    risk: RiskDecision,
    explanation: Explanation,
) -> DetectionResult:
    identity_payload = json.dumps(
        {
            "flow_id": str(flow.flow_id),
            "scores": scores.model_dump(mode="json", exclude={"scored_at"}),
            "risk_policy_checksum": risk.risk_policy_checksum,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(identity_payload).hexdigest()
    detection_id = uuid5(NAMESPACE_URL, f"aegishunt-detection:{digest}")
    reason_codes = [item.code for item in explanation.reason_evidence]
    return DetectionResult(
        detection_id=detection_id,
        flow_id=flow.flow_id,
        supervised_label=str(scores.supervised_label),
        supervised_probability=scores.supervised_probability,
        supervised_threshold=scores.supervised_threshold,
        anomaly_raw_score=scores.anomaly_raw_score,
        normalized_anomaly_score=scores.normalized_anomaly_score,
        anomaly_threshold=scores.anomaly_threshold,
        fusion_score=scores.fusion_score,
        fusion_threshold=scores.fusion_threshold,
        risk_score=risk.risk_score,
        risk_source=risk.score_source,
        severity=risk.severity,
        alert_threshold=risk.alert_threshold,
        model_versions={
            scores.supervised_model_id: scores.supervised_model_version,
            scores.anomaly_model_id: scores.anomaly_model_version,
        },
        policy_versions={
            scores.fusion_policy_id: scores.fusion_policy_version,
            risk.risk_policy_id: risk.risk_policy_version,
        },
        policy_checksums={
            scores.fusion_policy_id: scores.fusion_policy_checksum,
            risk.risk_policy_id: risk.risk_policy_checksum,
        },
        feature_schema_version=scores.feature_schema_version,
        reason_codes=reason_codes,
        explanation=explanation.model_dump(mode="json"),
        detected_at=scores.scored_at,
    )
