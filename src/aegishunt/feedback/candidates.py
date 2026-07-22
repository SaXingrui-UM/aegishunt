"""Explicit retraining-candidate construction with evaluation-leakage gates."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal, cast
from uuid import UUID, uuid5

from pydantic import JsonValue, ValidationError
from sqlalchemy.orm import Session

from aegishunt.artifact_io import (
    configured_artifact_root,
    json_bytes,
    sha256_bytes,
    verify_data_artifact,
    write_data_artifact,
)
from aegishunt.cases.config import LoadedCaseFeedbackPolicy
from aegishunt.datasets.artifacts import safe_git_sha
from aegishunt.errors import DataArtifactError
from aegishunt.feedback.contracts import (
    CandidateConflict,
    CandidateExclusion,
    CandidateManifest,
    CandidateRow,
)
from aegishunt.feedback.errors import FeedbackArtifactError, FeedbackEligibilityError
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.schemas import AnalystFeedback, DetectionResult, NetworkFlow, SecurityAlert
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import AnalystVerdict, FeedbackObjectType
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    TelemetrySourceRepository,
)
from aegishunt.storage.schema_version import CURRENT_SCHEMA_VERSION

_CANDIDATE_NAMESPACE = UUID("6111ce21-c7c6-5d3c-8f96-b4dedab5a579")

CandidateLabel = Literal["malicious", "benign"]


def _mapped_label(verdict: AnalystVerdict) -> CandidateLabel | None:
    if verdict is AnalystVerdict.TRUE_POSITIVE:
        return "malicious"
    if verdict in {AnalystVerdict.FALSE_POSITIVE, AnalystVerdict.BENIGN_EXPECTED}:
        return "benign"
    return None


def _required_metadata(metadata: JsonObject, name: str) -> str | None:
    value = metadata.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _candidate_jsonl(rows: list[CandidateRow]) -> bytes:
    return b"".join(
        json.dumps(row.model_dump(mode="json"), sort_keys=True, ensure_ascii=False).encode()
        + b"\n"
        for row in rows
    )


def _feature_values(flow: NetworkFlow) -> tuple[float, ...]:
    values: list[float] = []
    for name in feature_names():
        value = flow.behavioral_features[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise FeedbackEligibilityError("candidate feature vector is non-numeric")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise FeedbackEligibilityError("candidate feature vector is non-finite")
        values.append(numeric)
    return tuple(values)


class RetrainingCandidateService:
    """Build review-only candidate rows from uniquely mapped alert feedback."""

    def __init__(
        self,
        session: Session,
        loaded_policy: LoadedCaseFeedbackPolicy,
        *,
        project_root: Path,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._session = session
        self._loaded = loaded_policy
        self._project_root = project_root
        self._clock = clock
        self._feedback = AnalystFeedbackService(session, loaded_policy, clock=clock)
        self._alerts = SecurityAlertRepository(session)
        self._detections = DetectionResultRepository(session)
        self._flows = NetworkFlowRepository(session)
        self._sources = TelemetrySourceRepository(session)
        self._audit = AuditLogRepository(session)

    def build(
        self,
        version: str,
        *,
        actor: str,
    ) -> tuple[Path, CandidateManifest]:
        """Build an immutable candidate artifact; never invoke model code."""

        normalized_actor = actor.strip()
        if not normalized_actor:
            raise FeedbackEligibilityError("candidate-build actor is required")
        maximum = self._loaded.policy.maximum_feedback_per_query
        feedback_rows, total = self._feedback.list(limit=maximum)
        if total > len(feedback_rows):
            raise FeedbackEligibilityError("candidate build exceeds feedback query bound")
        feedback_rows = sorted(
            feedback_rows, key=lambda item: (item.created_at, str(item.feedback_id))
        )
        exclusions: list[CandidateExclusion] = []
        grouped: dict[
            str,
            list[
                tuple[
                    AnalystFeedback,
                    CandidateLabel,
                    SecurityAlert,
                    DetectionResult,
                    NetworkFlow,
                    JsonObject,
                ]
            ],
        ] = defaultdict(list)
        for feedback in feedback_rows:
            resolved = self._resolve(feedback)
            if isinstance(resolved, str):
                exclusions.append(
                    CandidateExclusion(
                        feedback_id=str(feedback.feedback_id),
                        object_id=feedback.object_id,
                        reason=resolved,
                    )
                )
                continue
            label, alert, detection, flow, provenance = resolved
            grouped[str(flow.flow_id)].append(
                (feedback, label, alert, detection, flow, provenance)
            )

        generated_at = require_aware_utc(self._clock())
        conflicts: list[CandidateConflict] = []
        candidates: list[CandidateRow] = []
        for flow_id, items in sorted(grouped.items()):
            labels = sorted({item[1] for item in items})
            feedback_ids = tuple(sorted(str(item[0].feedback_id) for item in items))
            if len(labels) != 1:
                conflicts.append(
                    CandidateConflict(
                        flow_id=flow_id,
                        feedback_ids=feedback_ids,
                        labels=tuple(labels),
                    )
                )
                continue
            _, label, alert, detection, flow, provenance = items[0]
            confidence = min(item[0].confidence for item in items)
            names = feature_names()
            values = _feature_values(flow)
            candidate_id = uuid5(
                _CANDIDATE_NAMESPACE,
                f"{flow_id}:{label}:{FEATURE_SCHEMA_VERSION}:1.0.0",
            )
            candidates.append(
                CandidateRow(
                    candidate_id=str(candidate_id),
                    feature_schema_version=FEATURE_SCHEMA_VERSION,
                    feature_names=names,
                    feature_values=values,
                    candidate_label=label,
                    label_mapping_version=self._loaded.policy.candidate_label_mapping_version,
                    source_flow_id=flow_id,
                    source_detection_id=str(detection.detection_id),
                    source_alert_id=str(alert.alert_id),
                    supporting_feedback_ids=feedback_ids,
                    confidence=confidence,
                    provenance=provenance,
                    created_at=generated_at,
                )
            )

        candidates.sort(key=lambda item: (item.source_flow_id, item.candidate_id))
        exclusions.sort(key=lambda item: (item.feedback_id, item.reason))
        conflicts.sort(key=lambda item: item.flow_id)
        inventory = self._loaded.policy.candidate_dataset_inventory
        eligibility_status: Literal[
            "requires_manual_review", "insufficient_records", "empty"
        ]
        if not candidates:
            eligibility_status = "empty"
        elif len(candidates) < self._loaded.policy.candidate_dataset_minimum_records:
            eligibility_status = "insufficient_records"
        else:
            eligibility_status = "requires_manual_review"
        manifest = CandidateManifest(
            dataset_id=f"retraining-candidates-{version}",
            dataset_version=version,
            candidate_dataset_schema_version=(
                self._loaded.policy.candidate_dataset_schema_version
            ),
            eligibility_status=eligibility_status,
            candidate_count=len(candidates),
            exclusion_count=len(exclusions),
            conflict_count=len(conflicts),
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=feature_names(),
            label_mapping_version=self._loaded.policy.candidate_label_mapping_version,
            source_feedback_ids=tuple(str(row.feedback_id) for row in feedback_rows),
            generated_at=generated_at,
            git_commit=safe_git_sha(),
            database_schema_version=CURRENT_SCHEMA_VERSION,
            file_inventory=inventory,
            requirements=(
                "Requires manual review and Phase 4-equivalent dataset-quality validation.",
                "Must meet the configured minimum record count before downstream review.",
                "Requires a new group-aware split before any explicit training command.",
                "Must not include historical evaluation, test, holdout, or unknown provenance.",
                "Does not trigger training or model activation; current models are unchanged.",
            ),
        )
        schema = {
            "schema_version": self._loaded.policy.candidate_dataset_schema_version,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "feature_names": feature_names(),
            "feature_metadata_separation": True,
            "label_mapping": {
                "true_positive": "malicious",
                "false_positive": "benign",
                "benign_expected": "benign",
                "needs_more_information": "excluded",
            },
            "status": "retraining_candidate",
        }
        payloads = {
            "candidate_manifest.json": json_bytes(manifest.model_dump(mode="json")),
            "candidate_schema.json": json_bytes(schema),
            "candidates.jsonl": _candidate_jsonl(candidates),
            "conflicts.json": json_bytes(
                [item.model_dump(mode="json") for item in conflicts]
            ),
            "exclusions.json": json_bytes(
                [item.model_dump(mode="json") for item in exclusions]
            ),
        }
        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.candidate_root
            )
            destination = write_data_artifact(
                root=root,
                version=version,
                payloads=payloads,
                exact_inventory=inventory,
            )
        except DataArtifactError as exc:
            raise FeedbackArtifactError(str(exc)) from exc
        self._audit.record(
            actor=normalized_actor,
            action="build_retraining_candidates",
            object_type="retraining_candidate_dataset",
            object_id=manifest.dataset_id,
            details={
                "operation_id": f"candidate-build:{version}",
                "candidate_count": len(candidates),
                "exclusion_count": len(exclusions),
                "conflict_count": len(conflicts),
                "manifest_checksum": sha256_bytes(
                    payloads["candidate_manifest.json"]
                ),
                "status": "retraining_candidate",
                "source": "explicit_analyst_action",
                "training_invoked": False,
                "model_activation_invoked": False,
            },
            created_at=generated_at,
        )
        return destination, manifest

    def _resolve(
        self, feedback: AnalystFeedback
    ) -> tuple[
        CandidateLabel,
        SecurityAlert,
        DetectionResult,
        NetworkFlow,
        JsonObject,
    ] | str:
        if feedback.object_type is not FeedbackObjectType.ALERT:
            return "case-level feedback is not propagated to flow labels"
        label = _mapped_label(feedback.verdict)
        if label is None:
            return "needs_more_information is not an eligible row label"
        if feedback.confidence < self._loaded.policy.feedback_confidence_minimum:
            return "feedback confidence is below the configured minimum"
        try:
            alert_id = UUID(feedback.object_id)
        except ValueError:
            return "feedback alert identity is invalid"
        alert = self._alerts.get(alert_id)
        if alert is None:
            return "feedback alert cannot be resolved"
        detection = self._detections.get(alert.detection_id)
        if detection is None:
            return "alert detection cannot be resolved"
        flow = self._flows.get(detection.flow_id)
        if flow is None:
            return "detection flow cannot be resolved"
        if not flow.behavioral_features or tuple(flow.behavioral_features) != feature_names():
            return "flow does not contain the fixed Phase 3 feature contract"
        values = tuple(flow.behavioral_features.values())
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in values
        ):
            return "flow feature vector contains a non-finite or non-numeric value"
        source = self._sources.get(flow.source_id)
        if source is None:
            return "flow telemetry provenance cannot be resolved"
        metadata = source.source_metadata
        partition = _required_metadata(metadata, "provenance_partition")
        provenance_type = _required_metadata(metadata, "provenance_type")
        dataset_id = _required_metadata(metadata, "dataset_id")
        dataset_version = _required_metadata(metadata, "dataset_version")
        scenario_id = _required_metadata(metadata, "scenario_id")
        group_id = _required_metadata(metadata, "group_id")
        if None in {
            partition,
            provenance_type,
            dataset_id,
            dataset_version,
            scenario_id,
            group_id,
        }:
            return "telemetry provenance is incomplete or unknown"
        assert partition is not None
        assert provenance_type is not None
        if partition in self._loaded.policy.excluded_provenance_partitions:
            return f"provenance partition is excluded: {partition}"
        if partition not in self._loaded.policy.eligible_provenance_partitions:
            return "provenance partition is not explicitly eligible"
        if provenance_type not in self._loaded.policy.eligible_provenance_types:
            return "provenance type is not explicitly eligible"
        provenance: JsonObject = {
            "provenance_partition": partition,
            "provenance_type": provenance_type,
            "dataset_id": cast(JsonValue, dataset_id),
            "dataset_version": cast(JsonValue, dataset_version),
            "capture_session_id": flow.capture_session_id,
            "scenario_id": cast(JsonValue, scenario_id),
            "group_id": cast(JsonValue, group_id),
            "source_id": str(source.source_id),
            "evaluation_exclusion_decision": "eligible_non_evaluation_source",
        }
        return label, alert, detection, flow, provenance

    def verify(self, version: str) -> CandidateManifest:
        """Verify candidate inventory/checksums and parse every row contract."""

        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.candidate_root
            )
            payloads = verify_data_artifact(
                root / version,
                root=root,
                exact_inventory=self._loaded.policy.candidate_dataset_inventory,
            )
            manifest = CandidateManifest.model_validate_json(
                payloads["candidate_manifest.json"]
            )
            rows = [
                CandidateRow.model_validate_json(line)
                for line in payloads["candidates.jsonl"].splitlines()
            ]
            json.loads(payloads["conflicts.json"])
            json.loads(payloads["exclusions.json"])
        except (
            DataArtifactError,
            ValidationError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            raise FeedbackArtifactError("candidate artifact verification failed") from exc
        if (
            manifest.dataset_version != version
            or manifest.candidate_count != len(rows)
            or manifest.file_inventory
            != self._loaded.policy.candidate_dataset_inventory
        ):
            raise FeedbackArtifactError("candidate artifact identity is inconsistent")
        return manifest
