"""Typed, immutable, checksummed database evidence references."""

from __future__ import annotations

import json
from datetime import datetime
from typing import cast
from uuid import UUID

from pydantic import JsonValue
from sqlalchemy.orm import Session

from aegishunt.artifact_io import sha256_bytes
from aegishunt.cases.errors import CaseEligibilityError
from aegishunt.cases.lifecycle import reference_identity
from aegishunt.schemas import CaseEvidenceReference
from aegishunt.schemas.base import CoreSchema, JsonObject
from aegishunt.schemas.enums import CaseEvidenceObjectType
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
    ThreatHypothesisRepository,
)


class EvidenceResolver:
    """Resolve only allowlisted persisted entities; never read files or URLs."""

    def __init__(self, session: Session) -> None:
        self._hypotheses = ThreatHypothesisRepository(session)
        self._groups = AlertGroupRepository(session)
        self._alerts = SecurityAlertRepository(session)
        self._detections = DetectionResultRepository(session)
        self._flows = NetworkFlowRepository(session)

    def resolve(self, object_type: CaseEvidenceObjectType, object_id: str) -> JsonObject:
        try:
            identifier = UUID(object_id)
        except ValueError as exc:
            raise CaseEligibilityError("evidence object ID must be a UUID") from exc
        entity: CoreSchema | None
        if object_type is CaseEvidenceObjectType.THREAT_HYPOTHESIS:
            entity = self._hypotheses.get(identifier)
        elif object_type is CaseEvidenceObjectType.ALERT_GROUP:
            entity = self._groups.get(identifier)
        elif object_type is CaseEvidenceObjectType.SECURITY_ALERT:
            entity = self._alerts.get(identifier)
        elif object_type is CaseEvidenceObjectType.DETECTION_RESULT:
            entity = self._detections.get(identifier)
        else:
            entity = self._flows.get(identifier)
        if entity is None:
            raise CaseEligibilityError("referenced evidence object does not exist")
        snapshot = entity.model_dump(mode="json")
        if object_type is CaseEvidenceObjectType.NETWORK_FLOW:
            snapshot.pop("ground_truth_label", None)
            snapshot.pop("attack_family", None)
        return cast(dict[str, JsonValue], snapshot)

    @staticmethod
    def checksum(snapshot: JsonObject) -> str:
        payload = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
        return sha256_bytes(payload)

    def reference(
        self,
        *,
        case_id: UUID,
        object_type: CaseEvidenceObjectType,
        object_id: str,
        description: str,
        actor: str,
        added_at: datetime,
    ) -> CaseEvidenceReference:
        snapshot = self.resolve(object_type, object_id)
        schema_version = next(
            (
                str(value)
                for key, value in snapshot.items()
                if key.endswith("_schema_version") and value is not None
            ),
            None,
        )
        return CaseEvidenceReference(
            reference_id=reference_identity(case_id, object_type, object_id),
            case_id=case_id,
            object_type=object_type,
            object_id=object_id,
            object_schema_version=schema_version,
            snapshot=snapshot,
            snapshot_checksum=self.checksum(snapshot),
            description=description,
            added_by=actor,
            added_at=added_at,
        )
