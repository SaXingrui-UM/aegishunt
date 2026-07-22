"""Versioned, deterministic, data-only analyst-feedback exports."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError
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
from aegishunt.feedback.contracts import FeedbackExportManifest
from aegishunt.feedback.errors import FeedbackArtifactError, FeedbackEligibilityError
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas import AnalystFeedback
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import AnalystVerdict, FeedbackObjectType
from aegishunt.storage.repositories import AuditLogRepository
from aegishunt.storage.schema_version import CURRENT_SCHEMA_VERSION


def _jsonl(rows: list[AnalystFeedback]) -> bytes:
    return b"".join(
        json.dumps(row.model_dump(mode="json"), sort_keys=True, ensure_ascii=False).encode()
        + b"\n"
        for row in rows
    )


class FeedbackExportService:
    """Export bounded feedback records without treating them as training data."""

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
        self._audit = AuditLogRepository(session)

    def export(
        self,
        version: str,
        *,
        actor: str,
        object_type: FeedbackObjectType | None = None,
        verdict: AnalystVerdict | None = None,
    ) -> tuple[Path, FeedbackExportManifest]:
        """Write one exact-inventory export and record its sanitized identity."""

        normalized_actor = actor.strip()
        if not normalized_actor:
            raise FeedbackEligibilityError("feedback export actor is required")
        maximum = self._loaded.policy.maximum_feedback_per_query
        rows, total = self._feedback.list(
            limit=maximum,
            object_type=object_type,
            verdict=verdict,
        )
        if total > len(rows):
            raise FeedbackEligibilityError("feedback export exceeds configured query bound")
        rows = sorted(rows, key=lambda item: (item.created_at, str(item.feedback_id)))
        filters: JsonObject = {
            "object_type": None if object_type is None else object_type.value,
            "verdict": None if verdict is None else verdict.value,
        }
        generated_at = require_aware_utc(self._clock())
        inventory = self._loaded.policy.feedback_export_inventory
        manifest = FeedbackExportManifest(
            export_id=f"feedback-export-{version}",
            export_version=version,
            export_schema_version=self._loaded.policy.feedback_export_schema_version,
            feedback_schema_version="1.0.0",
            filters=filters,
            record_count=len(rows),
            object_type_counts=dict(Counter(row.object_type.value for row in rows)),
            verdict_counts=dict(Counter(row.verdict.value for row in rows)),
            source_feedback_ids=tuple(str(row.feedback_id) for row in rows),
            generated_at=generated_at,
            generated_by=normalized_actor,
            git_commit=safe_git_sha(),
            database_schema_version=CURRENT_SCHEMA_VERSION,
            file_inventory=inventory,
            limitations=(
                "Human-supplied feedback may be noisy or inconsistent.",
                "This export is data-only and is not an approved training dataset.",
                "Exporting does not train, activate, or replace any model.",
            ),
        )
        schema = {
            "schema_version": "1.0.0",
            "record_contract": "AnalystFeedback",
            "ordering": ["created_at", "feedback_id"],
            "trust_boundary": "human_supplied_possible_noisy_label",
            "training_status": "not_a_training_dataset",
        }
        payloads = {
            "feedback.jsonl": _jsonl(rows),
            "manifest.json": json_bytes(manifest.model_dump(mode="json")),
            "schema.json": json_bytes(schema),
        }
        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.export_root
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
            action="export_feedback",
            object_type="feedback_export",
            object_id=manifest.export_id,
            details={
                "operation_id": f"feedback-export:{version}",
                "version": version,
                "record_count": len(rows),
                "source": "explicit_analyst_action",
                "manifest_checksum": sha256_bytes(payloads["manifest.json"]),
            },
            created_at=generated_at,
        )
        return destination, manifest

    def verify(self, version: str) -> FeedbackExportManifest:
        """Verify exact inventory and deserialize the validated manifest."""

        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.export_root
            )
            payloads = verify_data_artifact(
                root / version,
                root=root,
                exact_inventory=self._loaded.policy.feedback_export_inventory,
            )
            manifest = FeedbackExportManifest.model_validate_json(
                payloads["manifest.json"]
            )
        except (DataArtifactError, ValidationError, KeyError) as exc:
            raise FeedbackArtifactError("feedback export verification failed") from exc
        if manifest.export_version != version or manifest.file_inventory != (
            self._loaded.policy.feedback_export_inventory
        ):
            raise FeedbackArtifactError("feedback export identity is inconsistent")
        return manifest
