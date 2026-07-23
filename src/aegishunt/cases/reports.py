"""Deterministic JSON/Markdown investigation-case reporting."""

from __future__ import annotations

import html
import json
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import cast
from uuid import UUID

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
from aegishunt.cases.contracts import CaseReportManifest
from aegishunt.cases.errors import CaseArtifactError, CaseEligibilityError
from aegishunt.datasets.artifacts import safe_git_sha
from aegishunt.errors import DataArtifactError
from aegishunt.schemas import AnalystFeedback
from aegishunt.schemas.base import JsonObject, require_aware_utc, utc_now
from aegishunt.schemas.enums import FeedbackObjectType
from aegishunt.storage.repositories import (
    AnalystFeedbackRepository,
    AuditLogRepository,
    CaseEvidenceReferenceRepository,
    CaseNoteRepository,
    InvestigationCaseRepository,
    ThreatHypothesisRepository,
)
from aegishunt.storage.schema_version import CURRENT_SCHEMA_VERSION


def _safe_markdown(value: object) -> str:
    return html.escape(str(value), quote=True).replace("\n", "  \n")


def _feedback_for_case(
    repository: AnalystFeedbackRepository,
    case_id: UUID,
    related_alert_ids: list[str],
    *,
    maximum: int,
) -> list[AnalystFeedback]:
    rows, total = repository.list_filtered(limit=maximum, offset=0)
    if total > len(rows):
        raise CaseEligibilityError("case report exceeds configured feedback query bound")
    alert_ids = set(related_alert_ids)
    return [
        item
        for item in rows
        if (item.object_type is FeedbackObjectType.CASE and item.object_id == str(case_id))
        or (item.object_type is FeedbackObjectType.ALERT and item.object_id in alert_ids)
    ]


def _report_markdown(report: JsonObject) -> str:
    case = report["case"]
    lifecycle = report["case_lifecycle"]
    event_window = report["source_event_window"]
    judgment = report["analyst_judgment"]
    assert isinstance(case, dict)
    assert isinstance(lifecycle, dict)
    assert isinstance(event_window, dict)
    assert isinstance(judgment, dict)
    lines = [
        "# AegisHunt Investigation Case Report",
        "",
        "> Research prototype. This case is a review work item, not proof of attack or compromise.",
        "",
        "## Case",
        "",
        f"- ID: `{_safe_markdown(case['case_id'])}`",
        f"- Title: {_safe_markdown(case['title'])}",
        f"- Status: `{_safe_markdown(case['status'])}`",
        f"- Triage priority: `{_safe_markdown(case['priority'])}` (not attack certainty)",
        f"- Assigned to: {_safe_markdown(case.get('assigned_to') or 'unassigned')}",
        "",
        "## Timelines",
        "",
        f"- Source event first seen: `{_safe_markdown(event_window['first_seen'])}`",
        f"- Source event last seen: `{_safe_markdown(event_window['last_seen'])}`",
        f"- Case created: `{_safe_markdown(lifecycle['created_at'])}`",
        f"- Case updated: `{_safe_markdown(lifecycle['updated_at'])}`",
        f"- Case closed: `{_safe_markdown(lifecycle.get('closed_at') or 'not closed')}`",
        "",
        "## Evidence and inference boundaries",
        "",
        "Observed evidence, model-derived inferences, and analyst judgment remain "
        "separate in the JSON report.",
        "Evidence references are immutable snapshots with SHA-256 checksums.",
        "Possible MITRE mappings are hypotheses, not attribution.",
        "Recommended queries are shown as text and are never executed by report generation.",
        "",
        "## Analyst judgment",
        "",
        f"- Verdict: `{_safe_markdown(judgment.get('verdict') or 'not set')}`",
        f"- Confidence: `{_safe_markdown(judgment.get('confidence'))}`",
        f"- Reason: {_safe_markdown(judgment.get('reason') or 'not set')}",
        "",
        "## Limitations",
        "",
        "- Analyst feedback may be noisy and is not benchmark ground truth.",
        "- A case-level verdict is not propagated to every related flow.",
        "- This report does not execute queries, automate response, train models, "
        "or activate models.",
        "",
    ]
    return "\n".join(lines)


class CaseReportService:
    """Generate and verify cautious exact-inventory case reports."""

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
        self._cases = InvestigationCaseRepository(session)
        self._notes = CaseNoteRepository(session)
        self._references = CaseEvidenceReferenceRepository(session)
        self._feedback = AnalystFeedbackRepository(session)
        self._hypotheses = ThreatHypothesisRepository(session)
        self._audit = AuditLogRepository(session)

    def generate(
        self,
        case_id: UUID,
        version: str,
        *,
        actor: str,
    ) -> tuple[Path, CaseReportManifest]:
        normalized_actor = actor.strip()
        if not normalized_actor:
            raise CaseEligibilityError("case report actor is required")
        case = self._cases.get(case_id)
        if case is None or case.hypothesis_id is None:
            raise CaseEligibilityError("investigation case does not exist")
        hypothesis = self._hypotheses.get(case.hypothesis_id)
        if hypothesis is None:
            raise CaseEligibilityError("case source hypothesis cannot be resolved")
        notes = self._notes.list_by_case(case_id)
        references = self._references.list_by_case(case_id)
        feedback = _feedback_for_case(
            self._feedback,
            case_id,
            case.related_alert_ids,
            maximum=self._loaded.policy.maximum_feedback_per_query,
        )
        related_ids = {str(case_id), *(str(item.feedback_id) for item in feedback)}
        audit_events = [
            item for item in self._audit.list() if item.object_id in related_ids
        ]
        generated_at = require_aware_utc(self._clock())
        report = cast(
            JsonObject,
            {
            "report_schema_version": "1.0.0",
            "generated_at": generated_at.isoformat(),
            "case": case.model_dump(mode="json"),
            "case_lifecycle": {
                "created_at": case.created_at.isoformat(),
                "updated_at": case.updated_at.isoformat(),
                "closed_at": None if case.closed_at is None else case.closed_at.isoformat(),
            },
            "source_event_window": {
                "first_seen": hypothesis.first_seen.isoformat(),
                "last_seen": hypothesis.last_seen.isoformat(),
            },
            "observed_evidence": {
                "facts": hypothesis.observed_facts,
                "references": [item.model_dump(mode="json") for item in references],
            },
            "model_inference": {
                "hypothesis_title": hypothesis.title,
                "derived_inferences": hypothesis.derived_inferences,
                "assumptions": hypothesis.assumptions,
                "benign_alternatives": hypothesis.alternative_explanations,
                "possible_mitre_mappings": [
                    item.model_dump(mode="json")
                    if not isinstance(item, str)
                    else item
                    for item in hypothesis.possible_mitre_mappings
                ],
                "recommended_queries_not_executed": [
                    item.model_dump(mode="json")
                    if not isinstance(item, str)
                    else item
                    for item in hypothesis.recommended_queries
                ],
                "recommended_steps": hypothesis.recommended_steps,
            },
            "analyst_judgment": {
                "verdict": None if case.verdict is None else case.verdict.value,
                "confidence": case.verdict_confidence,
                "reason": case.verdict_reason,
                "semantics": "current analyst judgment; not absolute ground truth",
            },
            "notes": [item.model_dump(mode="json") for item in notes],
            "feedback_summary": [item.model_dump(mode="json") for item in feedback],
            "audit_timeline": [item.model_dump(mode="json") for item in audit_events],
            "limitations": [
                "A case is a review work item and does not confirm an attack.",
                "Analyst feedback may be noisy and is not benchmark ground truth.",
                "Case verdicts are not propagated into row-level flow labels.",
                "No query, response, training, or model activation is performed.",
            ],
            },
        )
        inventory = self._loaded.policy.case_report_inventory
        report_version = f"{case_id}-{version}"
        manifest = CaseReportManifest(
            report_id=f"case-report-{case_id}-{version}",
            report_version=report_version,
            report_schema_version="1.0.0",
            case_schema_version="1.0.0",
            case_id=str(case_id),
            generated_at=generated_at,
            generated_by=normalized_actor,
            git_commit=safe_git_sha(),
            database_schema_version=CURRENT_SCHEMA_VERSION,
            file_inventory=inventory,
            evidence_reference_count=len(references),
            note_count=len(notes),
            feedback_count=len(feedback),
            limitations=(
                "Research prototype report; not incident confirmation.",
                "No LLM, network lookup, query execution, or automated response.",
            ),
        )
        payloads = {
            "case_report.json": json_bytes(report),
            "case_report.md": _report_markdown(report).encode(),
            "manifest.json": json_bytes(manifest.model_dump(mode="json")),
        }
        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.report_root
            )
            destination = write_data_artifact(
                root=root,
                version=report_version,
                payloads=payloads,
                exact_inventory=inventory,
            )
        except DataArtifactError as exc:
            raise CaseArtifactError(str(exc)) from exc
        self._audit.record(
            actor=normalized_actor,
            action="export_case_report",
            object_type="case_report",
            object_id=manifest.report_id,
            details={
                "operation_id": f"case-report:{case_id}:{version}",
                "before": None,
                "after": {"report_id": manifest.report_id},
                "reason": "explicit versioned case report export",
                "source": "case_report_service",
                "case_id": str(case_id),
                "manifest_checksum": sha256_bytes(payloads["manifest.json"]),
                "query_execution": False,
                "automated_response": False,
            },
            created_at=generated_at,
        )
        return destination, manifest

    def verify(self, case_id: UUID, version: str) -> CaseReportManifest:
        report_version = f"{case_id}-{version}"
        try:
            root = configured_artifact_root(
                self._project_root, self._loaded.policy.report_root
            )
            payloads = verify_data_artifact(
                root / report_version,
                root=root,
                exact_inventory=self._loaded.policy.case_report_inventory,
            )
            manifest = CaseReportManifest.model_validate_json(payloads["manifest.json"])
            json.loads(payloads["case_report.json"])
            payloads["case_report.md"].decode()
        except (
            DataArtifactError,
            ValidationError,
            KeyError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise CaseArtifactError("case report verification failed") from exc
        if (
            manifest.case_id != str(case_id)
            or manifest.report_version != report_version
            or manifest.file_inventory != self._loaded.policy.case_report_inventory
        ):
            raise CaseArtifactError("case report identity is inconsistent")
        return manifest
