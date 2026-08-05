"""Investigation-case, feedback, and data-only export API."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi import Path as ApiPath
from fastapi.responses import FileResponse, Response

from aegishunt.api.audit_service import list_case_audit_events
from aegishunt.api.contracts import (
    AnalystFeedbackPage,
    ArtifactRequest,
    ArtifactResult,
    CaseAuditEventPage,
    CaseCloseRequest,
    CaseCreateRequest,
    CaseDetail,
    CaseEvidenceRequest,
    CaseNoteRequest,
    CaseReportRequest,
    CaseUpdateRequest,
    FeedbackRequest,
    InvestigationCasePage,
)
from aegishunt.api.dependencies import PaginationDependency, get_database, get_settings
from aegishunt.api.errors import ApiError, not_found
from aegishunt.api.repository import ApiReadRepository
from aegishunt.artifact_io import (
    configured_artifact_root,
    verified_data_artifact_zip,
)
from aegishunt.cases.config import LoadedCaseFeedbackPolicy, load_case_feedback_policy
from aegishunt.cases.reports import CaseReportService
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import ApplicationSettings
from aegishunt.feedback.candidates import RetrainingCandidateService
from aegishunt.feedback.export import FeedbackExportService
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas import (
    AnalystFeedback,
    CaseEvidenceReference,
    CaseNote,
    InvestigationCase,
)
from aegishunt.schemas.base import JsonObject, require_aware_utc
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CasePriority,
    CaseStatus,
    FeedbackObjectType,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AnalystFeedbackRepository,
    AuditLogRepository,
    CaseEvidenceReferenceRepository,
    CaseNoteRepository,
    InvestigationCaseRepository,
    ThreatHypothesisRepository,
)

router = APIRouter(tags=["cases", "feedback"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]


def _policy(settings: ApplicationSettings) -> LoadedCaseFeedbackPolicy:
    return load_case_feedback_policy(settings.case_feedback.policy_path)


@router.get("/cases", response_model=InvestigationCasePage, operation_id="list_cases")
def list_cases(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    case_status: CaseStatus | None = None,
    priority: CasePriority | None = None,
    assigned_to: str | None = None,
) -> InvestigationCasePage:
    with database.session() as session:
        items, total = ApiReadRepository(session).list_cases(
            limit=pagination.limit,
            offset=pagination.offset,
            status=case_status,
            priority=priority,
            assigned_to=assigned_to,
        )
    return InvestigationCasePage(
        items=items,
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
        next_offset=(
            pagination.offset + len(items)
            if pagination.offset + len(items) < total
            else None
        ),
    )


@router.get("/cases/{case_id}", response_model=CaseDetail, operation_id="get_case")
def get_case(case_id: UUID, database: DatabaseDependency) -> CaseDetail:
    with database.session() as session:
        case = InvestigationCaseRepository(session).get(case_id)
        if case is None:
            not_found("investigation case")
        hypothesis = (
            None
            if case.hypothesis_id is None
            else ThreatHypothesisRepository(session).get(case.hypothesis_id)
        )
        notes = CaseNoteRepository(session).list_by_case(case_id)
        evidence = CaseEvidenceReferenceRepository(session).list_by_case(case_id)
        feedback, _ = AnalystFeedbackRepository(session).list_filtered(
            limit=100,
            offset=0,
            object_type=FeedbackObjectType.CASE,
            object_id=str(case_id),
        )
    return CaseDetail(
        case=case,
        hypothesis=hypothesis,
        notes=notes,
        evidence=evidence,
        feedback=feedback,
    )


@router.get(
    "/cases/{case_id}/audit-events",
    response_model=CaseAuditEventPage,
    operation_id="list_case_audit_events",
)
def get_case_audit_events(
    case_id: UUID,
    database: DatabaseDependency,
    settings: SettingsDependency,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 50,
    action: Annotated[str | None, Query(max_length=255)] = None,
    actor: Annotated[str | None, Query(max_length=255)] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    order: Literal["asc", "desc"] = "desc",
) -> CaseAuditEventPage:
    """Read immutable case-related audit records through fixed filters."""

    if page_size > settings.web.maximum_page_size:
        raise ApiError(
            "page size exceeds the configured maximum",
            code="page_limit_exceeded",
            status_code=422,
            details={"maximum_page_size": settings.web.maximum_page_size},
        )
    if created_from is not None:
        try:
            created_from = require_aware_utc(created_from)
        except ValueError as exc:
            raise ApiError(
                "audit start time must be timezone-aware UTC",
                code="invalid_time_range",
                status_code=422,
            ) from exc
    if created_to is not None:
        try:
            created_to = require_aware_utc(created_to)
        except ValueError as exc:
            raise ApiError(
                "audit end time must be timezone-aware UTC",
                code="invalid_time_range",
                status_code=422,
            ) from exc
    if (
        created_from is not None
        and created_to is not None
        and created_from > created_to
    ):
        raise ApiError(
            "audit time range is invalid",
            code="invalid_time_range",
            status_code=422,
        )
    normalized_action = action.strip() if action is not None else None
    normalized_actor = actor.strip() if actor is not None else None
    offset = (page - 1) * page_size
    with database.session() as session:
        if InvestigationCaseRepository(session).get(case_id) is None:
            not_found("investigation case")
        items, total = list_case_audit_events(
            AuditLogRepository(session),
            case_id,
            limit=page_size,
            offset=offset,
            action=normalized_action or None,
            actor=normalized_actor or None,
            created_from=created_from,
            created_to=created_to,
            descending=order == "desc",
        )
    total_pages = (total + page_size - 1) // page_size
    return CaseAuditEventPage(
        items=items,
        total=total,
        limit=page_size,
        offset=offset,
        next_offset=offset + len(items) if offset + len(items) < total else None,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.post("/cases", response_model=InvestigationCase, operation_id="create_case")
def create_case(
    payload: CaseCreateRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> InvestigationCase:
    with database.session() as session, session.begin():
        return InvestigationCaseService(session, _policy(settings)).create_from_hypothesis(
            payload.hypothesis_id,
            actor=payload.actor,
        )


@router.patch("/cases/{case_id}", response_model=InvestigationCase, operation_id="update_case")
def update_case(
    case_id: UUID,
    payload: CaseUpdateRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> InvestigationCase:
    """Apply exactly one existing case-service mutation."""

    requested = {
        name
        for name in ("status", "priority", "assigned_to", "verdict")
        if name in payload.model_fields_set
    }
    if len(requested) != 1:
        raise ApiError(
            "case update must contain exactly one mutable field",
            code="ambiguous_case_update",
            status_code=400,
        )
    with database.session() as session, session.begin():
        service = InvestigationCaseService(session, _policy(settings))
        if "status" in requested:
            assert payload.status is not None
            return service.update_status(
                case_id,
                payload.status,
                actor=payload.actor,
                reason=payload.reason,
            )
        if "priority" in requested:
            assert payload.priority is not None
            return service.set_priority(
                case_id,
                payload.priority,
                actor=payload.actor,
                reason=payload.reason,
            )
        if "assigned_to" in requested:
            return service.assign(
                case_id,
                payload.assigned_to,
                actor=payload.actor,
                reason=payload.reason,
            )
        if payload.verdict is None or payload.verdict_confidence is None:
            raise ApiError(
                "verdict and verdict_confidence are required together",
                code="incomplete_case_verdict",
                status_code=400,
            )
        return service.set_verdict(
            case_id,
            payload.verdict,
            confidence=payload.verdict_confidence,
            reason=payload.reason,
            actor=payload.actor,
        )


@router.post("/cases/{case_id}/notes", response_model=CaseNote, operation_id="add_case_note")
def add_case_note(
    case_id: UUID,
    payload: CaseNoteRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> CaseNote:
    with database.session() as session, session.begin():
        return InvestigationCaseService(session, _policy(settings)).add_note(
            case_id,
            payload.body,
            actor=payload.actor,
            note_type=payload.note_type,
        )


@router.post(
    "/cases/{case_id}/evidence",
    response_model=CaseEvidenceReference,
    operation_id="add_case_evidence",
)
def add_case_evidence(
    case_id: UUID,
    payload: CaseEvidenceRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> CaseEvidenceReference:
    with database.session() as session, session.begin():
        return InvestigationCaseService(session, _policy(settings)).add_evidence(
            case_id,
            payload.object_type,
            payload.object_id,
            description=payload.description,
            actor=payload.actor,
        )


@router.post(
    "/cases/{case_id}/feedback",
    response_model=AnalystFeedback,
    operation_id="add_case_feedback",
)
def add_case_feedback(
    case_id: UUID,
    payload: FeedbackRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> AnalystFeedback:
    with database.session() as session, session.begin():
        return AnalystFeedbackService(session, _policy(settings)).record_case(
            case_id,
            payload.verdict,
            confidence=payload.confidence,
            notes=payload.notes,
            actor=payload.actor,
            source="phase12_api",
        )


@router.post(
    "/cases/{case_id}/close",
    response_model=InvestigationCase,
    operation_id="close_case",
)
def close_case(
    case_id: UUID,
    payload: CaseCloseRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> InvestigationCase:
    with database.session() as session, session.begin():
        return InvestigationCaseService(session, _policy(settings)).close(
            case_id,
            closure_note=payload.closure_note,
            actor=payload.actor,
        )


@router.post(
    "/cases/{case_id}/report",
    response_model=ArtifactResult,
    operation_id="generate_case_report",
)
def generate_case_report(
    case_id: UUID,
    payload: CaseReportRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ArtifactResult:
    with database.session() as session, session.begin():
        _, manifest = CaseReportService(
            session,
            _policy(settings),
            project_root=Path.cwd(),
        ).generate(case_id, payload.version, actor=payload.actor)
    return ArtifactResult(
        artifact_type="case_report",
        version=payload.version,
        manifest=cast(JsonObject, manifest.model_dump(mode="json")),
    )


@router.get(
    "/cases/{case_id}/reports/{version}",
    response_class=FileResponse,
    operation_id="download_case_report",
)
def download_case_report(
    case_id: UUID,
    version: Annotated[
        str,
        ApiPath(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ],
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> FileResponse:
    """Download one exact-inventory verified Markdown report without accepting a path."""

    loaded = _policy(settings)
    with database.session() as session:
        CaseReportService(
            session,
            loaded,
            project_root=Path.cwd(),
        ).verify(case_id, version)
    root = configured_artifact_root(Path.cwd(), loaded.policy.report_root)
    report = root / f"{case_id}-{version}" / "case_report.md"
    return FileResponse(
        report,
        media_type="text/markdown; charset=utf-8",
        filename=f"aegishunt-case-{case_id}-{version}.md",
    )


@router.get(
    "/feedback",
    response_model=AnalystFeedbackPage,
    operation_id="list_analyst_feedback",
)
def list_feedback(
    database: DatabaseDependency,
    settings: SettingsDependency,
    pagination: PaginationDependency,
    object_type: FeedbackObjectType | None = None,
    object_id: str | None = None,
    verdict: AnalystVerdict | None = None,
    actor: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> AnalystFeedbackPage:
    with database.session() as session:
        items, total = AnalystFeedbackService(session, _policy(settings)).list(
            limit=pagination.limit,
            offset=pagination.offset,
            object_type=object_type,
            object_id=object_id,
            verdict=verdict,
            actor=actor,
            created_from=created_from,
            created_to=created_to,
        )
    return AnalystFeedbackPage(
        items=items,
        total=total,
        limit=pagination.limit,
        offset=pagination.offset,
        next_offset=(
            pagination.offset + len(items)
            if pagination.offset + len(items) < total
            else None
        ),
    )


@router.get(
    "/feedback/{feedback_id}",
    response_model=AnalystFeedback,
    operation_id="get_analyst_feedback",
)
def get_feedback(feedback_id: UUID, database: DatabaseDependency) -> AnalystFeedback:
    with database.session() as session:
        feedback = AnalystFeedbackRepository(session).get(feedback_id)
    if feedback is None:
        not_found("analyst feedback")
    return feedback


@router.post(
    "/feedback/alerts/{alert_id}",
    response_model=AnalystFeedback,
    operation_id="add_alert_feedback",
)
def add_alert_feedback(
    alert_id: UUID,
    payload: FeedbackRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> AnalystFeedback:
    with database.session() as session, session.begin():
        return AnalystFeedbackService(session, _policy(settings)).record_alert(
            alert_id,
            payload.verdict,
            confidence=payload.confidence,
            notes=payload.notes,
            actor=payload.actor,
            source="phase12_api",
        )


@router.post(
    "/feedback/cases/{case_id}",
    response_model=AnalystFeedback,
    operation_id="add_feedback_for_case",
)
def add_feedback_for_case(
    case_id: UUID,
    payload: FeedbackRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> AnalystFeedback:
    return add_case_feedback(case_id, payload, database, settings)


@router.post(
    "/feedback/export",
    response_model=ArtifactResult,
    operation_id="export_analyst_feedback",
)
def export_feedback(
    payload: ArtifactRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ArtifactResult:
    with database.session() as session, session.begin():
        _, manifest = FeedbackExportService(
            session,
            _policy(settings),
            project_root=Path.cwd(),
        ).export(payload.version, actor=payload.actor)
    return ArtifactResult(
        artifact_type="feedback_export",
        version=payload.version,
        manifest=cast(JsonObject, manifest.model_dump(mode="json")),
    )


@router.get(
    "/feedback/exports/{version}/download",
    response_class=Response,
    operation_id="download_analyst_feedback_export",
)
def download_feedback_export(
    version: Annotated[
        str,
        ApiPath(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ],
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> Response:
    """Download one checksum-verified, exact-inventory feedback ZIP."""

    loaded = _policy(settings)
    with database.session() as session:
        FeedbackExportService(
            session,
            loaded,
            project_root=Path.cwd(),
        ).verify(version)
    root = configured_artifact_root(Path.cwd(), loaded.policy.export_root)
    archive = verified_data_artifact_zip(
        root / version,
        root=root,
        exact_inventory=loaded.policy.feedback_export_inventory,
    )
    return Response(
        content=archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="aegishunt-feedback-export-{version}.zip"'
            )
        },
    )


@router.post(
    "/feedback/retraining-candidates",
    response_model=ArtifactResult,
    operation_id="build_retraining_candidates",
)
def build_retraining_candidates(
    payload: ArtifactRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ArtifactResult:
    with database.session() as session, session.begin():
        _, manifest = RetrainingCandidateService(
            session,
            _policy(settings),
            project_root=Path.cwd(),
        ).build(payload.version, actor=payload.actor)
    return ArtifactResult(
        artifact_type="retraining_candidates",
        version=payload.version,
        manifest=cast(JsonObject, manifest.model_dump(mode="json")),
    )


@router.get(
    "/feedback/retraining-candidates/{version}/download",
    response_class=Response,
    operation_id="download_retraining_candidates",
)
def download_retraining_candidates(
    version: Annotated[
        str,
        ApiPath(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
    ],
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> Response:
    """Download one verified review-only candidate ZIP without training."""

    loaded = _policy(settings)
    with database.session() as session:
        RetrainingCandidateService(
            session,
            loaded,
            project_root=Path.cwd(),
        ).verify(version)
    root = configured_artifact_root(Path.cwd(), loaded.policy.candidate_root)
    archive = verified_data_artifact_zip(
        root / version,
        root=root,
        exact_inventory=loaded.policy.candidate_dataset_inventory,
    )
    return Response(
        content=archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="aegishunt-retraining-candidates-{version}.zip"'
            )
        },
    )
