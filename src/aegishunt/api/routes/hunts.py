"""Alert-group and threat-hypothesis APIs."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from aegishunt.api.contracts import (
    AlertGroupDetail,
    AlertGroupPage,
    CreateCaseFromHypothesisRequest,
    HypothesisDetail,
    HypothesisStatusRequest,
    ThreatHypothesisPage,
)
from aegishunt.api.dependencies import (
    PaginationDependency,
    RuntimeJobScopeDependency,
    get_database,
    get_settings,
)
from aegishunt.api.errors import not_found
from aegishunt.api.repository import ApiReadRepository
from aegishunt.cases.config import load_case_feedback_policy
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import ApplicationSettings
from aegishunt.schemas import InvestigationCase, ThreatHypothesis
from aegishunt.schemas.base import utc_now
from aegishunt.schemas.enums import HypothesisStatus, Severity
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    ThreatHypothesisRepository,
)

router = APIRouter(tags=["alert-groups", "hypotheses"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]


@router.get(
    "/alert-groups",
    response_model=AlertGroupPage,
    operation_id="list_alert_groups",
)
def list_alert_groups(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    runtime_scope: RuntimeJobScopeDependency,
    severity: Severity | None = None,
    group_status: str | None = None,
) -> AlertGroupPage:
    with database.session() as session:
        items, total = ApiReadRepository(session).list_groups(
            limit=pagination.limit,
            offset=pagination.offset,
            severity=severity,
            status=group_status,
            runtime_scope=runtime_scope,
        )
    return AlertGroupPage(
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
    "/alert-groups/{group_id}",
    response_model=AlertGroupDetail,
    operation_id="get_alert_group",
)
def get_alert_group(group_id: UUID, database: DatabaseDependency) -> AlertGroupDetail:
    with database.session() as session:
        repository = AlertGroupRepository(session)
        group = repository.get(group_id)
        if group is None:
            not_found("alert group")
        alerts = repository.list_members(group_id)
        hypothesis = ThreatHypothesisRepository(session).get_by_group(group_id)
    return AlertGroupDetail(
        group=group,
        alerts=alerts,
        hypothesis_id=None if hypothesis is None else hypothesis.hypothesis_id,
    )


@router.get(
    "/hypotheses",
    response_model=ThreatHypothesisPage,
    operation_id="list_threat_hypotheses",
)
def list_hypotheses(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    runtime_scope: RuntimeJobScopeDependency,
    hypothesis_status: HypothesisStatus | None = None,
    severity: Severity | None = None,
) -> ThreatHypothesisPage:
    with database.session() as session:
        items, total = ApiReadRepository(session).list_hypotheses(
            limit=pagination.limit,
            offset=pagination.offset,
            status=hypothesis_status,
            severity=severity,
            runtime_scope=runtime_scope,
        )
    return ThreatHypothesisPage(
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
    "/hypotheses/{hypothesis_id}",
    response_model=HypothesisDetail,
    operation_id="get_threat_hypothesis",
)
def get_hypothesis(
    hypothesis_id: UUID,
    database: DatabaseDependency,
) -> HypothesisDetail:
    with database.session() as session:
        hypothesis = ThreatHypothesisRepository(session).get(hypothesis_id)
        if hypothesis is None:
            not_found("threat hypothesis")
        case_id = ApiReadRepository(session).hypothesis_case_id(hypothesis_id)
    return HypothesisDetail(hypothesis=hypothesis, case_id=case_id)


@router.patch(
    "/hypotheses/{hypothesis_id}",
    response_model=ThreatHypothesis,
    operation_id="update_threat_hypothesis_status",
)
def update_hypothesis(
    hypothesis_id: UUID,
    payload: HypothesisStatusRequest,
    database: DatabaseDependency,
) -> ThreatHypothesis:
    with database.session() as session, session.begin():
        repository = ThreatHypothesisRepository(session, AuditLogRepository(session))
        return repository.update_status(
            hypothesis_id,
            payload.status,
            actor=payload.actor,
            changed_at=utc_now(),
        )


@router.post(
    "/hypotheses/{hypothesis_id}/create-case",
    response_model=InvestigationCase,
    operation_id="create_case_from_hypothesis",
)
def create_case_from_hypothesis(
    hypothesis_id: UUID,
    payload: CreateCaseFromHypothesisRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> InvestigationCase:
    with database.session() as session, session.begin():
        return InvestigationCaseService(
            session,
            load_case_feedback_policy(settings.case_feedback.policy_path),
        ).create_from_hypothesis(hypothesis_id, actor=payload.actor)
