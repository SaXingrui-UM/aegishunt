"""SecurityAlert query and verdict API."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from aegishunt.api.contracts import (
    AlertDetail,
    AlertVerdictRequest,
    DetectionDetail,
    DetectionResultPage,
    SecurityAlertPage,
)
from aegishunt.api.dependencies import PaginationDependency, get_database
from aegishunt.api.errors import not_found
from aegishunt.api.repository import ApiReadRepository
from aegishunt.schemas import SecurityAlert
from aegishunt.schemas.enums import AlertStatus, AnalystVerdict, Severity
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    SecurityAlertRepository,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])
detections_router = APIRouter(prefix="/detections", tags=["detections"])
DatabaseDependency = Annotated[Database, Depends(get_database)]


@detections_router.get(
    "",
    response_model=DetectionResultPage,
    operation_id="list_detection_results",
)
def list_detections(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    supervised_label: str | None = None,
    minimum_risk: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    minimum_anomaly_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> DetectionResultPage:
    with database.session() as session:
        items, total = ApiReadRepository(session).list_detections(
            limit=pagination.limit,
            offset=pagination.offset,
            supervised_label=supervised_label,
            minimum_risk=minimum_risk,
            minimum_anomaly_score=minimum_anomaly_score,
        )
    return DetectionResultPage(
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


@detections_router.get(
    "/{detection_id}",
    response_model=DetectionDetail,
    operation_id="get_detection_result",
)
def get_detection(detection_id: UUID, database: DatabaseDependency) -> DetectionDetail:
    with database.session() as session:
        detection = DetectionResultRepository(session).get(detection_id)
        if detection is None:
            not_found("detection result")
        alert = SecurityAlertRepository(session).get_by_detection(detection_id)
    return DetectionDetail(
        detection=detection,
        alert_id=None if alert is None else alert.alert_id,
    )


@router.get("", response_model=SecurityAlertPage, operation_id="list_security_alerts")
def list_alerts(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    severity: Severity | None = None,
    alert_status: AlertStatus | None = None,
    analyst_verdict: AnalystVerdict | None = None,
    minimum_risk: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> SecurityAlertPage:
    with database.session() as session:
        items, total = ApiReadRepository(session).list_alerts(
            limit=pagination.limit,
            offset=pagination.offset,
            severity=severity,
            status=alert_status,
            analyst_verdict=analyst_verdict,
            minimum_risk=minimum_risk,
        )
    return SecurityAlertPage(
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


@router.get("/{alert_id}", response_model=AlertDetail, operation_id="get_security_alert")
def get_alert(alert_id: UUID, database: DatabaseDependency) -> AlertDetail:
    with database.session() as session:
        alert = SecurityAlertRepository(session).get(alert_id)
        if alert is None:
            not_found("security alert")
        groups, hypotheses = ApiReadRepository(session).alert_relations(alert_id)
    return AlertDetail(
        alert=alert,
        related_group_ids=groups,
        related_hypothesis_ids=hypotheses,
    )


@router.patch(
    "/{alert_id}",
    response_model=SecurityAlert,
    operation_id="update_security_alert_verdict",
)
def update_alert(
    alert_id: UUID,
    payload: AlertVerdictRequest,
    database: DatabaseDependency,
) -> SecurityAlert:
    """Update only the human verdict; detection evidence is immutable."""

    with database.session() as session, session.begin():
        repository = SecurityAlertRepository(session, AuditLogRepository(session))
        return repository.update_verdict(
            alert_id,
            payload.analyst_verdict,
            actor=payload.actor,
            reason=payload.reason,
            source="phase12_api",
        )
