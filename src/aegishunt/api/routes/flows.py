"""Bounded NetworkFlow query API."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from aegishunt.api.contracts import FlowSummary, NetworkFlowPage
from aegishunt.api.dependencies import (
    PaginationDependency,
    RuntimeJobScopeDependency,
    get_database,
)
from aegishunt.api.errors import not_found
from aegishunt.api.repository import ApiReadRepository
from aegishunt.schemas import NetworkFlow
from aegishunt.schemas.enums import NetworkProtocol
from aegishunt.storage import Database
from aegishunt.storage.repositories import NetworkFlowRepository

router = APIRouter(prefix="/flows", tags=["flows"])
DatabaseDependency = Annotated[Database, Depends(get_database)]


@router.get("", response_model=NetworkFlowPage, operation_id="list_network_flows")
def list_flows(
    database: DatabaseDependency,
    pagination: PaginationDependency,
    runtime_scope: RuntimeJobScopeDependency,
    source_id: UUID | None = None,
    capture_session_id: str | None = None,
    protocol: NetworkProtocol | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
    supervised_label: str | None = None,
    alert_present: bool | None = None,
    minimum_risk: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
    minimum_anomaly_score: Annotated[float | None, Query(ge=0.0, le=1.0)] = None,
) -> NetworkFlowPage:
    """Filter runtime flows without exposing ground-truth labels by default."""

    with database.session() as session:
        items, total = ApiReadRepository(session).list_flows(
            limit=pagination.limit,
            offset=pagination.offset,
            source_id=source_id,
            capture_session_id=capture_session_id,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            time_from=time_from,
            time_to=time_to,
            supervised_label=supervised_label,
            alert_present=alert_present,
            minimum_risk=minimum_risk,
            minimum_anomaly_score=minimum_anomaly_score,
            runtime_scope=runtime_scope,
        )
    return NetworkFlowPage(
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


@router.get("/summary", response_model=FlowSummary, operation_id="summarize_network_flows")
def summarize_flows(
    database: DatabaseDependency,
    runtime_scope: RuntimeJobScopeDependency,
    source_id: UUID | None = None,
) -> FlowSummary:
    """Return bounded SQL aggregations for the Traffic Explorer."""

    with database.session() as session:
        return ApiReadRepository(session).flow_summary(
            source_id=source_id,
            runtime_scope=runtime_scope,
        )


@router.get("/{flow_id}", response_model=NetworkFlow, operation_id="get_network_flow")
def get_flow(flow_id: UUID, database: DatabaseDependency) -> NetworkFlow:
    with database.session() as session:
        flow = NetworkFlowRepository(session).get(flow_id)
    if flow is None:
        not_found("network flow")
    return flow
