"""Read-only verified evaluation catalog API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from aegishunt.api.contracts import (
    EvaluationDescriptor,
    EvaluationPage,
    EvaluationSummary,
    FusionEvaluationDiscovery,
)
from aegishunt.api.dependencies import PaginationDependency, get_database, get_settings
from aegishunt.api.errors import not_found
from aegishunt.api.evaluation_service import (
    DemoEvaluationSummaryService,
    EvaluationCatalogService,
)
from aegishunt.config import ApplicationSettings
from aegishunt.storage import Database

router = APIRouter(prefix="/evaluation", tags=["evaluation"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]


def _items(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> list[EvaluationDescriptor]:
    return EvaluationCatalogService(database, settings).list()


@router.get("", response_model=EvaluationPage, operation_id="list_evaluations")
def list_evaluations(
    database: DatabaseDependency,
    settings: SettingsDependency,
    pagination: PaginationDependency,
) -> EvaluationPage:
    all_items = _items(database, settings)
    items = all_items[pagination.offset : pagination.offset + pagination.limit]
    return EvaluationPage(
        items=items,
        total=len(all_items),
        limit=pagination.limit,
        offset=pagination.offset,
        next_offset=(
            pagination.offset + len(items)
            if pagination.offset + len(items) < len(all_items)
            else None
        ),
    )


@router.get(
    "/latest",
    response_model=list[EvaluationDescriptor],
    operation_id="get_latest_evaluations",
)
def latest_evaluations(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> list[EvaluationDescriptor]:
    """Return one latest verified/unavailable descriptor per engine."""

    latest: dict[str, EvaluationDescriptor] = {}
    for item in _items(database, settings):
        latest[item.engine] = item
    return [latest[key] for key in sorted(latest)]


@router.get(
    "/fusion-status",
    response_model=FusionEvaluationDiscovery,
    operation_id="get_fusion_evaluation_discovery",
)
def fusion_evaluation_discovery(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> FusionEvaluationDiscovery:
    """Distinguish missing artifacts from a verified inconclusive result."""

    return EvaluationCatalogService(database, settings).fusion_discovery()


@router.get(
    "/summary",
    response_model=EvaluationSummary,
    operation_id="get_evaluation_summary",
)
def evaluation_summary(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> EvaluationSummary:
    """Return a fail-closed projection of prepared controlled evidence."""

    return DemoEvaluationSummaryService(database, settings).read()


@router.get(
    "/{run_id}",
    response_model=EvaluationDescriptor,
    operation_id="get_evaluation",
)
def get_evaluation(
    run_id: str,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> EvaluationDescriptor:
    for item in _items(database, settings):
        if item.run_id == run_id:
            return item
    not_found("evaluation run")
