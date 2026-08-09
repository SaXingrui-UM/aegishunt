"""Verified model registry and explicit controlled mutation routes."""

from __future__ import annotations

from typing import Annotated, Literal

from fastapi import APIRouter, Depends

from aegishunt.api.contracts import (
    EffectiveModelState,
    ModelActivateRequest,
    ModelDescriptor,
    ModelImportance,
    ModelPage,
    ModelTrainRequest,
)
from aegishunt.api.dependencies import PaginationDependency, get_database, get_settings
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.api.runtime_model_service import EffectiveRuntimeModelService
from aegishunt.config import ApplicationSettings
from aegishunt.storage import Database

router = APIRouter(prefix="/models", tags=["models"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]


def _service(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ModelRegistryService:
    return ModelRegistryService(database, settings)


@router.get("", response_model=ModelPage, operation_id="list_models")
def list_models(
    database: DatabaseDependency,
    settings: SettingsDependency,
    pagination: PaginationDependency,
) -> ModelPage:
    all_items = _service(database, settings).list_models()
    items = all_items[pagination.offset : pagination.offset + pagination.limit]
    return ModelPage(
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


@router.get("/active", response_model=list[ModelDescriptor], operation_id="list_active_models")
def list_active_models(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> list[ModelDescriptor]:
    return _service(database, settings).active()


@router.get(
    "/effective",
    response_model=EffectiveModelState,
    operation_id="get_effective_runtime_models",
)
def get_effective_runtime_models(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> EffectiveModelState:
    """Separate immutable job-pinned artifacts from global active pointers."""

    return EffectiveRuntimeModelService(database, settings).read()


@router.get(
    "/{model_id}/importance",
    response_model=ModelImportance,
    operation_id="get_model_importance",
)
def get_model_importance(
    model_id: str,
    database: DatabaseDependency,
    settings: SettingsDependency,
    kind: Literal["native", "permutation"] = "native",
) -> ModelImportance:
    return _service(database, settings).importance(model_id, kind=kind)


@router.post("/train", response_model=ModelDescriptor, operation_id="train_controlled_model")
def train_model(
    payload: ModelTrainRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ModelDescriptor:
    return _service(database, settings).train(payload)


@router.get("/{model_id}", response_model=ModelDescriptor, operation_id="get_model")
def get_model(
    model_id: str,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ModelDescriptor:
    return _service(database, settings).get(model_id)


@router.post(
    "/{model_id}/activate",
    response_model=ModelDescriptor,
    operation_id="activate_verified_model",
)
def activate_model(
    model_id: str,
    payload: ModelActivateRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> ModelDescriptor:
    return _service(database, settings).activate(
        model_id,
        actor=payload.actor,
        reason=payload.reason,
        expected_active_version=payload.expected_active_version,
    )
