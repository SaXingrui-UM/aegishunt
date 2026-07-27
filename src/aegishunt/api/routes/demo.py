"""Explicit controlled sample-demo API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends

from aegishunt.api.contracts import DemoRequest, DemoResult, DemoStatus
from aegishunt.api.demo_service import SampleDemoService
from aegishunt.api.dependencies import get_database, get_settings
from aegishunt.config import ApplicationSettings
from aegishunt.storage import Database

router = APIRouter(prefix="/demo", tags=["demo"])
DatabaseDependency = Annotated[Database, Depends(get_database)]
SettingsDependency = Annotated[ApplicationSettings, Depends(get_settings)]


@router.get("/status", response_model=DemoStatus, operation_id="get_demo_status")
def demo_status(
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> DemoStatus:
    return SampleDemoService(database, settings).status()


@router.post("/sample", response_model=DemoResult, operation_id="run_sample_demo")
def run_sample_demo(
    payload: DemoRequest,
    database: DatabaseDependency,
    settings: SettingsDependency,
) -> DemoResult:
    return SampleDemoService(database, settings).run(payload)
