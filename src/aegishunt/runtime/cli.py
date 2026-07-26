"""Typer commands for the durable single-node runtime and offline PCAP replay."""

from __future__ import annotations

import json
import os
import signal
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer
from pydantic import BaseModel

from aegishunt.config import ApplicationSettings, load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.runtime.config import LoadedRuntimePolicy, load_runtime_policy
from aegishunt.runtime.contracts import RuntimeJobStatus
from aegishunt.runtime.repositories import RuntimeWorkerRepository
from aegishunt.runtime.service import RuntimeJobService
from aegishunt.runtime.status import RuntimeStatusReader
from aegishunt.runtime.worker import RuntimeWorkerProcess
from aegishunt.storage import Database

runtime_app = typer.Typer(name="runtime", help="Durable Phase 11 offline replay runtime.")
runtime_config_app = typer.Typer(name="config", help="Verify runtime policy.")
replay_app = typer.Typer(name="replay", help="Create pinned offline replay jobs.")
jobs_app = typer.Typer(name="jobs", help="Inspect and control runtime jobs.")
worker_app = typer.Typer(name="worker", help="Run one local background worker.")
workers_app = typer.Typer(name="workers", help="Inspect local worker records.")
runtime_app.add_typer(runtime_config_app)
runtime_app.add_typer(replay_app)
runtime_app.add_typer(jobs_app)
runtime_app.add_typer(worker_app)
runtime_app.add_typer(workers_app)

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", dir_okay=False, readable=True),
]


def _load(config: Path | None) -> tuple[ApplicationSettings, LoadedRuntimePolicy, Database]:
    settings = load_settings(config)
    policy = load_runtime_policy(settings.runtime.policy_path)
    database = Database(settings.database)
    database.initialize()
    return settings, policy, database


def _service(
    settings: ApplicationSettings,
    policy: LoadedRuntimePolicy,
    database: Database,
) -> RuntimeJobService:
    return RuntimeJobService(
        database,
        settings=settings,
        runtime_policy=policy,
        project_root=Path.cwd(),
    )


def _echo(value: object) -> None:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    typer.echo(json.dumps(value, indent=2, sort_keys=True))


def _fail(exc: AegisHuntError) -> None:
    typer.echo(f"Runtime command failed: {exc}", err=True)
    raise typer.Exit(code=1) from exc


@runtime_config_app.command("verify")
def verify_config(config: ConfigOption = None) -> None:
    """Verify runtime configuration without loading a model or starting a worker."""

    try:
        settings = load_settings(config)
        loaded = load_runtime_policy(settings.runtime.policy_path)
    except AegisHuntError as exc:
        _fail(exc)
    _echo(
        {
            "status": "verified",
            "policy_id": loaded.policy.policy_id,
            "policy_version": loaded.policy.policy_version,
            "configuration_checksum": loaded.configuration_checksum,
            "execution_mode": loaded.policy.execution_mode,
            "automatic_recovery": loaded.policy.automatic_recovery,
            "live_capture_enabled": loaded.policy.live_capture_enabled,
        }
    )


@replay_app.command("create")
def create_replay(
    source_id: UUID,
    speed: Annotated[float | None, typer.Option("--speed", min=0.000001)] = None,
    actor: Annotated[str, typer.Option("--actor", min=1, max=255)] = "runtime-cli",
    config: ConfigOption = None,
) -> None:
    """Create one source-ID-based replay job after complete artifact preflight."""

    database: Database | None = None
    try:
        settings, policy, database = _load(config)
        _echo(
            _service(settings, policy, database).create_replay(
                source_id,
                speed=speed,
                actor=actor,
            )
        )
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@jobs_app.command("list")
def list_jobs(
    status: Annotated[RuntimeJobStatus | None, typer.Option("--status")] = None,
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    config: ConfigOption = None,
) -> None:
    database: Database | None = None
    try:
        settings, policy, database = _load(config)
        items, total = _service(settings, policy, database).list(
            limit=limit,
            offset=offset,
            status=status,
        )
        _echo({"items": [item.model_dump(mode="json") for item in items], "total": total})
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@jobs_app.command("describe")
def describe_job(job_id: UUID, config: ConfigOption = None) -> None:
    database: Database | None = None
    try:
        settings, policy, database = _load(config)
        service = _service(settings, policy, database)
        job = service.get(job_id)
        _echo(
            {
                "job": job.model_dump(mode="json"),
                "attempts": [
                    attempt.model_dump(mode="json")
                    for attempt in service.attempts(job_id)
                ],
                "progress_contract": {
                    "observed": "non_durable_live_observation",
                    "durable": "durable_committed_evidence",
                    "recovery_strategy": "deterministic_restart_from_origin",
                    "observed_is_checkpoint": False,
                    "exact_cursor_resume": False,
                },
            }
        )
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


def _job_action(
    action: str,
    job_id: UUID,
    config: Path | None,
    *,
    actor: str,
    reason: str,
) -> None:
    database: Database | None = None
    try:
        settings, policy, database = _load(config)
        service = _service(settings, policy, database)
        _echo(getattr(service, action)(job_id, actor=actor, reason=reason))
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@jobs_app.command("pause")
def pause_job(
    job_id: UUID,
    actor: Annotated[str, typer.Option("--actor", min=1, max=255)] = "runtime-cli",
    reason: Annotated[str, typer.Option("--reason", min=1, max=512)] = (
        "operator requested pause"
    ),
    config: ConfigOption = None,
) -> None:
    _job_action("pause", job_id, config, actor=actor, reason=reason)


@jobs_app.command("resume")
def resume_job(
    job_id: UUID,
    actor: Annotated[str, typer.Option("--actor", min=1, max=255)] = "runtime-cli",
    reason: Annotated[str, typer.Option("--reason", min=1, max=512)] = (
        "operator requested resume"
    ),
    config: ConfigOption = None,
) -> None:
    _job_action("resume", job_id, config, actor=actor, reason=reason)


@jobs_app.command("recover")
def recover_job(
    job_id: UUID,
    actor: Annotated[str, typer.Option("--actor", min=1, max=255)] = "runtime-cli",
    reason: Annotated[str, typer.Option("--reason", min=1, max=512)] = (
        "operator requested explicit origin recovery"
    ),
    config: ConfigOption = None,
) -> None:
    """Explicitly queue a deterministic restart from packet zero."""

    _job_action("recover", job_id, config, actor=actor, reason=reason)


@worker_app.command("run")
def run_worker(
    once: Annotated[bool, typer.Option("--once/--forever")] = False,
    worker_id: Annotated[str | None, typer.Option("--worker-id")] = None,
    config: ConfigOption = None,
) -> None:
    database: Database | None = None
    try:
        settings, policy, database = _load(config)
        selected_id = worker_id or f"local-worker-{os.getpid()}"
        worker = RuntimeWorkerProcess(
            database,
            settings=settings,
            runtime_policy=policy,
            project_root=Path.cwd(),
            worker_id=selected_id,
        )

        def request_shutdown(signum: int, frame: object) -> None:
            del signum, frame
            worker.request_shutdown()

        signal.signal(signal.SIGINT, request_shutdown)
        signal.signal(signal.SIGTERM, request_shutdown)
        claimed = worker.run_one_and_stop() if once else None
        if once:
            _echo({"status": "stopped", "worker_id": selected_id, "job_claimed": claimed})
        else:
            worker.run_forever()
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@workers_app.command("list")
def list_workers(
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    config: ConfigOption = None,
) -> None:
    database: Database | None = None
    try:
        _settings, policy, database = _load(config)
        if limit > policy.policy.worker.maximum_workers_per_query:
            raise typer.BadParameter("worker query exceeds the configured limit")
        with database.session() as session:
            workers = RuntimeWorkerRepository(session).list(limit=limit, offset=offset)
        _echo([worker.model_dump(mode="json") for worker in workers])
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@workers_app.command("describe")
def describe_worker(worker_id: str, config: ConfigOption = None) -> None:
    database: Database | None = None
    try:
        _settings, _policy, database = _load(config)
        with database.session() as session:
            worker = RuntimeWorkerRepository(session).get(worker_id)
        if worker is None:
            raise typer.BadParameter("runtime worker does not exist")
        _echo(worker)
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@runtime_app.command("status")
def runtime_status(config: ConfigOption = None) -> None:
    database: Database | None = None
    try:
        _settings, _policy, database = _load(config)
        _echo(RuntimeStatusReader(database).read())
    except AegisHuntError as exc:
        _fail(exc)
    finally:
        if database is not None:
            database.dispose()


@runtime_app.command("live-capture")
def live_capture_status() -> None:
    """Report the explicit Phase 11 safe-disabled live capture state."""

    _echo(
        {
            "status": "disabled",
            "live_capture_enabled": False,
            "reason": "offline PCAP replay is the supported rootless runtime path",
        }
    )
