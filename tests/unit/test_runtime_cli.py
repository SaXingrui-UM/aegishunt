"""Phase 11 CLI discovery and safe operator output."""

from __future__ import annotations

import json
import signal
from collections.abc import Callable
from pathlib import Path

import pytest
from typer.testing import CliRunner

from aegishunt.cli import app
from aegishunt.config import DatabaseSettings
from aegishunt.runtime import cli as runtime_cli
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.schemas import TelemetrySource
from aegishunt.schemas.enums import IngestionMode, LifecycleStatus, SourceType
from aegishunt.storage import Database
from aegishunt.storage.repositories import TelemetrySourceRepository
from tests.fixtures.runtime import SOURCE_ID, runtime_job

PROJECT_ROOT = Path(__file__).parents[2]
runner = CliRunner()


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "application.yaml"
    path.write_text(
        "\n".join(
            (
                "database:",
                f"  url: sqlite:///{tmp_path / 'runtime-cli.sqlite3'}",
                "runtime:",
                f"  policy_path: {PROJECT_ROOT / 'configs' / 'runtime.yaml'}",
                f"  fusion_policy_root: {tmp_path / 'fusion'}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return path


def test_runtime_cli_help_discovers_lifecycle_commands() -> None:
    result = runner.invoke(app, ["runtime", "--help"])

    assert result.exit_code == 0
    for command in ("config", "replay", "jobs", "worker", "workers", "status"):
        assert command in result.stdout
    assert "live-capture" in result.stdout


def test_runtime_config_verify_and_live_capture_disabled() -> None:
    verified = runner.invoke(app, ["runtime", "config", "verify"])
    disabled = runner.invoke(app, ["runtime", "live-capture"])

    assert verified.exit_code == 0
    verify_payload = json.loads(verified.stdout)
    assert verify_payload["execution_mode"] == "single_node_sqlite"
    assert verify_payload["automatic_recovery"] is False
    assert verify_payload["live_capture_enabled"] is False
    assert disabled.exit_code == 0
    disabled_payload = json.loads(disabled.stdout)
    assert disabled_payload["status"] == "disabled"
    assert disabled_payload["live_capture_enabled"] is False


def test_runtime_status_and_empty_lists_are_machine_readable(tmp_path: Path) -> None:
    config = _config(tmp_path)
    status = runner.invoke(app, ["runtime", "status", "--config", str(config)])
    jobs = runner.invoke(
        app,
        ["runtime", "jobs", "list", "--config", str(config)],
    )
    workers = runner.invoke(
        app,
        ["runtime", "workers", "list", "--config", str(config)],
    )

    assert status.exit_code == jobs.exit_code == workers.exit_code == 0
    status_payload = json.loads(status.stdout)
    assert status_payload["queue_length"] == 0
    assert status_payload["model_loading_state"] == "verified_per_job_preflight"
    assert status_payload["automatic_recovery"] is False
    assert (
        status_payload["observed_progress_semantics"]
        == "non_durable_live_observation"
    )
    assert status_payload["durable_progress_semantics"] == "durable_committed_evidence"
    assert status_payload["recovery_strategy"] == "deterministic_restart_from_origin"
    assert json.loads(jobs.stdout) == {"items": [], "total": 0}
    assert json.loads(workers.stdout) == []


def test_runtime_job_describe_exposes_separate_progress_contract(tmp_path: Path) -> None:
    config = _config(tmp_path)
    database = Database(
        DatabaseSettings(url=f"sqlite:///{tmp_path / 'runtime-cli.sqlite3'}")
    )
    assert database.initialize() == 5
    job = runtime_job()
    try:
        with database.session() as session, session.begin():
            TelemetrySourceRepository(session).add(
                TelemetrySource(
                    source_id=SOURCE_ID,
                    source_type=SourceType.PCAP,
                    filename_or_interface="runtime-cli.pcap",
                    ingestion_mode=IngestionMode.IMPORT,
                    status=LifecycleStatus.COMPLETED,
                )
            )
            RuntimeJobRepository(session).add(job, actor="test")

        result = runner.invoke(
            app,
            [
                "runtime",
                "jobs",
                "describe",
                str(job.job_id),
                "--config",
                str(config),
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["job"]["progress_semantics"] == "durable_committed_evidence"
        assert (
            payload["job"]["observed_progress_semantics"]
            == "non_durable_live_observation"
        )
        assert payload["progress_contract"] == {
            "durable": "durable_committed_evidence",
            "exact_cursor_resume": False,
            "observed": "non_durable_live_observation",
            "observed_is_checkpoint": False,
            "recovery_strategy": "deterministic_restart_from_origin",
        }
    finally:
        database.dispose()


def test_runtime_config_failure_is_sanitized_without_traceback(tmp_path: Path) -> None:
    policy = tmp_path / "invalid-runtime.yaml"
    policy.write_text("live_capture_enabled: true\n", encoding="utf-8")
    config = tmp_path / "invalid-application.yaml"
    config.write_text(
        "\n".join(
            (
                "runtime:",
                f"  policy_path: {policy}",
                f"  fusion_policy_root: {tmp_path / 'fusion'}",
                "",
            )
        ),
        encoding="utf-8",
    )

    result = runner.invoke(
        app,
        ["runtime", "config", "verify", "--config", str(config)],
    )

    assert result.exit_code == 1
    assert "Runtime command failed" in result.stdout
    assert "Traceback" not in result.stdout
    assert str(tmp_path) not in result.stdout


def test_runtime_worker_registers_cooperative_sigint_and_sigterm_handlers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeWorker:
        def __init__(self, *_: object, **__: object) -> None:
            self.shutdown_requests = 0
            workers.append(self)

        def request_shutdown(self) -> None:
            self.shutdown_requests += 1

        def run_one_and_stop(self) -> bool:
            return False

    handlers: dict[int, Callable[[int, object], None]] = {}
    workers: list[FakeWorker] = []

    def register(signum: int, handler: Callable[[int, object], None]) -> None:
        handlers[signum] = handler

    monkeypatch.setattr(runtime_cli, "RuntimeWorkerProcess", FakeWorker)
    monkeypatch.setattr(runtime_cli.signal, "signal", register)

    result = runner.invoke(
        app,
        [
            "runtime",
            "worker",
            "run",
            "--once",
            "--config",
            str(_config(tmp_path)),
        ],
    )

    assert result.exit_code == 0
    assert set(handlers) == {signal.SIGINT, signal.SIGTERM}
    assert len(workers) == 1
    handlers[signal.SIGINT](signal.SIGINT, None)
    handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert workers[0].shutdown_requests == 2
