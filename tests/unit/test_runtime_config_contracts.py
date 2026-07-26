"""Phase 11 runtime policy and durable-contract validation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aegishunt.runtime.config import RuntimePolicy, load_runtime_policy
from aegishunt.runtime.contracts import (
    RuntimeArtifactIdentity,
    RuntimeAttempt,
    RuntimeAttemptStatus,
    RuntimeJob,
    RuntimeJobStatus,
    RuntimePipelineSnapshot,
    RuntimeProgressMode,
    RuntimeResourceSample,
)
from aegishunt.runtime.errors import RuntimeConfigurationError
from tests.fixtures.runtime import NOW, runtime_job, runtime_snapshot

PROJECT_ROOT = Path(__file__).parents[2]
POLICY_PATH = PROJECT_ROOT / "configs" / "runtime.yaml"


def test_runtime_policy_loads_with_fail_closed_single_node_defaults() -> None:
    loaded = load_runtime_policy(POLICY_PATH)

    assert loaded.policy.execution_mode == "single_node_sqlite"
    assert loaded.policy.recovery_strategy == "deterministic_restart_from_origin"
    assert loaded.policy.automatic_recovery is False
    assert loaded.policy.live_capture_enabled is False
    assert loaded.policy.worker.maximum_attempts == 3
    assert loaded.policy.worker.maximum_jobs_per_query == 100
    assert loaded.policy.pipeline_stages[-1] == "completion"
    assert (
        loaded.policy.output_identity_policy
        == "deterministic_domain_ids_with_verified_runtime_ledger"
    )
    assert len(loaded.configuration_checksum) == 64


@pytest.mark.parametrize(
    ("path_mutation", "message"),
    (
        (lambda payload: payload.update({"automatic_recovery": True}), "invalid"),
        (
            lambda payload: payload["worker"].update(
                {"heartbeat_interval_seconds": payload["worker"]["lease_seconds"]}
            ),
            "invalid",
        ),
        (
            lambda payload: payload["replay"].update(
                {"default_speed": payload["replay"]["maximum_speed"] + 1}
            ),
            "invalid",
        ),
        (
            lambda payload: payload["worker"].update({"maximum_attempts": 0}),
            "invalid",
        ),
        (
            lambda payload: payload["worker"].update(
                {"maximum_jobs_per_query": 1001}
            ),
            "invalid",
        ),
        (
            lambda payload: payload.pop("pipeline_stages"),
            "invalid",
        ),
        (lambda payload: payload.update({"unexpected": "field"}), "invalid"),
    ),
)
def test_runtime_policy_rejects_unsafe_or_inconsistent_values(
    tmp_path: Path,
    path_mutation: object,
    message: str,
) -> None:
    payload = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    path_mutation(payload)  # type: ignore[operator]
    path = tmp_path / "runtime.yaml"
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    with pytest.raises(RuntimeConfigurationError, match=message):
        load_runtime_policy(path)


def test_runtime_policy_refuses_symlink(tmp_path: Path) -> None:
    link = tmp_path / "runtime.yaml"
    link.symlink_to(POLICY_PATH)

    with pytest.raises(RuntimeConfigurationError, match="regular file"):
        load_runtime_policy(link)


def test_snapshot_requires_exact_component_inventory_and_safe_filename() -> None:
    snapshot = runtime_snapshot()
    assert len(snapshot.artifacts) == 7
    assert snapshot.database_schema_version == 5

    with pytest.raises(ValidationError, match="logical"):
        runtime_snapshot(stored_filename="../../outside.pcap")
    with pytest.raises(ValidationError, match="one exact identity"):
        RuntimePipelineSnapshot.model_validate(
            {
                **snapshot.model_dump(mode="python"),
                "artifacts": snapshot.artifacts[:-1]
                + (
                    RuntimeArtifactIdentity(
                        artifact_type="supervised_model",
                        artifact_id="duplicate",
                        version="1.0.0",
                        checksum="0" * 64,
                    ),
                ),
            }
        )


def test_runtime_job_requires_complete_lease_identity_for_claimed_states() -> None:
    job = runtime_job()
    assert job.capture_session_id == job.snapshot.capture_session_id
    assert job.snapshot_checksum
    assert job.runtime_policy_checksum == job.snapshot.runtime_policy_checksum

    with pytest.raises(ValidationError, match="complete lease"):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                "status": RuntimeJobStatus.RUNNING,
                "claimed_by": "worker-a",
            }
        )

    with pytest.raises(ValidationError, match="verified total"):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                "progress_mode": RuntimeProgressMode.PACKET_COUNT,
                "progress_total": None,
            }
        )
    with pytest.raises(ValidationError, match="snapshot checksum"):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                "snapshot_checksum": "0" * 64,
            }
        )
    with pytest.raises(ValidationError, match="cannot retain"):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                "claimed_by": "worker-a",
            }
        )


def test_unavailable_resource_measurements_are_null_not_zero() -> None:
    sample = RuntimeResourceSample(
        worker_id="worker-a",
        sampled_at=NOW,
        sampler_available=False,
        monitoring_status="unavailable",
        error_code="resource_sampler_unavailable",
    )
    assert sample.process_cpu_percent is None
    assert sample.process_rss_bytes is None
    assert sample.system_memory_percent is None

    with pytest.raises(ValidationError, match="null measurements"):
        RuntimeResourceSample(
            worker_id="worker-a",
            sampled_at=NOW,
            sampler_available=False,
            monitoring_status="unavailable",
            process_cpu_percent=0.0,
        )


def test_runtime_contract_forbids_non_finite_numbers() -> None:
    payload = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    payload["replay"]["default_speed"] = float("nan")

    with pytest.raises(ValidationError):
        RuntimePolicy.model_validate(payload)


@pytest.mark.parametrize("value", (float("nan"), float("inf"), float("-inf")))
@pytest.mark.parametrize("field", ("progress", "observed_progress"))
def test_runtime_contract_rejects_non_finite_progress(
    field: str,
    value: float,
) -> None:
    job = runtime_job()

    with pytest.raises(ValidationError):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                field: value,
            }
        )


def test_runtime_progress_contract_enforces_totals_and_completion_gate() -> None:
    job = runtime_job()
    packet_progress = {
        **job.model_dump(mode="python"),
        "progress_mode": RuntimeProgressMode.PACKET_COUNT,
        "progress_total": 2,
        "observed_progress_total": 2,
    }

    with pytest.raises(ValidationError, match="cannot exceed"):
        RuntimeJob.model_validate({**packet_progress, "progress_current": 3})
    with pytest.raises(ValidationError, match="cannot exceed"):
        RuntimeJob.model_validate({**packet_progress, "observed_progress_current": 3})
    with pytest.raises(ValidationError, match="only completed"):
        RuntimeJob.model_validate({**job.model_dump(mode="python"), "progress": 1.0})
    with pytest.raises(ValidationError, match="require complete progress"):
        RuntimeJob.model_validate(
            {
                **job.model_dump(mode="python"),
                "status": RuntimeJobStatus.COMPLETED,
                "completed_at": NOW,
            }
        )

    attempt = RuntimeAttempt(
        job_id=job.job_id,
        worker_id="worker-a",
        attempt_number=1,
        started_at=NOW,
        updated_at=NOW,
    )
    with pytest.raises(ValidationError, match="only completed"):
        RuntimeAttempt.model_validate(
            {
                **attempt.model_dump(mode="python"),
                "progress": 1.0,
            }
        )
    with pytest.raises(ValidationError, match="require complete progress"):
        RuntimeAttempt.model_validate(
            {
                **attempt.model_dump(mode="python"),
                "status": RuntimeAttemptStatus.COMPLETED,
            }
        )
