"""Bounded process-resource sampling with explicit unavailable semantics."""

from __future__ import annotations

from collections.abc import Callable
from typing import Literal
from uuid import UUID

import psutil

from aegishunt.runtime.contracts import RuntimeResourceSample
from aegishunt.schemas.base import utc_now


class ProcessResourceSampler:
    """Sample only this worker process; failures never fabricate zero usage."""

    def __init__(self, process_factory: Callable[[], object] | None = None) -> None:
        self._process_factory = process_factory
        self._process: object | None = None

    def _process_instance(self) -> object:
        if self._process is None:
            self._process = (
                self._process_factory()
                if self._process_factory is not None
                else psutil.Process()
            )
        return self._process

    def sample(
        self,
        *,
        worker_id: str,
        job_id: UUID | None,
        queue_length: int = 0,
        active_job_count: int = 0,
        worker_heartbeat_age_seconds: float | None = None,
        model_load_state: Literal[
            "not_loaded", "verified_per_job_preflight"
        ] = "not_loaded",
    ) -> RuntimeResourceSample:
        try:
            process = self._process_instance()
            if self._process_factory is not None:
                memory_percent = None
            else:
                memory_percent = float(psutil.virtual_memory().percent)
            cpu_percent = float(process.cpu_percent(interval=None))  # type: ignore[attr-defined]
            rss_bytes = int(process.memory_info().rss)  # type: ignore[attr-defined]
            thread_count = int(process.num_threads())  # type: ignore[attr-defined]
            if memory_percent is None:
                memory_percent = float(process.memory_percent())  # type: ignore[attr-defined]
            return RuntimeResourceSample(
                worker_id=worker_id,
                job_id=job_id,
                sampled_at=utc_now(),
                process_cpu_percent=cpu_percent,
                process_rss_bytes=rss_bytes,
                system_memory_percent=memory_percent,
                thread_count=thread_count,
                queue_length=queue_length,
                active_job_count=active_job_count,
                worker_heartbeat_age_seconds=worker_heartbeat_age_seconds,
                model_load_state=model_load_state,
                sampler_available=True,
                monitoring_status="available",
            )
        except (AttributeError, OSError, RuntimeError, ValueError):
            return RuntimeResourceSample(
                worker_id=worker_id,
                job_id=job_id,
                sampled_at=utc_now(),
                queue_length=queue_length,
                active_job_count=active_job_count,
                worker_heartbeat_age_seconds=worker_heartbeat_age_seconds,
                model_load_state=model_load_state,
                sampler_available=False,
                monitoring_status="unavailable",
                error_code="resource_sampler_unavailable",
            )
