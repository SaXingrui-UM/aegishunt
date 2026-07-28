"""Deterministic replay pacing and resource-sampler behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.errors import RuntimeReplayError
from aegishunt.runtime.replay import ReplayPacer
from aegishunt.runtime.resources import ProcessResourceSampler

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)


def test_replay_uses_event_delta_speed_gap_cap_and_out_of_order_semantics() -> None:
    pacer = ReplayPacer(
        speed=2.0,
        maximum_sleep_seconds=3.0,
        sleep_quantum_seconds=0.5,
        clock=RuntimeClock(),
    )

    assert pacer.delay_for(NOW).delay_seconds == 0.0
    normal = pacer.delay_for(NOW + timedelta(seconds=4))
    assert normal.delay_seconds == 2.0
    assert normal.out_of_order is False
    assert normal.capped_gap is False
    capped = pacer.delay_for(NOW + timedelta(seconds=100))
    assert capped.delay_seconds == 3.0
    assert capped.capped_gap is True
    out_of_order = pacer.delay_for(NOW + timedelta(seconds=50))
    assert out_of_order.delay_seconds == 0.0
    assert out_of_order.out_of_order is True


def test_replay_sleep_is_quantized_and_interruptible() -> None:
    sleeps: list[float] = []
    quanta: list[None] = []
    pacer = ReplayPacer(
        speed=1.0,
        maximum_sleep_seconds=5.0,
        sleep_quantum_seconds=0.4,
        clock=RuntimeClock(sleep=sleeps.append),
    )
    first = pacer.delay_for(NOW)
    delay = pacer.delay_for(NOW + timedelta(seconds=1))
    assert pacer.sleep(
        first,
        should_stop=lambda: False,
        on_quantum=lambda: quanta.append(None),
    )
    assert pacer.sleep(
        delay,
        should_stop=lambda: False,
        on_quantum=lambda: quanta.append(None),
    )
    assert sleeps == pytest.approx([0.4, 0.4, 0.2])
    assert len(quanta) == 3

    stop = iter((False, True))
    assert (
        pacer.sleep(
            delay,
            should_stop=lambda: next(stop),
            on_quantum=lambda: None,
        )
        is False
    )


@pytest.mark.parametrize("speed", (0.0, -1.0, float("nan"), float("inf")))
def test_replay_refuses_non_finite_or_non_positive_speed(speed: float) -> None:
    with pytest.raises(RuntimeReplayError, match="finite and positive"):
        ReplayPacer(
            speed=speed,
            maximum_sleep_seconds=5.0,
            sleep_quantum_seconds=0.1,
            clock=RuntimeClock(),
        )


class _Memory:
    rss = 2_048


class _Process:
    def cpu_percent(self, *, interval: None) -> float:
        assert interval is None
        return 12.5

    def memory_info(self) -> _Memory:
        return _Memory()

    def memory_percent(self) -> float:
        return 25.0

    def num_threads(self) -> int:
        return 3


def test_resource_sampler_records_measurements_or_explicit_unavailable() -> None:
    instances: list[_Process] = []

    def process_factory() -> _Process:
        process = _Process()
        instances.append(process)
        return process

    sampler = ProcessResourceSampler(process_factory)
    available = sampler.sample(
        worker_id="worker-a",
        job_id=None,
    )
    repeated = sampler.sample(worker_id="worker-a", job_id=None)
    assert available.sampler_available is True
    assert available.process_cpu_percent == 12.5
    assert available.process_rss_bytes == 2_048
    assert available.system_memory_percent == 25.0
    assert available.thread_count == 3
    assert available.monitoring_status == "available"
    assert repeated.process_cpu_percent == 12.5
    assert len(instances) == 1

    unavailable = ProcessResourceSampler(
        lambda: (_ for _ in ()).throw(OSError("unavailable"))
    ).sample(worker_id="worker-a", job_id=None)
    assert unavailable.sampler_available is False
    assert unavailable.process_cpu_percent is None
    assert unavailable.error_code == "resource_sampler_unavailable"
    assert unavailable.monitoring_status == "unavailable"
