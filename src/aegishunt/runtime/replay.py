"""Deterministic event-time replay pacing with cooperative interruption."""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from aegishunt.runtime.clock import RuntimeClock
from aegishunt.runtime.errors import RuntimeReplayError


@dataclass(frozen=True, slots=True)
class ReplayDelay:
    delay_seconds: float
    out_of_order: bool
    capped_gap: bool


class ReplayPacer:
    """Convert packet event deltas into bounded wall-clock sleeps."""

    def __init__(
        self,
        *,
        speed: float,
        maximum_sleep_seconds: float,
        sleep_quantum_seconds: float,
        clock: RuntimeClock,
    ) -> None:
        if not math.isfinite(speed) or speed <= 0.0:
            raise RuntimeReplayError("replay speed must be finite and positive")
        if (
            not math.isfinite(maximum_sleep_seconds)
            or maximum_sleep_seconds <= 0.0
            or not math.isfinite(sleep_quantum_seconds)
            or sleep_quantum_seconds <= 0.0
            or sleep_quantum_seconds > maximum_sleep_seconds
        ):
            raise RuntimeReplayError("replay timing bounds are invalid")
        self._speed = speed
        self._maximum_sleep = maximum_sleep_seconds
        self._quantum = sleep_quantum_seconds
        self._clock = clock
        self._previous_timestamp: datetime | None = None

    def delay_for(self, timestamp: datetime) -> ReplayDelay:
        previous = self._previous_timestamp
        self._previous_timestamp = timestamp
        if previous is None:
            return ReplayDelay(0.0, False, False)
        event_delta = (timestamp - previous).total_seconds()
        out_of_order = event_delta < 0.0
        requested = max(0.0, event_delta) / self._speed
        capped = requested > self._maximum_sleep
        return ReplayDelay(min(requested, self._maximum_sleep), out_of_order, capped)

    def sleep(
        self,
        delay: ReplayDelay,
        *,
        should_stop: Callable[[], bool],
        on_quantum: Callable[[], None],
    ) -> bool:
        """Sleep in short quanta; return False when shutdown was requested."""

        remaining = delay.delay_seconds
        while remaining > 0.0:
            if should_stop():
                return False
            quantum = min(remaining, self._quantum)
            self._clock.sleep(quantum)
            remaining -= quantum
            on_quantum()
        return not should_stop()
