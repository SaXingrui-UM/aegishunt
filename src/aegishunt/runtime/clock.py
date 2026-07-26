"""Injectable replay and lifecycle clocks."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from aegishunt.schemas.base import utc_now


@dataclass(frozen=True, slots=True)
class RuntimeClock:
    """Wall clock, monotonic clock, and sleeper grouped for deterministic tests."""

    now: Callable[[], datetime] = utc_now
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
