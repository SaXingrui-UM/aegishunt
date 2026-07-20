"""Deterministic configuration-only severity mapping."""

from __future__ import annotations

import math

from aegishunt.detection.contracts import SeverityBand
from aegishunt.detection.errors import DetectionContractError
from aegishunt.schemas.enums import Severity


def map_severity(score: float, bands: tuple[SeverityBand, ...]) -> Severity:
    """Map a bounded score using inclusive lower boundaries."""

    if isinstance(score, bool) or not math.isfinite(score) or not 0.0 <= score <= 1.0:
        raise DetectionContractError("severity input must be finite and inside zero and one")
    if not bands:
        raise DetectionContractError("severity policy cannot be empty")
    selected = bands[0].severity
    for band in bands:
        if score < band.minimum_score:
            break
        selected = band.severity
    return selected
