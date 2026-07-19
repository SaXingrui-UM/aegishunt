"""Strict schema validation and anomaly-only scoring results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from aegishunt.ml.anomaly.bundle import LoadedAnomalyModel
from aegishunt.ml.anomaly.contracts import AnomalyPredictionResult
from aegishunt.ml.anomaly.errors import AnomalyPredictionError
from aegishunt.ml.anomaly.normalization import normalize_scores
from aegishunt.ml.anomaly.scoring import score_pipeline


class AnomalyPredictionBatch(BaseModel):
    """Immutable ordered features; extra metadata and labels are rejected."""

    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)

    feature_schema_version: str
    feature_names: tuple[str, ...]
    dtype: Literal["float64"]
    rows: tuple[tuple[float, ...], ...]

    @field_validator("rows")
    @classmethod
    def validate_rows(cls, rows: tuple[tuple[float, ...], ...]) -> tuple[tuple[float, ...], ...]:
        if not rows:
            raise ValueError("anomaly prediction batch cannot be empty")
        values = np.asarray(rows, dtype=np.float64)
        if values.ndim != 2 or not np.isfinite(values).all():
            raise ValueError("anomaly prediction rows must form a finite matrix")
        return rows

    @model_validator(mode="after")
    def validate_width(self) -> AnomalyPredictionBatch:
        if not self.feature_names or any(len(row) != len(self.feature_names) for row in self.rows):
            raise ValueError("anomaly prediction rows must match the feature width")
        return self

    def matrix(self) -> NDArray[np.float64]:
        return np.asarray(self.rows, dtype=np.float64)


def score_batch(
    model: LoadedAnomalyModel,
    batch: AnomalyPredictionBatch,
) -> tuple[AnomalyPredictionResult, ...]:
    manifest = model.manifest
    if batch.feature_schema_version != manifest.feature_schema_version:
        raise AnomalyPredictionError("anomaly feature schema version is incompatible")
    if batch.feature_names != manifest.feature_names:
        raise AnomalyPredictionError("anomaly feature names or order are incompatible")
    if batch.dtype != manifest.expected_dtype:
        raise AnomalyPredictionError("anomaly feature dtype is incompatible")
    raw, canonical = score_pipeline(model.estimator, batch.matrix())
    normalized = normalize_scores(canonical, manifest.normalizer)
    timestamp = datetime.now(UTC)
    return tuple(
        AnomalyPredictionResult(
            raw_model_score=float(raw_score),
            canonical_anomaly_score=float(canonical_score),
            normalized_anomaly_score=float(normalized_score),
            selected_threshold=manifest.anomaly_threshold,
            is_anomaly=bool(normalized_score >= manifest.anomaly_threshold),
            model_id=manifest.model_id,
            model_version=manifest.model_version,
            feature_schema_version=manifest.feature_schema_version,
            scored_at=timestamp,
        )
        for raw_score, canonical_score, normalized_score in zip(
            raw, canonical, normalized, strict=True
        )
    )
