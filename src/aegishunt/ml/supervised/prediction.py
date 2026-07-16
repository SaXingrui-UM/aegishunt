"""Strict feature-contract validation and supervised batch prediction."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, cast

import numpy as np
from numpy.typing import NDArray
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from aegishunt.ml.supervised.bundle import LoadedModel
from aegishunt.ml.supervised.candidates import raw_positive_scores
from aegishunt.ml.supervised.contracts import PredictionResult
from aegishunt.ml.supervised.errors import PredictionError


class PredictionBatch(BaseModel):
    """One immutable, explicitly ordered float64 feature batch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    feature_schema_version: str
    feature_names: tuple[str, ...]
    dtype: Literal["float64"]
    rows: tuple[tuple[float, ...], ...]

    @field_validator("rows")
    @classmethod
    def validate_rows(cls, rows: tuple[tuple[float, ...], ...]) -> tuple[tuple[float, ...], ...]:
        if not rows:
            raise ValueError("prediction batch cannot be empty")
        values = np.asarray(rows, dtype=np.float64)
        if values.ndim != 2 or not np.isfinite(values).all():
            raise ValueError("prediction rows must be a finite matrix")
        return rows

    @model_validator(mode="after")
    def validate_width(self) -> PredictionBatch:
        if not self.feature_names or any(len(row) != len(self.feature_names) for row in self.rows):
            raise ValueError("prediction rows must match the declared feature width")
        return self

    def matrix(self) -> NDArray[np.float64]:
        return np.asarray(self.rows, dtype=np.float64)


def predict_batch(model: LoadedModel, batch: PredictionBatch) -> tuple[PredictionResult, ...]:
    """Reject schema drift, then return calibrated supervised outputs only."""

    manifest = model.manifest
    if batch.feature_schema_version != manifest.feature_schema_version:
        raise PredictionError("prediction feature schema version is incompatible")
    if batch.feature_names != manifest.feature_names:
        raise PredictionError("prediction feature names or order are incompatible")
    if batch.dtype != manifest.expected_dtype:
        raise PredictionError("prediction feature dtype is incompatible")
    scores = raw_positive_scores(model.estimator, batch.matrix())
    probabilities = model.calibrator.transform(scores)
    timestamp = datetime.now(UTC)
    return tuple(
        PredictionResult(
            predicted_label=cast(
                Literal[0, 1],
                int(probability >= manifest.classification_threshold),
            ),
            raw_score=float(score),
            calibrated_probability=float(probability),
            selected_threshold=manifest.classification_threshold,
            model_id=manifest.model_id,
            model_version=manifest.model_version,
            feature_schema_version=manifest.feature_schema_version,
            prediction_timestamp=timestamp,
        )
        for score, probability in zip(scores, probabilities, strict=True)
    )
