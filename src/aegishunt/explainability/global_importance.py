"""Non-causal native and fixed-validation permutation importance."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import numpy as np
from sklearn.inspection import permutation_importance

from aegishunt.detection.errors import DetectionContractError
from aegishunt.explainability.contracts import (
    GlobalImportanceReport,
    ImportanceEntry,
    PermutationImportanceReport,
)


def native_tree_importance(
    estimator: object,
    *,
    report_id: str,
    model_id: str,
    model_version: str,
    feature_schema_version: str,
    feature_names: tuple[str, ...],
    created_at: datetime | None = None,
) -> GlobalImportanceReport:
    """Read supported tree importance without inventing unavailable values."""

    candidate = estimator
    named_steps = getattr(estimator, "named_steps", None)
    if isinstance(named_steps, dict) and named_steps:
        candidate = tuple(named_steps.values())[-1]
    raw = getattr(candidate, "feature_importances_", None)
    if raw is None:
        return GlobalImportanceReport(
            report_schema_version="1.0.0",
            report_id=report_id,
            method="native_tree_importance",
            status="not_applicable",
            model_id=model_id,
            model_version=model_version,
            feature_schema_version=feature_schema_version,
            feature_names=feature_names,
            entries=(),
            semantics="model association or sensitivity; not causation",
            created_at=created_at or datetime.now(UTC),
        )
    values = np.asarray(raw, dtype=np.float64)
    if values.shape != (len(feature_names),) or not np.isfinite(values).all():
        raise DetectionContractError("native importance does not match the feature contract")
    if np.any(values < 0.0):
        raise DetectionContractError("native tree importance cannot be negative")
    return GlobalImportanceReport(
        report_schema_version="1.0.0",
        report_id=report_id,
        method="native_tree_importance",
        status="available",
        model_id=model_id,
        model_version=model_version,
        feature_schema_version=feature_schema_version,
        feature_names=feature_names,
        entries=tuple(
            ImportanceEntry(feature_name=name, mean=float(values[index]), standard_deviation=0.0)
            for index, name in enumerate(feature_names)
        ),
        semantics="model association or sensitivity; not causation",
        created_at=created_at or datetime.now(UTC),
    )


def fixed_validation_permutation_importance(
    estimator: Any,
    *,
    report_id: str,
    model_id: str,
    model_version: str,
    feature_schema_version: str,
    feature_names: tuple[str, ...],
    rows: tuple[tuple[float, ...], ...],
    labels: tuple[int, ...],
    group_ids: tuple[str, ...],
    source_partition: str,
    scoring_metric: str,
    random_seed: int,
    repeats: int,
    created_at: datetime | None = None,
) -> PermutationImportanceReport:
    """Measure fixed-validation sensitivity; negative importance is retained."""

    if source_partition != "validation":
        raise DetectionContractError("permutation importance must use validation evidence")
    if len(rows) < 2 or len(rows) != len(labels) or len(rows) != len(group_ids):
        raise DetectionContractError("permutation evidence is empty or misaligned")
    matrix = np.asarray(rows, dtype=np.float64)
    targets = np.asarray(labels, dtype=np.int64)
    if matrix.ndim != 2 or matrix.shape[1] != len(feature_names):
        raise DetectionContractError("permutation feature width is invalid")
    if not np.isfinite(matrix).all():
        raise DetectionContractError("permutation values must be finite")
    try:
        result = permutation_importance(
            estimator,
            matrix,
            targets,
            scoring=scoring_metric,
            n_repeats=repeats,
            random_state=random_seed,
            n_jobs=1,
        )
    except (TypeError, ValueError) as exc:
        raise DetectionContractError("permutation importance could not be computed") from exc
    means = np.asarray(result.importances_mean, dtype=np.float64)
    deviations = np.asarray(result.importances_std, dtype=np.float64)
    if (
        means.shape != (len(feature_names),)
        or deviations.shape != means.shape
        or not np.isfinite(means).all()
        or not np.isfinite(deviations).all()
    ):
        raise DetectionContractError("permutation importance output is invalid")
    return PermutationImportanceReport(
        report_schema_version="1.0.0",
        report_id=report_id,
        method="permutation_importance",
        model_id=model_id,
        model_version=model_version,
        feature_schema_version=feature_schema_version,
        feature_names=feature_names,
        source_partition="validation",
        test_data_used=False,
        scoring_metric=scoring_metric,
        random_seed=random_seed,
        repeats=repeats,
        row_count=len(rows),
        group_count=len(set(group_ids)),
        entries=tuple(
            ImportanceEntry(
                feature_name=name,
                mean=float(means[index]),
                standard_deviation=float(deviations[index]),
            )
            for index, name in enumerate(feature_names)
        ),
        semantics="model sensitivity to feature permutation; not causation",
        created_at=created_at or datetime.now(UTC),
    )
