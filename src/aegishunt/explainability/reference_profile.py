"""Benign-training-only reference profile construction."""

from __future__ import annotations

from datetime import UTC, datetime

import numpy as np

from aegishunt.detection.errors import DetectionContractError
from aegishunt.explainability.contracts import FeatureReference, ReferenceProfile


def build_reference_profile(
    *,
    profile_id: str,
    profile_version: str,
    dataset_id: str,
    dataset_version: str,
    dataset_checksum: str,
    split_checksum: str,
    feature_schema_version: str,
    feature_names: tuple[str, ...],
    rows: tuple[tuple[float, ...], ...],
    labels: tuple[int, ...],
    group_ids: tuple[str, ...],
    source_partition: str,
    git_commit_sha: str | None,
    created_at: datetime | None = None,
) -> ReferenceProfile:
    """Build q05–q95 reference evidence while rejecting test or attack rows."""

    if source_partition != "train":
        raise DetectionContractError("reference profile must use the training partition")
    if not rows or len(rows) != len(labels) or len(rows) != len(group_ids):
        raise DetectionContractError("reference profile inputs are empty or misaligned")
    if any(label != 0 for label in labels):
        raise DetectionContractError("reference profile cannot use attack rows")
    values = np.asarray(rows, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != len(feature_names):
        raise DetectionContractError("reference profile feature width is invalid")
    if not np.isfinite(values).all():
        raise DetectionContractError("reference profile values must be finite")
    quantiles = np.quantile(values, (0.05, 0.25, 0.5, 0.75, 0.95), axis=0)
    features = tuple(
        FeatureReference(
            feature_name=name,
            dtype="float64",
            count=len(rows),
            minimum=float(np.min(values[:, index])),
            q05=float(quantiles[0, index]),
            q25=float(quantiles[1, index]),
            median=float(quantiles[2, index]),
            q75=float(quantiles[3, index]),
            q95=float(quantiles[4, index]),
            maximum=float(np.max(values[:, index])),
            finite=True,
        )
        for index, name in enumerate(feature_names)
    )
    return ReferenceProfile(
        profile_schema_version="1.0.0",
        profile_id=profile_id,
        profile_version=profile_version,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        dataset_checksum=dataset_checksum,
        split_checksum=split_checksum,
        feature_schema_version=feature_schema_version,
        feature_names=feature_names,
        source_partition="train",
        benign_only=True,
        test_data_used=False,
        benign_row_count=len(rows),
        benign_group_count=len(set(group_ids)),
        reference_range="q05_q95",
        features=features,
        generation_config={
            "quantiles": [0.05, 0.25, 0.5, 0.75, 0.95],
            "reference_range": "q05_q95",
        },
        git_commit_sha=git_commit_sha,
        created_at=created_at or datetime.now(UTC),
    )
