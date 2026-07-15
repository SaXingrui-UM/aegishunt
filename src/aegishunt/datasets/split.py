"""Deterministic group-aware train/validation/test partitioning."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Sequence
from typing import Literal, cast

from aegishunt.datasets.errors import DatasetSplitError
from aegishunt.datasets.io import canonical_row_json
from aegishunt.datasets.reports import SplitManifest
from aegishunt.datasets.schemas import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalDatasetRow,
    SplitAssignment,
)
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION

SPLIT_MANIFEST_SCHEMA_VERSION = "1.0.0"
SPLIT_NAMES = ("train", "validation", "test")


def _stable_group_order(groups: Sequence[str], seed: int) -> list[str]:
    return sorted(
        groups,
        key=lambda group: hashlib.sha256(f"{seed}:{group}".encode()).hexdigest(),
    )


def _split_counts(group_count: int, ratios: dict[str, float]) -> dict[str, int]:
    if group_count < 3:
        raise DatasetSplitError("at least three independent groups are required")
    train_count = max(1, round(group_count * ratios["train"]))
    validation_count = max(1, round(group_count * ratios["validation"]))
    test_count = group_count - train_count - validation_count
    if test_count < 1:
        train_count -= 1 - test_count
        test_count = 1
    if train_count < 1:
        raise DatasetSplitError("configured ratios leave no training group")
    return {
        "train": train_count,
        "validation": validation_count,
        "test": test_count,
    }


def _require_identity_isolation(rows: Sequence[CanonicalDatasetRow]) -> None:
    for attribute in ("source_file", "capture_session_id", "scenario_id"):
        owners: dict[str, str] = {}
        for row in rows:
            value = str(getattr(row.metadata, attribute))
            previous = owners.setdefault(value, row.metadata.group_id)
            if previous != row.metadata.group_id:
                raise DatasetSplitError(
                    f"{attribute} is shared by multiple groups; group isolation would leak"
                )


def group_aware_split(
    rows: Sequence[CanonicalDatasetRow],
    *,
    seed: int,
    train_ratio: float,
    validation_ratio: float,
    test_ratio: float,
) -> tuple[tuple[SplitAssignment, ...], SplitManifest]:
    """Assign whole groups and refuse any source/session/scenario overlap."""

    if not rows:
        raise DatasetSplitError("cannot split an empty dataset")
    if abs(train_ratio + validation_ratio + test_ratio - 1.0) > 1e-9:
        raise DatasetSplitError("split ratios must sum to 1.0")
    dataset_ids = {(row.metadata.dataset_id, row.metadata.dataset_version) for row in rows}
    if len(dataset_ids) != 1:
        raise DatasetSplitError("one split operation may contain only one dataset version")
    _require_identity_isolation(rows)
    grouped: dict[str, list[CanonicalDatasetRow]] = defaultdict(list)
    for row in rows:
        grouped[row.metadata.group_id].append(row)
    ratios = {"train": train_ratio, "validation": validation_ratio, "test": test_ratio}
    counts = _split_counts(len(grouped), ratios)
    ordered = _stable_group_order(tuple(grouped), seed)
    train_end = counts["train"]
    validation_end = train_end + counts["validation"]
    group_partitions = {
        "train": tuple(sorted(ordered[:train_end])),
        "validation": tuple(sorted(ordered[train_end:validation_end])),
        "test": tuple(sorted(ordered[validation_end:])),
    }
    group_to_split = {
        group: split for split, groups in group_partitions.items() for group in groups
    }
    assignments = tuple(
        SplitAssignment(
            split=cast(
                Literal["train", "validation", "test"],
                group_to_split[row.metadata.group_id],
            ),
            row=row,
        )
        for row in sorted(rows, key=lambda item: item.metadata.record_id)
    )
    rows_by_split = {
        split: tuple(assignment.row for assignment in assignments if assignment.split == split)
        for split in SPLIT_NAMES
    }
    row_counts = {split: len(partition) for split, partition in rows_by_split.items()}
    total_rows = len(rows)
    dataset_payload = "\n".join(
        canonical_row_json(row) for row in sorted(rows, key=lambda item: item.metadata.record_id)
    )
    dataset_checksum = hashlib.sha256(dataset_payload.encode()).hexdigest()
    dataset_id, dataset_version = next(iter(dataset_ids))
    manifest = SplitManifest(
        manifest_schema_version=SPLIT_MANIFEST_SCHEMA_VERSION,
        dataset_id=dataset_id,
        dataset_version=dataset_version,
        split_strategy="deterministic group hash; no row-level fallback",
        group_key="metadata.group_id with source/session/scenario exclusivity",
        random_seed=seed,
        configured_ratios=ratios,
        actual_ratios={
            split: row_counts[split] / total_rows for split in SPLIT_NAMES
        },
        train_groups=group_partitions["train"],
        validation_groups=group_partitions["validation"],
        test_groups=group_partitions["test"],
        row_counts=row_counts,
        group_counts={
            split: len(groups) for split, groups in group_partitions.items()
        },
        class_distributions={
            split: dict(
                sorted(Counter(str(row.labels.binary_label) for row in partition).items())
            )
            for split, partition in rows_by_split.items()
        },
        attack_family_distributions={
            split: dict(sorted(Counter(row.labels.attack_family for row in partition).items()))
            for split, partition in rows_by_split.items()
        },
        overlap_validation_result="pass",
        source_file_overlap_result="pass",
        frozen_test=True,
        test_usage_policy=(
            "Frozen for one-time final evaluation; not for model, threshold, or feature selection."
        ),
        dataset_checksum=dataset_checksum,
        canonical_schema_version=CANONICAL_SCHEMA_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
    )
    return assignments, manifest


def assignments_json(assignments: Sequence[SplitAssignment]) -> str:
    """Serialize assignments deterministically for restart comparisons."""

    payload = [assignment.model_dump(mode="json") for assignment in assignments]
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
