"""Deterministic canonical dataset quality and duplicate analysis."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Literal

from aegishunt.datasets.errors import DatasetQualityError
from aegishunt.datasets.io import canonical_row_json
from aegishunt.datasets.reports import QualityFinding, QualityReport
from aegishunt.datasets.schemas import (
    CANONICAL_SCHEMA_VERSION,
    CanonicalDatasetRow,
)
from aegishunt.flows.registry import FEATURE_DEFINITIONS, FEATURE_SCHEMA_VERSION, feature_names

QUALITY_REPORT_SCHEMA_VERSION = "1.0.0"


def feature_fingerprint(row: CanonicalDatasetRow) -> str:
    payload = json.dumps(row.features.values, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def near_feature_fingerprint(row: CanonicalDatasetRow, tolerance: float) -> str:
    quantized = tuple(round(value / tolerance) for value in row.features.values)
    payload = json.dumps(quantized, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def _duplicates(fingerprints: Sequence[str]) -> int:
    return sum(count - 1 for count in Counter(fingerprints).values() if count > 1)


def analyze_quality(
    rows: Sequence[CanonicalDatasetRow],
    *,
    near_duplicate_tolerance: float,
) -> QualityReport:
    """Analyze validated rows without silently repairing or deleting evidence."""

    if not rows:
        raise DatasetQualityError("quality analysis requires at least one canonical row")
    feature_values = {
        name: [row.features.values[index] for row in rows]
        for index, name in enumerate(feature_names())
    }
    exact_fingerprints = [
        hashlib.sha256(canonical_row_json(row).encode()).hexdigest() for row in rows
    ]
    feature_fingerprints = [feature_fingerprint(row) for row in rows]
    label_by_feature: dict[str, set[str]] = defaultdict(set)
    for row, fingerprint in zip(rows, feature_fingerprints, strict=True):
        label_by_feature[fingerprint].add(row.labels.ground_truth_label)
    provenance_fingerprints = [
        f"{row.metadata.source_file}|{row.metadata.original_row_id}" for row in rows
    ]
    near_groups: dict[str, list[CanonicalDatasetRow]] = defaultdict(list)
    for row in rows:
        near_groups[near_feature_fingerprint(row, near_duplicate_tolerance)].append(row)
    near_duplicate_sets = [
        group
        for group in near_groups.values()
        if len(group) > 1 and len({feature_fingerprint(row) for row in group}) > 1
    ]
    invalid: list[str] = []
    for definition in FEATURE_DEFINITIONS:
        for value in feature_values[definition.name]:
            if not math.isfinite(value):
                invalid.append(definition.name)
                break
            if definition.minimum is not None and value < definition.minimum:
                invalid.append(definition.name)
                break
            if definition.maximum is not None and value > definition.maximum:
                invalid.append(definition.name)
                break

    constant = tuple(
        name for name, values in feature_values.items() if len(set(values)) == 1
    )
    near_constant = tuple(
        name
        for name, values in feature_values.items()
        if len(set(values)) > 1 and Counter(values).most_common(1)[0][1] / len(values) >= 0.95
    )
    all_zero = tuple(
        name for name, values in feature_values.items() if all(value == 0.0 for value in values)
    )
    binary = Counter(str(row.labels.binary_label) for row in rows)
    families = Counter(row.labels.attack_family for row in rows)
    group_classes: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        group_classes[row.metadata.group_id][str(row.labels.binary_label)] += 1

    missing_counts = {
        "metadata.observed_at": sum(row.metadata.observed_at is None for row in rows),
        "metadata.group_id": sum(not row.metadata.group_id for row in rows),
        "metadata.capture_session_id": sum(not row.metadata.capture_session_id for row in rows),
        "metadata.scenario_id": sum(not row.metadata.scenario_id for row in rows),
        "labels.ground_truth_label": sum(not row.labels.ground_truth_label for row in rows),
        "labels.binary_label": sum(row.labels.binary_label is None for row in rows),
        "labels.attack_family": sum(not row.labels.attack_family for row in rows),
        "features": 0,
    }
    findings: list[QualityFinding] = []
    conflicting = sum(len(labels) > 1 for labels in label_by_feature.values())
    if conflicting:
        findings.append(
            QualityFinding(
                code="Q-CONFLICTING-LABELS",
                severity="high",
                message="identical feature vectors have conflicting ground-truth labels",
                evidence=(str(conflicting),),
                remediation="inspect source labels and conversion rules before splitting",
            )
        )
    if invalid:
        findings.append(
            QualityFinding(
                code="Q-INVALID-FEATURE",
                severity="high",
                message="one or more features violate the Phase 3 contract",
                evidence=tuple(sorted(set(invalid))),
                remediation="correct the converter; do not impute or clamp silently",
            )
        )
    if constant:
        findings.append(
            QualityFinding(
                code="Q-CONSTANT-FEATURES",
                severity="informational",
                message="features are constant in the observed dataset",
                evidence=constant,
                remediation="retain and document until a later research phase evaluates removal",
            )
        )
    status: Literal["pass", "fail", "warning"] = (
        "fail" if conflicting or invalid or any(missing_counts.values()) else "pass"
    )
    return QualityReport(
        report_schema_version=QUALITY_REPORT_SCHEMA_VERSION,
        canonical_schema_version=CANONICAL_SCHEMA_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        status=status,
        row_count=len(rows),
        group_count=len({row.metadata.group_id for row in rows}),
        missing_counts=missing_counts,
        missing_percentages={
            name: count / len(rows) for name, count in missing_counts.items()
        },
        exact_duplicate_count=_duplicates(exact_fingerprints),
        feature_duplicate_count=_duplicates(feature_fingerprints),
        conflicting_label_fingerprint_count=conflicting,
        provenance_duplicate_count=_duplicates(provenance_fingerprints),
        near_duplicate_count=sum(len(group) - 1 for group in near_duplicate_sets),
        near_duplicate_groups=tuple(
            sorted({row.metadata.group_id for group in near_duplicate_sets for row in group})
        ),
        near_duplicate_tolerance=near_duplicate_tolerance,
        constant_features=constant,
        near_constant_features=near_constant,
        all_zero_features=all_zero,
        invalid_features=tuple(sorted(set(invalid))),
        binary_class_distribution=dict(sorted(binary.items())),
        attack_family_distribution=dict(sorted(families.items())),
        group_class_distribution={
            group: dict(sorted(counts.items())) for group, counts in sorted(group_classes.items())
        },
        findings=tuple(findings),
    )


def _quantile(values: Sequence[float], fraction: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def write_feature_statistics(rows: Sequence[CanonicalDatasetRow], path: Path) -> None:
    """Export deterministic finite per-feature descriptive statistics."""

    if not rows:
        raise DatasetQualityError("feature statistics require canonical rows")
    if path.exists():
        raise DatasetQualityError("feature statistics output already exists")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination, lineterminator="\n")
            writer.writerow(
                (
                    "feature_name",
                    "feature_schema_version",
                    "count",
                    "missing_count",
                    "minimum",
                    "maximum",
                    "mean",
                    "standard_deviation",
                    "median",
                    "q25",
                    "q75",
                    "finite_status",
                    "constant_indicator",
                    "near_constant_indicator",
                )
            )
            for index, name in enumerate(feature_names()):
                values = [row.features.values[index] for row in rows]
                counts = Counter(values)
                writer.writerow(
                    (
                        name,
                        FEATURE_SCHEMA_VERSION,
                        len(values),
                        0,
                        min(values),
                        max(values),
                        statistics.fmean(values),
                        statistics.pstdev(values) if len(values) > 1 else 0.0,
                        statistics.median(values),
                        _quantile(values, 0.25),
                        _quantile(values, 0.75),
                        "finite" if all(math.isfinite(value) for value in values) else "invalid",
                        str(len(counts) == 1).lower(),
                        str(
                            len(counts) > 1
                            and counts.most_common(1)[0][1] / len(values) >= 0.95
                        ).lower(),
                    )
                )
    except OSError as exc:
        raise DatasetQualityError("unable to write feature statistics") from exc


def write_class_distribution(
    rows_by_split: Mapping[str, Sequence[CanonicalDatasetRow]],
    path: Path,
) -> None:
    """Export binary and family distributions without resampling."""

    if path.exists():
        raise DatasetQualityError("class distribution output already exists")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="") as destination:
            writer = csv.writer(destination, lineterminator="\n")
            writer.writerow(("split", "distribution_type", "label", "count", "percentage"))
            for split, rows in sorted(rows_by_split.items()):
                distributions = {
                    "binary": Counter(str(row.labels.binary_label) for row in rows),
                    "attack_family": Counter(row.labels.attack_family for row in rows),
                }
                for distribution_type, counts in distributions.items():
                    total = sum(counts.values())
                    for label, count in sorted(counts.items()):
                        percentage = count / total if total else 0.0
                        writer.writerow((split, distribution_type, label, count, percentage))
    except OSError as exc:
        raise DatasetQualityError("unable to write class distribution") from exc
