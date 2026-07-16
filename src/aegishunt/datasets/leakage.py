"""Fail-closed cross-split and feature/metadata leakage checks."""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Sequence

from aegishunt.datasets.quality import feature_fingerprint, near_feature_fingerprint
from aegishunt.datasets.reports import LeakageReport, QualityFinding
from aegishunt.datasets.schemas import SplitAssignment

LEAKAGE_REPORT_SCHEMA_VERSION = "1.0.0"
LABEL_TOKENS = {
    "attack",
    "benign",
    "malicious",
    "scan",
    "brute",
    "ddos",
    "dos",
    "bot",
    "infiltration",
    "exfiltration",
    "ransomware",
}
METADATA_FIELD_NAMES = {
    "dataset_id",
    "dataset_version",
    "record_id",
    "source_file",
    "source_file_checksum",
    "capture_session_id",
    "scenario_id",
    "group_id",
    "original_row_id",
    "observed_at",
    "ground_truth_label",
    "binary_label",
    "attack_family",
    "original_label",
}


def _overlap(assignments: Sequence[SplitAssignment], attribute: str) -> tuple[str, ...]:
    owners: dict[str, set[str]] = defaultdict(set)
    for assignment in assignments:
        owners[str(getattr(assignment.row.metadata, attribute))].add(assignment.split)
    return tuple(sorted(value for value, splits in owners.items() if len(splits) > 1))


def _fingerprint_overlap(
    assignments: Sequence[SplitAssignment],
    *,
    near_tolerance: float | None,
) -> tuple[str, ...]:
    owners: dict[str, set[str]] = defaultdict(set)
    for assignment in assignments:
        fingerprint = (
            feature_fingerprint(assignment.row)
            if near_tolerance is None
            else near_feature_fingerprint(assignment.row, near_tolerance)
        )
        owners[fingerprint].add(assignment.split)
    return tuple(sorted(fingerprint for fingerprint, splits in owners.items() if len(splits) > 1))


def _direct_label_features(assignments: Sequence[SplitAssignment]) -> tuple[str, ...]:
    rows = [assignment.row for assignment in assignments]
    if not rows:
        return ()
    suspicious: list[str] = []
    for index, name in enumerate(rows[0].features.names):
        values = [row.features.values[index] for row in rows]
        labels = [row.labels.binary_label for row in rows]
        if any(label is None for label in labels):
            continue
        paired = zip(values, labels, strict=True)
        if all(
            label is not None and math.isclose(value, float(label), abs_tol=0.0)
            for value, label in paired
        ):
            suspicious.append(name)
        if any(token in name.casefold() for token in LABEL_TOKENS):
            suspicious.append(name)
    return tuple(sorted(set(suspicious)))


def _metadata_leakage(assignments: Sequence[SplitAssignment]) -> tuple[str, ...]:
    if not assignments:
        return ()
    feature_names = set(assignments[0].row.features.names)
    accidental = feature_names & METADATA_FIELD_NAMES
    provenance_keys = {
        key for assignment in assignments for key in assignment.row.metadata.provenance
    }
    accidental.update(feature_names & provenance_keys)
    suspicious_values: set[str] = set()
    for assignment in assignments:
        metadata = assignment.row.metadata
        if any(token in metadata.scenario_id.casefold() for token in LABEL_TOKENS):
            suspicious_values.add(f"scenario_id:{metadata.scenario_id}")
        for key, value in metadata.provenance.items():
            if any(token in value.casefold() for token in LABEL_TOKENS):
                suspicious_values.add(f"provenance.{key}:{value}")
    return tuple(sorted((*accidental, *suspicious_values)))


def _correlation_warnings(assignments: Sequence[SplitAssignment]) -> tuple[str, ...]:
    rows = [assignment.row for assignment in assignments]
    labels = [row.labels.binary_label for row in rows]
    if len(rows) < 3 or any(label is None for label in labels):
        return ()
    numeric_labels = [float(label) for label in labels if label is not None]
    label_mean = sum(numeric_labels) / len(numeric_labels)
    label_variance = sum((label - label_mean) ** 2 for label in numeric_labels)
    if label_variance == 0.0:
        return ()
    warnings: list[str] = []
    for index, name in enumerate(rows[0].features.names):
        values = [row.features.values[index] for row in rows]
        value_mean = sum(values) / len(values)
        value_variance = sum((value - value_mean) ** 2 for value in values)
        if value_variance == 0.0:
            continue
        covariance = sum(
            (value - value_mean) * (label - label_mean)
            for value, label in zip(values, numeric_labels, strict=True)
        )
        correlation = covariance / math.sqrt(value_variance * label_variance)
        if abs(correlation) >= 0.98:
            warnings.append(f"{name}:{correlation:.6f}")
    return tuple(sorted(warnings))


def _unique_value_label_warnings(
    assignments: Sequence[SplitAssignment],
) -> tuple[str, ...]:
    """Flag low-cardinality values that deterministically partition known labels."""

    rows = [assignment.row for assignment in assignments]
    if len(rows) < 4 or any(row.labels.binary_label is None for row in rows):
        return ()
    cardinality_limit = max(2, min(20, math.isqrt(len(rows))))
    warnings: list[str] = []
    for index, name in enumerate(rows[0].features.names):
        labels_by_value: dict[float, set[int]] = defaultdict(set)
        for row in rows:
            label = row.labels.binary_label
            if label is not None:
                labels_by_value[row.features.values[index]].add(label)
        represented_labels = set().union(*labels_by_value.values())
        if (
            1 < len(labels_by_value) <= cardinality_limit
            and len(represented_labels) > 1
            and all(len(labels) == 1 for labels in labels_by_value.values())
        ):
            warnings.append(f"{name}:{len(labels_by_value)}-value deterministic association")
    return tuple(sorted(warnings))


def _token_leakage(assignments: Sequence[SplitAssignment], attribute: str) -> tuple[str, ...]:
    values = {str(getattr(assignment.row.metadata, attribute)) for assignment in assignments}
    return tuple(
        sorted(
            value
            for value in values
            if any(token in value.casefold() for token in LABEL_TOKENS)
        )
    )


def analyze_leakage(
    assignments: Sequence[SplitAssignment],
    *,
    near_duplicate_tolerance: float,
) -> LeakageReport:
    """Reject split/feature leakage and retain warnings as structured evidence."""

    group_overlap = _overlap(assignments, "group_id")
    source_overlap = _overlap(assignments, "source_file")
    session_overlap = _overlap(assignments, "capture_session_id")
    scenario_overlap = _overlap(assignments, "scenario_id")
    exact_overlap = _fingerprint_overlap(assignments, near_tolerance=None)
    near_overlap = _fingerprint_overlap(
        assignments,
        near_tolerance=near_duplicate_tolerance,
    )
    label_features = _direct_label_features(assignments)
    suspicious_metadata = _metadata_leakage(assignments)
    filename_leakage = _token_leakage(assignments, "source_file")
    record_id_leakage = _token_leakage(assignments, "record_id")
    correlation_warnings = _correlation_warnings(assignments)
    unique_value_label_warnings = _unique_value_label_warnings(assignments)
    observed_dates: dict[str, set[int]] = defaultdict(set)
    for assignment in assignments:
        observed = assignment.row.metadata.observed_at
        binary_label = assignment.row.labels.binary_label
        if observed is not None and binary_label is not None:
            observed_dates[observed.date().isoformat()].add(binary_label)
    timestamp_leakage = tuple(
        sorted(date for date, labels in observed_dates.items() if len(labels) == 1)
    ) if len(observed_dates) > 1 else ()
    blockers = (
        group_overlap,
        source_overlap,
        session_overlap,
        scenario_overlap,
        exact_overlap,
        near_overlap,
        label_features,
        suspicious_metadata,
        filename_leakage,
        record_id_leakage,
    )
    findings: list[QualityFinding] = []
    if any(blockers):
        findings.append(
            QualityFinding(
                code="L-FAIL-CLOSED",
                severity="high",
                message="dataset split or feature metadata failed a leakage gate",
                evidence=tuple(str(len(values)) for values in blockers),
                remediation="repair conversion or group assignments and regenerate all manifests",
            )
        )
    if timestamp_leakage:
        findings.append(
            QualityFinding(
                code="L-TIMESTAMP-SIGNAL",
                severity="medium",
                message="dates are associated with only one binary label and require review",
                evidence=timestamp_leakage,
                remediation=(
                    "keep timestamps outside features and consider grouped time-aware validation"
                ),
            )
        )
    if unique_value_label_warnings:
        findings.append(
            QualityFinding(
                code="L-UNIQUE-LABEL-ASSOCIATION",
                severity="medium",
                message=(
                    "low-cardinality feature values have a deterministic label association"
                ),
                evidence=unique_value_label_warnings,
                remediation=(
                    "audit feature provenance; treat this as a risk signal, not causal proof"
                ),
            )
        )
    return LeakageReport(
        report_schema_version=LEAKAGE_REPORT_SCHEMA_VERSION,
        status="fail" if any(blockers) else "pass",
        group_overlap=group_overlap,
        source_file_overlap=source_overlap,
        session_overlap=session_overlap,
        scenario_overlap=scenario_overlap,
        exact_duplicate_overlap=exact_overlap,
        near_duplicate_overlap=near_overlap,
        label_derived_features=label_features,
        suspicious_metadata=suspicious_metadata,
        filename_leakage=filename_leakage,
        timestamp_leakage=timestamp_leakage,
        record_id_leakage=record_id_leakage,
        correlation_warnings=correlation_warnings,
        unique_value_label_warnings=unique_value_label_warnings,
        attack_family_considerations=(
            "Attack-family metadata remains outside features for group-isolated evaluation.",
            (
                "Leave-One-Attack-Family-Out experiments are deferred and must not use "
                "the frozen test split for selection."
            ),
        ),
        findings=tuple(findings),
    )
