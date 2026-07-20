"""Independent, group-isolated controlled evidence for Phase 7."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from aegishunt.datasets.demo import DEMO_GENERATOR_VERSION, build_controlled_demo
from aegishunt.datasets.io import canonical_row_json
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.quality import analyze_quality
from aegishunt.datasets.schemas import (
    CanonicalDatasetRow,
    CanonicalFeatureVector,
    CanonicalMetadata,
)
from aegishunt.flows.registry import feature_names
from aegishunt.ml.fusion.config import FusionExperimentConfig, ParameterShiftDefinition
from aegishunt.ml.fusion.contracts import Phase7DatasetManifest, Phase7SplitManifest
from aegishunt.ml.fusion.errors import FusionDatasetError

TimelineStage = Literal["early", "middle", "late"]
_STAGES: tuple[TimelineStage, ...] = ("early", "middle", "late")
PHASE7_GENERATOR_VERSION = "1.0.0"
_SHIFT_FEATURES: dict[str, tuple[str, ...]] = {
    "flow_duration": (
        "flow_duration",
        "mean_inter_arrival_time",
        "packets_per_second",
        "bytes_per_second",
    ),
    "packet_rate": (
        "packets_per_second",
        "bytes_per_second",
        "connection_burst_score",
    ),
    "packet_size_pattern": (
        "total_bytes",
        "mean_packet_size",
        "max_packet_size",
        "bytes_per_second",
    ),
    "connection_frequency": ("connection_burst_score",),
}


@dataclass(frozen=True, slots=True)
class ExperimentPartition:
    """Canonical rows with array access and non-feature evidence."""

    name: str
    rows: tuple[CanonicalDatasetRow, ...]

    def __post_init__(self) -> None:
        if not self.rows:
            raise FusionDatasetError("experiment partition cannot be empty")

    @property
    def features(self) -> NDArray[np.float64]:
        return np.asarray([row.features.values for row in self.rows], dtype=np.float64)

    @property
    def labels(self) -> NDArray[np.int64]:
        labels = [row.labels.binary_label for row in self.rows]
        if any(value is None for value in labels):
            raise FusionDatasetError("experiment partition contains an unmapped label")
        return np.asarray(labels, dtype=np.int64)

    @property
    def groups(self) -> NDArray[np.str_]:
        return np.asarray([row.metadata.group_id for row in self.rows], dtype=np.str_)

    @property
    def families(self) -> NDArray[np.str_]:
        return np.asarray([row.labels.attack_family for row in self.rows], dtype=np.str_)


@dataclass(frozen=True, slots=True)
class ControlledExperimentDataset:
    """One immutable in-memory Phase 7 dataset and its evidence manifests."""

    rows: tuple[CanonicalDatasetRow, ...]
    manifest: Phase7DatasetManifest
    split_manifest: Phase7SplitManifest

    def stage(self, stage: TimelineStage) -> ExperimentPartition:
        rows = tuple(row for row in self.rows if row.metadata.provenance["timeline_stage"] == stage)
        return ExperimentPartition(stage, rows)

    @property
    def eligible_attack_families(self) -> tuple[str, ...]:
        return self.manifest.attack_families

    def leave_one_family_out(
        self, family: str
    ) -> tuple[ExperimentPartition, ExperimentPartition, ExperimentPartition]:
        if family not in self.eligible_attack_families:
            raise FusionDatasetError("held-out attack family is not eligible")
        train = tuple(row for row in self.stage("early").rows if row.labels.attack_family != family)
        validation = tuple(
            row for row in self.stage("middle").rows if row.labels.attack_family != family
        )
        evaluation = tuple(
            row for row in self.stage("late").rows if row.labels.attack_family in {"benign", family}
        )
        _require_isolated(train, validation, evaluation)
        if any(row.labels.attack_family == family for row in (*train, *validation)):
            raise FusionDatasetError("held-out family leaked into fit or selection evidence")
        return (
            ExperimentPartition(f"loao-{family}-train", train),
            ExperimentPartition(f"loao-{family}-validation", validation),
            ExperimentPartition(f"loao-{family}-evaluation", evaluation),
        )


def _stage_for_variant(variant: int, groups_per_pattern: int) -> TimelineStage:
    if groups_per_pattern % 3:
        raise FusionDatasetError("timeline assignment requires three equal group strata")
    return _STAGES[variant % 3]


def _dataset_checksum(rows: tuple[CanonicalDatasetRow, ...]) -> str:
    payload = "\n".join(canonical_row_json(row) for row in rows).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _identity_sets(rows: tuple[CanonicalDatasetRow, ...], attribute: str) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        stage = row.metadata.provenance["timeline_stage"]
        result[stage].add(str(getattr(row.metadata, attribute)))
    return result


def _cross_overlap(values: dict[str, set[str]]) -> tuple[str, ...]:
    overlaps: set[str] = set()
    for index, left in enumerate(_STAGES):
        for right in _STAGES[index + 1 :]:
            overlaps.update(values[left] & values[right])
    return tuple(sorted(overlaps))


def _require_isolated(*partitions: tuple[CanonicalDatasetRow, ...]) -> None:
    for attribute in (
        "group_id",
        "source_file",
        "capture_session_id",
        "scenario_id",
    ):
        identities = [
            {str(getattr(row.metadata, attribute)) for row in rows} for rows in partitions
        ]
        if any(
            left & right
            for index, left in enumerate(identities)
            for right in identities[index + 1 :]
        ):
            raise FusionDatasetError(f"experiment partitions overlap by {attribute}")


def _observed_bounds(rows: tuple[CanonicalDatasetRow, ...]) -> tuple[datetime, datetime]:
    timestamps = tuple(
        row.metadata.observed_at for row in rows if row.metadata.observed_at is not None
    )
    if len(timestamps) != len(rows):
        raise FusionDatasetError("Phase 7 temporal evidence requires every timestamp")
    return min(timestamps), max(timestamps)


def build_controlled_experiment_dataset(
    config: FusionExperimentConfig,
    label_mapper: LabelMapper,
) -> ControlledExperimentDataset:
    """Generate new evidence without reading Phase 4/5/6 frozen test partitions."""

    if config.groups_per_pattern % 3:
        raise FusionDatasetError("groups per pattern must divide evenly across three stages")
    source = build_controlled_demo(
        seed=config.data_seed,
        label_mapper=label_mapper,
        groups_per_pattern=config.groups_per_pattern,
    )
    rows_by_pattern_group: dict[str, dict[str, list[CanonicalDatasetRow]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in source:
        pattern = row.metadata.provenance["pattern_code"]
        rows_by_pattern_group[pattern][row.metadata.group_id].append(row)
    generated: list[CanonicalDatasetRow] = []
    for pattern_index, pattern in enumerate(sorted(rows_by_pattern_group)):
        groups = rows_by_pattern_group[pattern]
        for variant, original_group in enumerate(sorted(groups)):
            stage = _stage_for_variant(variant, config.groups_per_pattern)
            stage_index = _STAGES.index(stage)
            group_id = f"p7-{pattern}-{stage}-{variant + 1:02d}"
            source_group_rows = sorted(
                groups[original_group], key=lambda item: item.metadata.record_id
            )
            if len(source_group_rows) != config.rows_per_group:
                raise FusionDatasetError(
                    "controlled source rows per group differ from the frozen protocol"
                )
            for row_index, row in enumerate(source_group_rows):
                observed_at = config.protocol_frozen_at + timedelta(
                    days=stage_index * 30,
                    hours=pattern_index,
                    minutes=variant * 5 + row_index,
                )
                source_file = f"{group_id}.flow"
                checksum = hashlib.sha256(
                    (
                        f"{PHASE7_GENERATOR_VERSION}:{config.data_seed}:{group_id}:{row_index}"
                    ).encode()
                ).hexdigest()
                metadata = CanonicalMetadata(
                    dataset_id=config.dataset_id,
                    dataset_version=config.dataset_version,
                    record_id=f"{group_id}-row-{row_index + 1:02d}",
                    source_file=source_file,
                    source_file_checksum=checksum,
                    capture_session_id=f"capture-{group_id}",
                    scenario_id=f"scenario-{group_id}",
                    group_id=group_id,
                    original_row_id=str(row_index + 1),
                    source_access_date=config.protocol_frozen_at.date(),
                    observed_at=observed_at,
                    provenance={
                        "generator": "aegishunt-phase-07-controlled",
                        "generator_version": PHASE7_GENERATOR_VERSION,
                        "source_generator_version": DEMO_GENERATOR_VERSION,
                        "pattern_code": pattern,
                        "timeline_stage": stage,
                        "parameter_shift": "base",
                        "controlled_synthetic": "true",
                    },
                    conversion_version=row.metadata.conversion_version,
                )
                generated.append(
                    CanonicalDatasetRow(
                        canonical_schema_version=row.canonical_schema_version,
                        metadata=metadata,
                        features=row.features,
                        labels=row.labels,
                    )
                )
    rows = tuple(sorted(generated, key=lambda row: row.metadata.record_id))
    if len(rows) != len(source):
        raise FusionDatasetError("Phase 7 generator lost controlled rows")
    quality = analyze_quality(rows, near_duplicate_tolerance=1e-9)
    if quality.status != "pass":
        raise FusionDatasetError("Phase 7 controlled dataset failed quality validation")
    attack_families = tuple(
        sorted({row.labels.attack_family for row in rows if row.labels.binary_label == 1})
    )
    if len(attack_families) < 2:
        raise FusionDatasetError("Phase 7 requires at least two eligible attack families")
    checksum = _dataset_checksum(rows)
    family_distribution = dict(sorted(Counter(row.labels.attack_family for row in rows).items()))
    manifest = Phase7DatasetManifest(
        manifest_schema_version="1.0.0",
        dataset_id=config.dataset_id,
        dataset_version=config.dataset_version,
        generator_version=PHASE7_GENERATOR_VERSION,
        feature_schema_version=config.feature_schema_version,
        row_count=len(rows),
        group_count=len({row.metadata.group_id for row in rows}),
        attack_families=attack_families,
        family_distribution=family_distribution,
        dataset_checksum=checksum,
        quality_status="pass",
        exact_duplicate_count=quality.exact_duplicate_count,
        feature_duplicate_count=quality.feature_duplicate_count,
        conflicting_label_fingerprint_count=(quality.conflicting_label_fingerprint_count),
        near_duplicate_count=quality.near_duplicate_count,
        controlled_synthetic_only=True,
        public_benchmark=False,
        network_access=False,
        external_target=False,
        historical_frozen_test_reused=False,
        random_seed=config.data_seed,
    )
    rows_by_stage = {
        stage: tuple(row for row in rows if row.metadata.provenance["timeline_stage"] == stage)
        for stage in _STAGES
    }
    _require_isolated(*(rows_by_stage[stage] for stage in _STAGES))
    time_ranges: dict[str, tuple[datetime, datetime]] = {
        stage: _observed_bounds(stage_rows) for stage, stage_rows in rows_by_stage.items()
    }
    split = Phase7SplitManifest(
        manifest_schema_version="1.0.0",
        dataset_id=config.dataset_id,
        dataset_version=config.dataset_version,
        dataset_checksum=checksum,
        time_field="metadata.observed_at",
        early_groups=tuple(sorted({row.metadata.group_id for row in rows_by_stage["early"]})),
        middle_groups=tuple(sorted({row.metadata.group_id for row in rows_by_stage["middle"]})),
        late_groups=tuple(sorted({row.metadata.group_id for row in rows_by_stage["late"]})),
        row_counts={stage: len(stage_rows) for stage, stage_rows in rows_by_stage.items()},
        group_counts={
            stage: len({row.metadata.group_id for row in stage_rows})
            for stage, stage_rows in rows_by_stage.items()
        },
        time_ranges=time_ranges,
        group_overlap=_cross_overlap(_identity_sets(rows, "group_id")),
        source_overlap=_cross_overlap(_identity_sets(rows, "source_file")),
        session_overlap=_cross_overlap(_identity_sets(rows, "capture_session_id")),
        scenario_overlap=_cross_overlap(_identity_sets(rows, "scenario_id")),
        future_data_used_for_fit=False,
        historical_test_reused=False,
    )
    return ControlledExperimentDataset(rows=rows, manifest=manifest, split_manifest=split)


def build_parameter_shift_partition(
    partition: ExperimentPartition,
    shift: ParameterShiftDefinition,
) -> ExperimentPartition:
    """Apply one fixed, bounded feature-space change to independent cloned groups."""

    names = feature_names()
    shifted: list[CanonicalDatasetRow] = []
    for row in partition.rows:
        values = dict(zip(names, row.features.values, strict=True))
        if shift.axis == "flow_duration":
            for name in (
                "flow_duration",
                "mean_inter_arrival_time",
                "std_inter_arrival_time",
                "min_inter_arrival_time",
                "max_inter_arrival_time",
                "median_inter_arrival_time",
                "iat_q25",
                "iat_q75",
                "forward_mean_iat",
                "backward_mean_iat",
            ):
                values[name] *= shift.factor
            values["packets_per_second"] /= shift.factor
            values["bytes_per_second"] /= shift.factor
        elif shift.axis == "packet_rate":
            values["packets_per_second"] *= shift.factor
            values["bytes_per_second"] *= shift.factor
            values["connection_burst_score"] = min(
                1.0, values["connection_burst_score"] * shift.factor
            )
        elif shift.axis == "packet_size_pattern":
            for name in (
                "total_bytes",
                "forward_bytes",
                "backward_bytes",
                "mean_packet_size",
                "std_packet_size",
                "min_packet_size",
                "max_packet_size",
                "median_packet_size",
                "packet_size_q25",
                "packet_size_q75",
                "forward_mean_packet_size",
                "backward_mean_packet_size",
                "bytes_per_second",
            ):
                scaled = values[name] * shift.factor
                values[name] = round(scaled) if name.endswith("bytes") else scaled
        else:
            values["connection_burst_score"] = min(
                1.0, values["connection_burst_score"] * shift.factor
            )
        group_id = f"{row.metadata.group_id}--{shift.shift_id}"
        metadata_payload = row.metadata.model_dump()
        metadata_payload.update(
            {
                "record_id": f"{row.metadata.record_id}--{shift.shift_id}",
                "source_file": f"{group_id}.flow",
                "source_file_checksum": hashlib.sha256(group_id.encode()).hexdigest(),
                "capture_session_id": f"capture-{group_id}",
                "scenario_id": f"scenario-{group_id}",
                "group_id": group_id,
                "provenance": {
                    **row.metadata.provenance,
                    "parameter_shift": shift.shift_id,
                    "shift_axis": shift.axis,
                    "shift_factor": str(shift.factor),
                },
            }
        )
        shifted.append(
            CanonicalDatasetRow(
                canonical_schema_version=row.canonical_schema_version,
                metadata=CanonicalMetadata.model_validate(metadata_payload),
                features=CanonicalFeatureVector(
                    schema_version=row.features.schema_version,
                    names=names,
                    values=tuple(values[name] for name in names),
                ),
                labels=row.labels,
            )
        )
    result = ExperimentPartition(f"parameter-shift-{shift.shift_id}", tuple(shifted))
    _require_isolated(partition.rows, result.rows)
    return result


def parameter_shift_features(axis: str) -> tuple[str, ...]:
    """Return the pre-registered evidence features for one shift axis."""

    try:
        return _SHIFT_FEATURES[axis]
    except KeyError as exc:
        raise FusionDatasetError("parameter-shift axis is unsupported") from exc
