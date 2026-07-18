"""Fail-closed Phase 4 manifest and partition loading for supervised work."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, TypeVar

import numpy as np
from pydantic import BaseModel, ValidationError

from aegishunt.datasets.io import read_canonical_jsonl, sha256_file
from aegishunt.datasets.reports import DatasetManifest, LeakageReport, QualityReport, SplitManifest
from aegishunt.datasets.schemas import CanonicalDatasetRow
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.supervised.contracts import ModelSelectionRecord
from aegishunt.ml.supervised.errors import DatasetGateError

if TYPE_CHECKING:
    from numpy.typing import NDArray

REQUIRED_DATA_FILES = ("canonical.jsonl", "train.jsonl", "validation.jsonl", "test.jsonl")
REQUIRED_REPORT_FILES = (
    "dataset_manifest.json",
    "split_manifest.json",
    "quality_report.json",
    "leakage_report.json",
)
ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class PartitionData:
    """Validated rows plus model arrays and non-feature grouping evidence."""

    name: str
    rows: tuple[CanonicalDatasetRow, ...]

    @property
    def features(self) -> NDArray[np.float64]:
        return np.asarray([row.features.values for row in self.rows], dtype=np.float64)

    @property
    def labels(self) -> NDArray[np.int64]:
        values = [row.labels.binary_label for row in self.rows]
        if any(value is None for value in values):
            raise DatasetGateError("supervised partition contains an unmapped label")
        return np.asarray(values, dtype=np.int64)

    @property
    def groups(self) -> NDArray[np.str_]:
        return np.asarray([row.metadata.group_id for row in self.rows], dtype=np.str_)

    def metadata_values(self, attribute: str) -> tuple[str, ...]:
        return tuple(str(getattr(row.metadata, attribute)) for row in self.rows)

    @property
    def class_distribution(self) -> dict[str, int]:
        return dict(sorted(Counter(str(value) for value in self.labels.tolist()).items()))


@dataclass(frozen=True, slots=True)
class DatasetEvidence:
    """Checksummed Phase 4 evidence that binds every later experiment artifact."""

    dataset_manifest: DatasetManifest
    split_manifest: SplitManifest
    quality_report: QualityReport
    leakage_report: LeakageReport
    dataset_manifest_checksum: str
    split_manifest_checksum: str
    data_root: Path
    report_root: Path


@dataclass(frozen=True, slots=True)
class TrainingValidationData:
    evidence: DatasetEvidence
    train: PartitionData
    validation: PartitionData


class SupervisedDatasetGate:
    """Validate Phase 4 artifacts before any model or frozen-test access."""

    def __init__(self, data_root: Path, report_root: Path) -> None:
        self._data_root = data_root
        self._report_root = report_root
        self._evidence = self._load_evidence()

    @property
    def evidence(self) -> DatasetEvidence:
        return self._evidence

    @staticmethod
    def _read_model(path: Path, model_type: type[ModelT]) -> ModelT:
        try:
            payload = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise DatasetGateError("required Phase 4 report is unavailable") from exc
        try:
            return model_type.model_validate_json(payload)
        except ValidationError as exc:
            raise DatasetGateError("required Phase 4 report is invalid") from exc

    def _require_files(self) -> None:
        if any(not (self._data_root / name).is_file() for name in REQUIRED_DATA_FILES):
            raise DatasetGateError("required Phase 4 dataset partition is unavailable")
        if any(not (self._report_root / name).is_file() for name in REQUIRED_REPORT_FILES):
            raise DatasetGateError("required Phase 4 evidence report is unavailable")

    def _load_evidence(self) -> DatasetEvidence:
        self._require_files()
        dataset_path = self._report_root / "dataset_manifest.json"
        split_path = self._report_root / "split_manifest.json"
        dataset_manifest = self._read_model(dataset_path, DatasetManifest)
        split_manifest = self._read_model(split_path, SplitManifest)
        quality_report = self._read_model(
            self._report_root / "quality_report.json", QualityReport
        )
        leakage_report = self._read_model(
            self._report_root / "leakage_report.json", LeakageReport
        )
        self._validate_evidence(dataset_manifest, split_manifest, quality_report, leakage_report)
        return DatasetEvidence(
            dataset_manifest=dataset_manifest,
            split_manifest=split_manifest,
            quality_report=quality_report,
            leakage_report=leakage_report,
            dataset_manifest_checksum=sha256_file(dataset_path),
            split_manifest_checksum=sha256_file(split_path),
            data_root=self._data_root,
            report_root=self._report_root,
        )

    def _validate_evidence(
        self,
        dataset: DatasetManifest,
        split: SplitManifest,
        quality: QualityReport,
        leakage: LeakageReport,
    ) -> None:
        if dataset.quality_status != "pass" or quality.status != "pass":
            raise DatasetGateError("Phase 4 quality gate did not pass")
        if dataset.registry_conversion_status != "supported":
            raise DatasetGateError("dataset conversion is not approved for supervised training")
        if leakage.status != "pass" or any(
            (
                leakage.group_overlap,
                leakage.source_file_overlap,
                leakage.session_overlap,
                leakage.scenario_overlap,
                leakage.exact_duplicate_overlap,
                leakage.near_duplicate_overlap,
                leakage.label_derived_features,
                leakage.suspicious_metadata,
                leakage.filename_leakage,
                leakage.record_id_leakage,
            )
        ):
            raise DatasetGateError("Phase 4 leakage gate did not pass")
        if not split.frozen_test:
            raise DatasetGateError("Phase 4 test partition is not frozen")
        if split.overlap_validation_result != "pass" or split.source_file_overlap_result != "pass":
            raise DatasetGateError("Phase 4 split overlap validation did not pass")
        if dataset.feature_schema_version != FEATURE_SCHEMA_VERSION:
            raise DatasetGateError("dataset feature schema is incompatible with Phase 3")
        schema_versions = {
            dataset.feature_schema_version,
            split.feature_schema_version,
            quality.feature_schema_version,
        }
        if schema_versions != {FEATURE_SCHEMA_VERSION}:
            raise DatasetGateError("Phase 4 evidence feature schemas are inconsistent")
        canonical_versions = {
            dataset.canonical_schema_version,
            split.canonical_schema_version,
            quality.canonical_schema_version,
        }
        if len(canonical_versions) != 1:
            raise DatasetGateError("Phase 4 evidence canonical schemas are inconsistent")
        if (dataset.dataset_id, dataset.dataset_version) != (
            split.dataset_id,
            split.dataset_version,
        ):
            raise DatasetGateError("dataset and split manifest identities differ")
        if (quality.row_count, quality.group_count) != (
            dataset.row_count,
            dataset.group_count,
        ):
            raise DatasetGateError("quality report counts differ from the dataset manifest")
        expected_partitions = {"train", "validation", "test"}
        count_sections = (set(split.row_counts), set(split.group_counts))
        if any(section != expected_partitions for section in count_sections):
            raise DatasetGateError("split manifest partition counts are incomplete")
        if sum(split.row_counts.values()) != dataset.row_count:
            raise DatasetGateError("split row counts differ from the dataset manifest")
        if sum(split.group_counts.values()) != dataset.group_count:
            raise DatasetGateError("split group counts differ from the dataset manifest")
        declared_groups = {
            "train": split.train_groups,
            "validation": split.validation_groups,
            "test": split.test_groups,
        }
        if any(
            len(declared_groups[name]) != split.group_counts[name]
            for name in expected_partitions
        ):
            raise DatasetGateError("split group inventory differs from declared counts")
        combined_classes = Counter[str]()
        for distribution in split.class_distributions.values():
            combined_classes.update(distribution)
        if dict(sorted(combined_classes.items())) != quality.binary_class_distribution:
            raise DatasetGateError("split class distributions differ from the quality report")
        expected_names = set(REQUIRED_DATA_FILES)
        if set(dataset.processed_files) != expected_names:
            raise DatasetGateError("dataset manifest partition inventory is incomplete")
        if set(dataset.processed_checksums) != expected_names:
            raise DatasetGateError("dataset manifest checksum inventory is incomplete")
        for filename, expected_checksum in dataset.processed_checksums.items():
            path = PurePosixPath(filename)
            if path.is_absolute() or ".." in path.parts or len(path.parts) != 1:
                raise DatasetGateError("dataset manifest contains an unsafe artifact name")
            checksum_matches = sha256_file(self._data_root / filename) == expected_checksum
            if filename not in expected_names or not checksum_matches:
                raise DatasetGateError("dataset artifact checksum mismatch")
        canonical_payload = (self._data_root / "canonical.jsonl").read_bytes().rstrip(b"\n")
        if hashlib.sha256(canonical_payload).hexdigest() != split.dataset_checksum:
            raise DatasetGateError("split manifest dataset checksum mismatch")
        group_sets = (
            set(split.train_groups),
            set(split.validation_groups),
            set(split.test_groups),
        )
        overlaps = (
            left & right
            for index, left in enumerate(group_sets)
            for right in group_sets[index + 1 :]
        )
        if any(overlaps):
            raise DatasetGateError("Phase 4 split contains group overlap")

    def _load_partition(self, name: str, allowed_groups: tuple[str, ...]) -> PartitionData:
        try:
            rows = read_canonical_jsonl(self._data_root / f"{name}.jsonl")
        except (OSError, ValueError) as exc:
            raise DatasetGateError("supervised partition cannot be loaded") from exc
        if not rows:
            raise DatasetGateError("supervised partition is empty")
        allowed = set(allowed_groups)
        if {row.metadata.group_id for row in rows} != allowed:
            raise DatasetGateError("partition groups do not match the frozen split manifest")
        if any(row.features.names != feature_names() for row in rows):
            raise DatasetGateError("partition feature order does not match Phase 3")
        if any(row.features.schema_version != FEATURE_SCHEMA_VERSION for row in rows):
            raise DatasetGateError("partition feature schema does not match Phase 3")
        identities = {
            (row.metadata.dataset_id, row.metadata.dataset_version) for row in rows
        }
        manifest_identity = (
            self._evidence.dataset_manifest.dataset_id,
            self._evidence.dataset_manifest.dataset_version,
        )
        if identities != {manifest_identity}:
            raise DatasetGateError("partition dataset identity differs from its manifest")
        mapping_versions = {row.labels.label_mapping_version for row in rows}
        if mapping_versions != {self._evidence.dataset_manifest.label_mapping_version}:
            raise DatasetGateError("partition label mapping differs from its manifest")
        partition = PartitionData(name=name, rows=rows)
        if set(partition.class_distribution) != {"0", "1"}:
            raise DatasetGateError("supervised partition must contain both binary classes")
        split = self._evidence.split_manifest
        if len(rows) != split.row_counts[name]:
            raise DatasetGateError("partition row count differs from the split manifest")
        if len(set(partition.groups.tolist())) != split.group_counts[name]:
            raise DatasetGateError("partition group count differs from the split manifest")
        if partition.class_distribution != split.class_distributions[name]:
            raise DatasetGateError("partition class distribution differs from the split manifest")
        return partition

    @staticmethod
    def _require_identity_isolation(partitions: tuple[PartitionData, ...]) -> None:
        for attribute in ("group_id", "source_file", "capture_session_id", "scenario_id"):
            values = [set(partition.metadata_values(attribute)) for partition in partitions]
            overlaps = (
                left & right
                for index, left in enumerate(values)
                for right in values[index + 1 :]
            )
            if any(overlaps):
                raise DatasetGateError("supervised partitions violate identity isolation")

    def load_training_validation(self, *, cv_folds: int) -> TrainingValidationData:
        """Load train/validation only; frozen test content remains unread."""

        train = self._load_partition("train", self._evidence.split_manifest.train_groups)
        validation = self._load_partition(
            "validation", self._evidence.split_manifest.validation_groups
        )
        self._require_identity_isolation((train, validation))
        if len(set(train.groups.tolist())) < cv_folds:
            raise DatasetGateError("training groups are insufficient for configured CV folds")
        return TrainingValidationData(self._evidence, train, validation)

    def load_frozen_test(self, selection: ModelSelectionRecord) -> PartitionData:
        """Load test only after a selection record binds the exact Phase 4 evidence."""

        return self.load_frozen_test_for_contract(
            status=selection.status,
            test_data_accessed=selection.test_data_accessed,
            dataset_manifest_checksum=selection.dataset_manifest_checksum,
            split_manifest_checksum=selection.split_manifest_checksum,
        )

    def load_frozen_test_for_contract(
        self,
        *,
        status: str,
        test_data_accessed: bool,
        dataset_manifest_checksum: str,
        split_manifest_checksum: str,
    ) -> PartitionData:
        """Open frozen test rows for a checksummed, immutable model-selection contract."""

        if status != "frozen" or test_data_accessed is not False:
            raise DatasetGateError("model selection is not frozen before test access")
        if dataset_manifest_checksum != self._evidence.dataset_manifest_checksum:
            raise DatasetGateError("selection dataset manifest checksum mismatch")
        if split_manifest_checksum != self._evidence.split_manifest_checksum:
            raise DatasetGateError("selection split manifest checksum mismatch")
        test = self._load_partition("test", self._evidence.split_manifest.test_groups)
        train = self._load_partition("train", self._evidence.split_manifest.train_groups)
        validation = self._load_partition(
            "validation", self._evidence.split_manifest.validation_groups
        )
        self._require_identity_isolation((train, validation, test))
        return test
