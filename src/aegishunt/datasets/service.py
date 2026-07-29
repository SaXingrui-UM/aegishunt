"""Offline-first orchestration for registry, conversion, quality, and splitting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from pathlib import Path

from aegishunt.config import DatasetSettings
from aegishunt.datasets.artifacts import (
    build_dataset_manifest,
    write_report_bundle,
    write_split_datasets,
)
from aegishunt.datasets.conversion import convert_flow_csv
from aegishunt.datasets.demo import (
    BASE_TIME,
    DEFAULT_GROUPS_PER_PATTERN,
    DEMO_DATASET_ID,
    DEMO_PATTERNS,
    ROWS_PER_GROUP,
    build_controlled_demo,
    demo_generation_config,
)
from aegishunt.datasets.download import download_dataset_file
from aegishunt.datasets.errors import DatasetConversionError, DatasetQualityError
from aegishunt.datasets.io import read_canonical_jsonl, sha256_file, write_canonical_jsonl
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.leakage import analyze_leakage
from aegishunt.datasets.quality import analyze_quality
from aegishunt.datasets.registry import DatasetRegistry
from aegishunt.datasets.reports import (
    DatasetManifest,
    LeakageReport,
    QualityReport,
    SplitManifest,
)
from aegishunt.datasets.schemas import CanonicalDatasetRow, DatasetDefinition
from aegishunt.datasets.split import group_aware_split


@dataclass(frozen=True, slots=True)
class DatasetWorkflowResult:
    """Sanitized paths and validated reports from a complete offline workflow."""

    dataset_id: str
    row_count: int
    group_count: int
    data_files: tuple[Path, ...]
    report_files: tuple[Path, ...]
    quality_report: QualityReport
    leakage_report: LeakageReport
    split_manifest: SplitManifest
    dataset_manifest: DatasetManifest


class DatasetService:
    """Coordinate Phase 4 operations while preserving raw/interim/processed boundaries."""

    def __init__(self, settings: DatasetSettings) -> None:
        self._settings = settings
        self._registry = DatasetRegistry.load(settings.registry_path)

    def list(self) -> tuple[DatasetDefinition, ...]:
        return self._registry.list()

    def describe(self, dataset_id: str) -> DatasetDefinition:
        return self._registry.describe(dataset_id)

    def _label_mapper(self, definition: DatasetDefinition) -> LabelMapper:
        mapping_name = Path(definition.label_schema).name
        mapper = LabelMapper.load(self._settings.label_mapping_root / mapping_name)
        if mapper.dataset_id != definition.dataset_id:
            raise DatasetConversionError("label mapping dataset ID does not match the registry")
        return mapper

    def download(self, dataset_id: str) -> tuple[Path, str]:
        """Download only registry entries explicitly marked automatic."""

        definition = self.describe(dataset_id)
        return download_dataset_file(
            definition,
            self._settings.raw_root,
            max_bytes=self._settings.max_download_bytes,
        )

    def verify_manual_file(self, dataset_id: str, path: Path) -> tuple[str, int]:
        """Verify one operator-provided raw file without copying or modifying it."""

        definition = self.describe(dataset_id)
        try:
            path.resolve().relative_to(self._settings.raw_root.resolve())
        except ValueError as exc:
            raise DatasetQualityError("manual file must be inside the configured raw root") from exc
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise DatasetQualityError("manual dataset file is unavailable") from exc
        if not path.is_file() or size <= 0:
            raise DatasetQualityError("manual dataset input must be a non-empty regular file")
        if size > self._settings.max_download_bytes:
            raise DatasetQualityError("manual dataset file exceeds the configured limit")
        expected = next(
            (
                expected.checksum_sha256
                for expected in definition.expected_files
                if expected.filename == path.name and expected.checksum_sha256 is not None
            ),
            definition.expected_checksum or definition.locally_computed_checksum,
        )
        checksum = sha256_file(path)
        if expected is not None and checksum != expected:
            raise DatasetQualityError("manual dataset file checksum does not match")
        return checksum, size

    def convert_csv(
        self,
        dataset_id: str,
        raw_path: Path,
        output_path: Path,
        *,
        source_access_date: date,
    ) -> tuple[int, str]:
        """Convert an exact Phase 3 raw flow export without changing the source."""

        definition = self.describe(dataset_id)
        if definition.conversion_status == "blocked":
            raise DatasetConversionError("dataset conversion is blocked by the registry")
        rows = convert_flow_csv(
            raw_path,
            dataset_id=definition.dataset_id,
            dataset_version=definition.version,
            label_mapper=self._label_mapper(definition),
            source_access_date=source_access_date,
        )
        checksum = write_canonical_jsonl(rows, output_path)
        return len(rows), checksum

    def validate(self, path: Path) -> tuple[CanonicalDatasetRow, ...]:
        """Load and validate all canonical rows without network activity."""

        return read_canonical_jsonl(path)

    def quality(self, path: Path) -> QualityReport:
        """Analyze one existing canonical dataset."""

        return analyze_quality(
            self.validate(path),
            near_duplicate_tolerance=self._settings.near_duplicate_tolerance,
        )

    def _complete_workflow(
        self,
        definition: DatasetDefinition,
        rows: tuple[CanonicalDatasetRow, ...],
        *,
        data_root: Path,
        report_root: Path,
        seed: int,
        generation_config: dict[str, object],
        creation_timestamp: datetime,
        label_mapping_version: str,
    ) -> DatasetWorkflowResult:
        if definition.conversion_status == "blocked":
            raise DatasetQualityError("dataset conversion is blocked by the registry")
        identities = {
            (row.metadata.dataset_id, row.metadata.dataset_version) for row in rows
        }
        if identities != {(definition.dataset_id, definition.version)}:
            raise DatasetQualityError("canonical dataset identity does not match the registry")
        quality_report = analyze_quality(
            rows,
            near_duplicate_tolerance=self._settings.near_duplicate_tolerance,
        )
        if quality_report.status == "fail":
            raise DatasetQualityError("dataset quality gates failed")
        assignments, split_manifest = group_aware_split(
            rows,
            seed=seed,
            train_ratio=self._settings.train_ratio,
            validation_ratio=self._settings.validation_ratio,
            test_ratio=self._settings.test_ratio,
        )
        leakage_report = analyze_leakage(
            assignments,
            near_duplicate_tolerance=self._settings.near_duplicate_tolerance,
        )
        if leakage_report.status == "fail":
            raise DatasetQualityError("dataset leakage gates failed")

        canonical_path = data_root / "canonical.jsonl"
        expected_outputs = (
            canonical_path,
            *(data_root / f"{split}.jsonl" for split in ("train", "validation", "test")),
            *(report_root / name for name in (
                "quality_report.json",
                "leakage_report.json",
                "split_manifest.json",
                "dataset_manifest.json",
                "feature_statistics.csv",
                "class_distribution.csv",
            )),
        )
        temporary_outputs = tuple(
            path.with_name(f".{path.name}.tmp") for path in expected_outputs[:4]
        )
        if any(path.exists() for path in (*expected_outputs, *temporary_outputs)):
            raise DatasetQualityError("dataset workflow output already exists")
        write_canonical_jsonl(rows, canonical_path)
        split_paths = write_split_datasets(assignments, data_root)
        manifest = build_dataset_manifest(
            definition,
            rows=rows,
            canonical_path=canonical_path,
            split_paths=split_paths,
            quality_report=quality_report,
            generation_config=generation_config,
            random_seed=seed,
            creation_timestamp=creation_timestamp,
            label_mapping_version=label_mapping_version,
        )
        report_files = write_report_bundle(
            report_root,
            quality_report=quality_report,
            leakage_report=leakage_report,
            split_manifest=split_manifest,
            dataset_manifest=manifest,
            rows=rows,
            assignments=assignments,
        )
        return DatasetWorkflowResult(
            dataset_id=definition.dataset_id,
            row_count=len(rows),
            group_count=len({row.metadata.group_id for row in rows}),
            data_files=(canonical_path, *split_paths.values()),
            report_files=report_files,
            quality_report=quality_report,
            leakage_report=leakage_report,
            split_manifest=split_manifest,
            dataset_manifest=manifest,
        )

    def build_demo(
        self,
        *,
        data_root: Path | None = None,
        report_root: Path | None = None,
        seed: int | None = None,
        groups_per_pattern: int = DEFAULT_GROUPS_PER_PATTERN,
    ) -> DatasetWorkflowResult:
        """Run the complete controlled synthetic workflow without public network access."""

        definition = self.describe(DEMO_DATASET_ID)
        mapper = self._label_mapper(definition)
        selected_seed = self._settings.demo_seed if seed is None else seed
        selected_data_root = data_root or (
            self._settings.processed_root / definition.dataset_id / definition.version
        )
        selected_report_root = report_root or (
            self._settings.reports_root / definition.dataset_id / definition.version
        )
        rows = build_controlled_demo(
            seed=selected_seed,
            label_mapper=mapper,
            groups_per_pattern=groups_per_pattern,
        )
        return self._complete_workflow(
            definition,
            rows,
            data_root=selected_data_root,
            report_root=selected_report_root,
            seed=selected_seed,
            generation_config=demo_generation_config(selected_seed, groups_per_pattern),
            creation_timestamp=BASE_TIME,
            label_mapping_version=mapper.version,
        )

    def split_existing(
        self,
        path: Path,
        *,
        data_root: Path,
        report_root: Path,
        seed: int | None = None,
    ) -> DatasetWorkflowResult:
        """Regenerate a complete, fail-closed split bundle from canonical rows."""

        rows = self.validate(path)
        selected_seed = self._settings.demo_seed if seed is None else seed
        dataset_ids = {row.metadata.dataset_id for row in rows}
        if len(dataset_ids) != 1:
            raise DatasetQualityError("canonical input contains multiple dataset IDs")
        definition = self.describe(next(iter(dataset_ids)))
        identities = {
            (row.metadata.dataset_id, row.metadata.dataset_version) for row in rows
        }
        if identities != {(definition.dataset_id, definition.version)}:
            raise DatasetQualityError("canonical dataset identity does not match the registry")
        if definition.dataset_id == DEMO_DATASET_ID:
            rows_per_pattern = len(DEMO_PATTERNS) * ROWS_PER_GROUP
            groups_per_pattern, remainder = divmod(len(rows), rows_per_pattern)
            if remainder or groups_per_pattern < DEFAULT_GROUPS_PER_PATTERN:
                raise DatasetQualityError(
                    "controlled-demo rows do not match a registered generator shape"
                )
            expected = build_controlled_demo(
                seed=self._settings.demo_seed,
                label_mapper=self._label_mapper(definition),
                groups_per_pattern=groups_per_pattern,
            )
            if rows != expected:
                raise DatasetQualityError(
                    "controlled-demo provenance does not match the registered generator"
                )
        access_dates = {row.metadata.source_access_date for row in rows}
        creation_timestamp = datetime.combine(max(access_dates), time.min, tzinfo=UTC)
        mapping_versions = {row.labels.label_mapping_version for row in rows}
        if len(mapping_versions) != 1:
            raise DatasetQualityError("canonical input contains multiple label mapping versions")
        return self._complete_workflow(
            definition,
            rows,
            data_root=data_root,
            report_root=report_root,
            seed=selected_seed,
            generation_config={
                "source": "existing-canonical-jsonl",
                "input_filename": path.name,
            },
            creation_timestamp=creation_timestamp,
            label_mapping_version=next(iter(mapping_versions)),
        )
