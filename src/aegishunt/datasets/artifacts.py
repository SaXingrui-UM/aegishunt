"""Deterministic report, manifest, and partition artifact writers."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel

from aegishunt.datasets.errors import DatasetQualityError
from aegishunt.datasets.io import sha256_file, write_canonical_jsonl
from aegishunt.datasets.quality import write_class_distribution, write_feature_statistics
from aegishunt.datasets.reports import (
    DatasetManifest,
    LeakageReport,
    QualityReport,
    SplitManifest,
)
from aegishunt.datasets.schemas import (
    CANONICAL_SCHEMA_VERSION,
    CONVERSION_VERSION,
    CanonicalDatasetRow,
    DatasetDefinition,
    SplitAssignment,
)
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION
from aegishunt.metadata import __version__

MANIFEST_SCHEMA_VERSION = "1.0.0"


def safe_git_sha() -> str | None:
    """Return HEAD when safely available without surfacing paths or stderr."""

    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = result.stdout.strip().lower()
    return sha if result.returncode == 0 and len(sha) == 40 else None


def write_json_model(model: BaseModel, path: Path) -> None:
    """Write one validated model without overwriting an earlier artifact."""

    if path.exists():
        raise DatasetQualityError("report output already exists")
    payload = model.model_dump(mode="json")
    serialized = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as destination:
            destination.write(serialized)
    except OSError as exc:
        raise DatasetQualityError("unable to write dataset report") from exc


def build_dataset_manifest(
    definition: DatasetDefinition,
    *,
    rows: Sequence[CanonicalDatasetRow],
    canonical_path: Path,
    split_paths: dict[str, Path],
    quality_report: QualityReport,
    generation_config: dict[str, object],
    random_seed: int,
    creation_timestamp: datetime,
    label_mapping_version: str,
) -> DatasetManifest:
    """Build a sanitized manifest from generated and verified artifacts."""

    source = (
        str(definition.official_page)
        if definition.official_page is not None
        else "controlled-offline-generator"
    )
    processed_paths = {"canonical.jsonl": canonical_path, **split_paths}
    return DatasetManifest(
        manifest_schema_version=MANIFEST_SCHEMA_VERSION,
        dataset_id=definition.dataset_id,
        dataset_version=definition.version,
        dataset_type=definition.dataset_type,
        source=source,
        provider=definition.provider,
        license_name=definition.license_name,
        access_date=creation_timestamp.date().isoformat(),
        raw_files=(),
        raw_checksums={},
        processed_files=tuple(sorted(processed_paths)),
        processed_checksums={
            name: sha256_file(path) for name, path in sorted(processed_paths.items())
        },
        row_count=len(rows),
        group_count=len({row.metadata.group_id for row in rows}),
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        canonical_schema_version=CANONICAL_SCHEMA_VERSION,
        label_mapping_version=label_mapping_version,
        conversion_version=CONVERSION_VERSION,
        generation_config=generation_config,
        random_seed=random_seed,
        quality_status=quality_report.status,
        known_limitations=definition.known_limitations,
        creation_timestamp=creation_timestamp,
        tool_version=__version__,
        git_commit_sha=safe_git_sha(),
    )


def write_split_datasets(
    assignments: Sequence[SplitAssignment],
    output_root: Path,
) -> dict[str, Path]:
    """Write each deterministic partition under a caller-controlled processed root."""

    paths: dict[str, Path] = {}
    for split in ("train", "validation", "test"):
        path = output_root / f"{split}.jsonl"
        write_canonical_jsonl(
            (assignment.row for assignment in assignments if assignment.split == split),
            path,
        )
        paths[f"{split}.jsonl"] = path
    return paths


def write_report_bundle(
    report_root: Path,
    *,
    quality_report: QualityReport,
    leakage_report: LeakageReport,
    split_manifest: SplitManifest,
    dataset_manifest: DatasetManifest,
    rows: Sequence[CanonicalDatasetRow],
    assignments: Sequence[SplitAssignment],
) -> tuple[Path, ...]:
    """Write all Phase 4 required machine-readable reports."""

    quality_path = report_root / "quality_report.json"
    leakage_path = report_root / "leakage_report.json"
    split_path = report_root / "split_manifest.json"
    dataset_path = report_root / "dataset_manifest.json"
    feature_path = report_root / "feature_statistics.csv"
    class_path = report_root / "class_distribution.csv"
    write_json_model(quality_report, quality_path)
    write_json_model(leakage_report, leakage_path)
    write_json_model(split_manifest, split_path)
    write_json_model(dataset_manifest, dataset_path)
    write_feature_statistics(rows, feature_path)
    rows_by_split = {
        split: tuple(assignment.row for assignment in assignments if assignment.split == split)
        for split in ("train", "validation", "test")
    }
    write_class_distribution(rows_by_split, class_path)
    return (quality_path, leakage_path, split_path, dataset_path, feature_path, class_path)
