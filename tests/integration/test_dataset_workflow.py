"""Phase 4 offline workflow, report, restart, and reproducibility integration tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegishunt.config import DatasetSettings
from aegishunt.datasets.errors import DatasetQualityError
from aegishunt.datasets.io import read_canonical_jsonl
from aegishunt.datasets.reports import DatasetManifest, LeakageReport, QualityReport, SplitManifest
from aegishunt.datasets.service import DatasetService
from tests.fixtures.datasets import LABEL_ROOT, REGISTRY_PATH


def _settings(tmp_path: Path) -> DatasetSettings:
    return DatasetSettings(
        registry_path=REGISTRY_PATH,
        label_mapping_root=LABEL_ROOT,
        raw_root=tmp_path / "raw",
        interim_root=tmp_path / "interim",
        processed_root=tmp_path / "processed",
        reports_root=tmp_path / "reports",
        demo_seed=4_204,
    )


def _contents(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def test_controlled_demo_full_workflow_outputs_required_artifacts(tmp_path: Path) -> None:
    service = DatasetService(_settings(tmp_path))
    data_root = tmp_path / "bundle" / "data"
    report_root = tmp_path / "bundle" / "reports"

    result = service.build_demo(data_root=data_root, report_root=report_root)

    assert result.row_count == 48
    assert result.group_count == 24
    assert result.quality_report.status == "pass"
    assert result.leakage_report.status == "pass"
    assert result.split_manifest.frozen_test is True
    assert {path.name for path in result.data_files} == {
        "canonical.jsonl",
        "train.jsonl",
        "validation.jsonl",
        "test.jsonl",
    }
    assert {path.name for path in result.report_files} == {
        "dataset_manifest.json",
        "split_manifest.json",
        "leakage_report.json",
        "quality_report.json",
        "class_distribution.csv",
        "feature_statistics.csv",
    }
    assert sum(result.split_manifest.row_counts.values()) == result.row_count
    assert len(read_canonical_jsonl(data_root / "canonical.jsonl")) == 48

    DatasetManifest.model_validate_json(
        (report_root / "dataset_manifest.json").read_text(encoding="utf-8")
    )
    SplitManifest.model_validate_json(
        (report_root / "split_manifest.json").read_text(encoding="utf-8")
    )
    LeakageReport.model_validate_json(
        (report_root / "leakage_report.json").read_text(encoding="utf-8")
    )
    QualityReport.model_validate_json(
        (report_root / "quality_report.json").read_text(encoding="utf-8")
    )
    for report in result.report_files:
        assert str(tmp_path) not in report.read_text(encoding="utf-8")


def test_workflow_is_byte_reproducible_after_service_restart(tmp_path: Path) -> None:
    first_service = DatasetService(_settings(tmp_path))
    first_root = tmp_path / "first"
    first_service.build_demo(
        data_root=first_root / "data",
        report_root=first_root / "reports",
    )

    restarted_service = DatasetService(_settings(tmp_path))
    second_root = tmp_path / "second"
    restarted_service.build_demo(
        data_root=second_root / "data",
        report_root=second_root / "reports",
    )

    assert _contents(first_root) == _contents(second_root)
    reopened = restarted_service.validate(second_root / "data" / "canonical.jsonl")
    assert len(reopened) == 48
    assert restarted_service.quality(second_root / "data" / "canonical.jsonl").status == "pass"


def test_existing_canonical_data_can_be_resplit_without_row_random_fallback(
    tmp_path: Path,
) -> None:
    service = DatasetService(_settings(tmp_path))
    initial = tmp_path / "initial"
    service.build_demo(data_root=initial / "data", report_root=initial / "reports")

    result = service.split_existing(
        initial / "data" / "canonical.jsonl",
        data_root=tmp_path / "resplit" / "data",
        report_root=tmp_path / "resplit" / "reports",
        seed=9_001,
    )

    assert result.split_manifest.split_strategy.startswith("deterministic group hash")
    assert result.leakage_report.status == "pass"
    assert result.dataset_manifest.generation_config == {
        "source": "existing-canonical-jsonl",
        "input_filename": "canonical.jsonl",
    }


def test_existing_split_uses_configured_seed_when_not_overridden(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = DatasetService(settings)
    initial = tmp_path / "initial"
    service.build_demo(data_root=initial / "data", report_root=initial / "reports")

    result = service.split_existing(
        initial / "data" / "canonical.jsonl",
        data_root=tmp_path / "resplit" / "data",
        report_root=tmp_path / "resplit" / "reports",
    )

    assert result.split_manifest.random_seed == settings.demo_seed


def test_manifest_contains_provenance_versions_without_local_paths(tmp_path: Path) -> None:
    service = DatasetService(_settings(tmp_path))
    result = service.build_demo(
        data_root=tmp_path / "data",
        report_root=tmp_path / "reports",
    )
    manifest = result.dataset_manifest

    assert manifest.dataset_type == "controlled_demo"
    assert manifest.feature_schema_version == "1.0.0"
    assert manifest.canonical_schema_version == "1.0.0"
    assert manifest.label_mapping_version == "1.0.0"
    assert manifest.generation_config["network_access"] is False
    assert manifest.generation_config["external_target"] is False
    serialized = json.dumps(manifest.model_dump(mode="json"), sort_keys=True)
    assert str(tmp_path) not in serialized


def test_manual_provider_file_verification_is_bounded_to_raw_root(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    service = DatasetService(settings)
    manual = settings.raw_root / "cse-cic-ids2018" / "2018" / "capture.pcap"
    manual.parent.mkdir(parents=True)
    manual.write_bytes(b"operator-acquired-placeholder-for-verification")

    checksum, size = service.verify_manual_file("cse-cic-ids2018", manual)

    assert len(checksum) == 64
    assert size == manual.stat().st_size
    outside = tmp_path / "outside.pcap"
    outside.write_bytes(b"outside")
    with pytest.raises(DatasetQualityError, match="inside the configured raw root"):
        service.verify_manual_file("cse-cic-ids2018", outside)
