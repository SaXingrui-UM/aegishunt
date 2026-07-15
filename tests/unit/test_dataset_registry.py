"""Dataset registry, schema, configuration, and label mapping tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from aegishunt.config import DatasetSettings
from aegishunt.datasets.errors import (
    DatasetConversionError,
    DatasetNotFoundError,
    DatasetRegistryError,
)
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.registry import DatasetRegistry
from aegishunt.datasets.schemas import DatasetDefinition, DatasetRegistryDocument
from tests.fixtures.datasets import LABEL_ROOT, REGISTRY_PATH


def _definition(**updates: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "dataset_id": "example-dataset",
        "name": "Example",
        "version": "1",
        "dataset_type": "public_benchmark",
        "source_url": "https://example.invalid/data.csv",
        "official_page": "https://example.invalid/official",
        "provider": "Example provider",
        "license_name": "Academic",
        "license_url": "https://example.invalid/license",
        "academic_use_status": "permitted",
        "expected_format": ["csv"],
        "expected_files": [],
        "expected_checksum": None,
        "locally_computed_checksum": None,
        "raw_schema_reference": "official schema",
        "canonical_schema_version": "1.0.0",
        "feature_schema_version": "1.0.0",
        "label_schema": "mapping.yaml",
        "group_fields": ["source_file"],
        "download_status": "automatic",
        "conversion_status": "supported",
        "known_limitations": [],
        "citation": "Example citation",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
        "updated_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    payload.update(updates)
    return payload


def test_project_registry_lists_stable_serializable_definitions() -> None:
    registry = DatasetRegistry.load(REGISTRY_PATH)

    identifiers = [entry.dataset_id for entry in registry.list()]

    assert identifiers == sorted(identifiers)
    assert identifiers == [
        "aegishunt-controlled-demo",
        "cic-ids2017",
        "cse-cic-ids2018",
        "ton-iot",
        "unsw-nb15",
    ]
    assert registry.describe("CSE-CIC-IDS2018").download_status == "manual_required"
    assert "aegishunt-controlled-demo" in registry.to_json()


def test_registry_rejects_unknown_id_and_invalid_document(tmp_path: Path) -> None:
    registry = DatasetRegistry.load(REGISTRY_PATH)
    with pytest.raises(DatasetNotFoundError, match="not registered"):
        registry.describe("missing")

    invalid = tmp_path / "registry.yaml"
    invalid.write_text("registry_schema_version: 1.0.0\ndatasets: not-a-list\n", encoding="utf-8")
    with pytest.raises(DatasetRegistryError, match="validation failed"):
        DatasetRegistry.load(invalid)


def test_registry_rejects_invalid_yaml_and_missing_file(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.yaml"
    invalid.write_text("datasets: [", encoding="utf-8")
    with pytest.raises(DatasetRegistryError, match="YAML is invalid"):
        DatasetRegistry.load(invalid)
    with pytest.raises(DatasetRegistryError, match="unable to read"):
        DatasetRegistry.load(tmp_path / "missing.yaml")


def test_registry_contract_rejects_duplicates_and_invalid_license_metadata() -> None:
    definition = DatasetDefinition.model_validate(_definition())
    with pytest.raises(ValidationError, match="IDs must be unique"):
        DatasetRegistryDocument(
            registry_schema_version="1.0.0",
            datasets=(definition, definition),
        )
    with pytest.raises(ValidationError, match="license evidence"):
        DatasetDefinition.model_validate(_definition(license_url=None))
    with pytest.raises(ValidationError, match="kebab-case"):
        DatasetDefinition.model_validate(_definition(dataset_id="BAD ID"))
    with pytest.raises(ValidationError, match="source URL"):
        DatasetDefinition.model_validate(_definition(source_url=None))


def test_dataset_settings_validate_ratios_and_environment_paths() -> None:
    settings = DatasetSettings(train_ratio=0.5, validation_ratio=0.25, test_ratio=0.25)
    assert settings.registry_path == Path("configs/datasets/registry.yaml")
    with pytest.raises(ValidationError, match="sum to 1.0"):
        DatasetSettings(train_ratio=0.5, validation_ratio=0.3, test_ratio=0.3)


def test_label_mapper_normalizes_aliases_and_fails_unknown() -> None:
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")

    benign = mapper.map("  NORMAL ")
    attack = mapper.map("Scan")

    assert benign.binary_label == 0
    assert benign.original_label == "  NORMAL "
    assert attack.attack_family == "reconnaissance"
    with pytest.raises(DatasetConversionError, match="unmapped label"):
        mapper.map("new-unreviewed-label")


def test_label_mapper_rejects_invalid_mapping(tmp_path: Path) -> None:
    path = tmp_path / "mapping.yaml"
    path.write_text(yaml.safe_dump({"dataset_id": "x"}), encoding="utf-8")
    with pytest.raises(DatasetConversionError, match="validation failed"):
        LabelMapper.load(path)
