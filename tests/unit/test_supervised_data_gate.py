"""Phase 4 evidence must fail closed before supervised fitting or test access."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.errors import DatasetGateError
from tests.fixtures.supervised import build_phase4_bundle


def _rewrite_json(path: Path, update: dict[str, object]) -> None:
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload.update(update)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_dataset_gate_loads_training_and_validation_without_test(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)

    dataset = SupervisedDatasetGate(data_root, report_root).load_training_validation(cv_folds=3)

    assert dataset.train.features.shape == (28, 43)
    assert dataset.validation.features.shape == (10, 43)
    assert dataset.train.class_distribution == {"0": 10, "1": 18}
    assert dataset.validation.class_distribution == {"0": 4, "1": 6}
    assert set(dataset.train.groups).isdisjoint(set(dataset.validation.groups))
    assert dataset.evidence.split_manifest.frozen_test is True


def test_dataset_gate_rejects_checksum_mismatch(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    with (data_root / "train.jsonl").open("a", encoding="utf-8") as destination:
        destination.write("tampered\n")

    with pytest.raises(DatasetGateError, match="checksum mismatch"):
        SupervisedDatasetGate(data_root, report_root)


def test_dataset_gate_rejects_failed_leakage_report(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    _rewrite_json(report_root / "leakage_report.json", {"status": "fail"})

    with pytest.raises(DatasetGateError, match="leakage gate"):
        SupervisedDatasetGate(data_root, report_root)


def test_dataset_gate_rejects_unfrozen_test(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    _rewrite_json(report_root / "split_manifest.json", {"frozen_test": False})

    with pytest.raises(DatasetGateError, match="not frozen"):
        SupervisedDatasetGate(data_root, report_root)


def test_dataset_gate_rejects_provisional_public_conversion(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    _rewrite_json(
        report_root / "dataset_manifest.json",
        {"registry_conversion_status": "provisional"},
    )

    with pytest.raises(DatasetGateError, match="not approved"):
        SupervisedDatasetGate(data_root, report_root)


def test_dataset_gate_rejects_missing_partition(tmp_path: Path) -> None:
    data_root, report_root = build_phase4_bundle(tmp_path)
    (data_root / "test.jsonl").unlink()

    with pytest.raises(DatasetGateError, match="partition is unavailable"):
        SupervisedDatasetGate(data_root, report_root)
