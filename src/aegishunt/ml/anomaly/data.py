"""Benign-only Phase 4 data gate for anomaly training and frozen evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from aegishunt.ml.anomaly.contracts import AnomalySelectionRecord, BenignTrainingManifest
from aegishunt.ml.anomaly.errors import AnomalyDatasetError
from aegishunt.ml.supervised.data import (
    DatasetEvidence,
    PartitionData,
    SupervisedDatasetGate,
)
from aegishunt.ml.supervised.errors import DatasetGateError


@dataclass(frozen=True, slots=True)
class AnomalyTrainingData:
    """Benign fit data plus separately labelled validation evidence."""

    evidence: DatasetEvidence
    benign_train: PartitionData
    validation: PartitionData
    manifest: BenignTrainingManifest


class AnomalyDatasetGate:
    """Reuse Phase 4 integrity checks and enforce the one-class fit boundary."""

    def __init__(self, data_root: Path, report_root: Path) -> None:
        try:
            self._gate = SupervisedDatasetGate(data_root, report_root)
        except DatasetGateError as exc:
            raise AnomalyDatasetError(str(exc)) from exc

    @property
    def evidence(self) -> DatasetEvidence:
        return self._gate.evidence

    def load_training_validation(self, *, minimum_benign_groups: int) -> AnomalyTrainingData:
        """Load train/validation while fitting is restricted to train-label zero rows."""

        try:
            source = self._gate.load_training_validation(cv_folds=2)
        except DatasetGateError as exc:
            raise AnomalyDatasetError(str(exc)) from exc
        benign_rows = tuple(row for row in source.train.rows if row.labels.binary_label == 0)
        malicious_rows = tuple(row for row in source.train.rows if row.labels.binary_label == 1)
        if not benign_rows:
            raise AnomalyDatasetError("training partition contains no benign rows")
        benign = PartitionData(name="benign_train", rows=benign_rows)
        benign_groups = tuple(sorted(set(benign.groups.tolist())))
        if len(benign_groups) < minimum_benign_groups:
            raise AnomalyDatasetError(
                "benign training groups are insufficient for the configured anomaly policy"
            )
        if set(benign.labels.tolist()) != {0}:
            raise AnomalyDatasetError("anomaly estimator fit data is not benign-only")
        if set(source.validation.labels.tolist()) != {0, 1}:
            raise AnomalyDatasetError(
                "validation partition requires both benign and anomaly evidence"
            )
        validation_groups = tuple(sorted(set(source.validation.groups.tolist())))
        manifest = BenignTrainingManifest(
            dataset_id=source.evidence.dataset_manifest.dataset_id,
            dataset_version=source.evidence.dataset_manifest.dataset_version,
            partition="train",
            benign_rows=len(benign_rows),
            benign_groups=benign_groups,
            excluded_malicious_rows=len(malicious_rows),
            validation_rows=len(source.validation.rows),
            validation_groups=validation_groups,
            metadata_used_as_features=False,
            test_data_accessed=False,
        )
        return AnomalyTrainingData(
            evidence=source.evidence,
            benign_train=benign,
            validation=source.validation,
            manifest=manifest,
        )

    def load_frozen_test(self, selection: AnomalySelectionRecord) -> PartitionData:
        """Open the untouched test partition only for a frozen anomaly selection."""

        try:
            return self._gate.load_frozen_test_for_contract(
                status=selection.status,
                test_data_accessed=selection.test_data_accessed,
                dataset_manifest_checksum=selection.dataset_manifest_checksum,
                split_manifest_checksum=selection.split_manifest_checksum,
            )
        except DatasetGateError as exc:
            raise AnomalyDatasetError(str(exc)) from exc
