"""Read-only verified evaluation projections; GET calls never create evidence."""

from __future__ import annotations

from typing import cast

from aegishunt.api.contracts import EvaluationDescriptor
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.config import ApplicationSettings
from aegishunt.ml.anomaly.service import AnomalyTrainingService
from aegishunt.ml.supervised.service import SupervisedTrainingService
from aegishunt.schemas.base import JsonObject
from aegishunt.storage import Database


class EvaluationCatalogService:
    """Expose verified bundle evidence and explicit unavailable research evidence."""

    def __init__(self, database: Database, settings: ApplicationSettings) -> None:
        self._database = database
        self._settings = settings

    def list(self) -> list[EvaluationDescriptor]:
        """Read existing evidence only; never train, evaluate, or interpolate curves."""

        registry = ModelRegistryService(self._database, self._settings)
        output: list[EvaluationDescriptor] = []
        supervised = SupervisedTrainingService(
            data_root=self._settings.datasets.processed_root,
            dataset_report_root=self._settings.datasets.reports_root,
            training_config_path=self._settings.supervised.training_config_path,
            artifact_root=self._settings.supervised.artifact_root,
            reports_root=self._settings.supervised.reports_root,
        )
        anomaly = AnomalyTrainingService(
            data_root=self._settings.datasets.processed_root,
            dataset_report_root=self._settings.datasets.reports_root,
            training_config_path=self._settings.anomaly.training_config_path,
            artifact_root=self._settings.anomaly.artifact_root,
            reports_root=self._settings.anomaly.reports_root,
        )
        for descriptor in registry.list_models():
            if descriptor.engine == "supervised" and descriptor.artifact_available:
                supervised_manifest = supervised.verify(descriptor.version)
                metrics = (
                    supervised_manifest.frozen_test_metrics
                    or supervised_manifest.validation_metrics
                ).model_dump(mode="json")
                output.append(
                    EvaluationDescriptor(
                        run_id=f"supervised:{descriptor.version}",
                        engine="supervised",
                        version=descriptor.version,
                        available=True,
                        verification="verified",
                        metrics=cast(JsonObject, metrics),
                        provenance={
                            "dataset_id": supervised_manifest.training_dataset_id,
                            "dataset_version": supervised_manifest.training_dataset_version,
                            "pipeline_verification_only": (
                                supervised_manifest.pipeline_verification_only
                            ),
                            "test_affected_selection": False,
                        },
                        limitations=descriptor.limitations,
                    )
                )
            elif descriptor.engine == "anomaly" and descriptor.artifact_available:
                anomaly_manifest = anomaly.verify(descriptor.version)
                metrics = (
                    anomaly_manifest.frozen_test_metrics
                    or anomaly_manifest.validation_metrics
                ).model_dump(mode="json")
                output.append(
                    EvaluationDescriptor(
                        run_id=f"anomaly:{descriptor.version}",
                        engine="anomaly",
                        version=descriptor.version,
                        available=True,
                        verification="verified",
                        metrics=cast(JsonObject, metrics),
                        provenance={
                            "dataset_id": anomaly_manifest.training_dataset_id,
                            "dataset_version": anomaly_manifest.training_dataset_version,
                            "pipeline_verification_only": (
                                anomaly_manifest.pipeline_verification_only
                            ),
                            "status": anomaly_manifest.status,
                            "untouched_independent_holdout_available": (
                                anomaly_manifest.untouched_independent_holdout_available
                            ),
                        },
                        limitations=descriptor.limitations,
                    )
                )
        output.append(
            EvaluationDescriptor(
                run_id="fusion:phase-07",
                engine="fusion",
                version="phase-07",
                available=False,
                verification="unavailable",
                metrics=None,
                provenance={"recommendation": "inconclusive"},
                limitations=(
                    "fusion was not shown to outperform supervised-only",
                    "LOAO fusion was weaker than anomaly-only",
                    "held-out exfiltration and reconnaissance misses are retained",
                    "fusion score is not attack probability",
                ),
            )
        )
        return sorted(output, key=lambda item: (item.engine, item.version))
