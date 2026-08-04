"""Thin controlled registry/training adapter over Phase 5–7 model services."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast
from uuid import UUID, uuid5

from aegishunt.api.contracts import (
    ModelDescriptor,
    ModelImportance,
    ModelImportanceEntry,
    ModelOperationCapabilities,
    ModelTrainRequest,
)
from aegishunt.api.errors import ApiError, conflict, not_found
from aegishunt.config import ApplicationSettings
from aegishunt.detection.errors import DetectionArtifactError
from aegishunt.explainability.artifacts import load_explanation_artifact
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.service import AnomalyTrainingService
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.service import SupervisedTrainingService
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.schemas import ModelVersion
from aegishunt.schemas.base import JsonObject, utc_now
from aegishunt.schemas.enums import ModelStatus, ModelType
from aegishunt.storage import Database
from aegishunt.storage.repositories import AuditLogRepository, ModelVersionRepository

_MODEL_NAMESPACE = UUID("8beff1c6-1f18-545e-b15f-d9995d79dc0f")


def model_identity(engine: str, version: str) -> UUID:
    """Return a stable registry identity independent of filesystem location."""

    return uuid5(_MODEL_NAMESPACE, f"{engine}:{version}")


class ModelRegistryService:
    """Verify bundles before listing, training, or explicit activation."""

    def __init__(self, database: Database, settings: ApplicationSettings) -> None:
        self._database = database
        self._settings = settings

    def _supervised(self, config: Path | None = None) -> SupervisedTrainingService:
        settings = self._settings
        return SupervisedTrainingService(
            data_root=settings.datasets.processed_root,
            dataset_report_root=settings.datasets.reports_root,
            training_config_path=config or settings.supervised.training_config_path,
            artifact_root=settings.supervised.artifact_root,
            reports_root=settings.supervised.reports_root,
        )

    def _anomaly(self, config: Path | None = None) -> AnomalyTrainingService:
        settings = self._settings
        return AnomalyTrainingService(
            data_root=settings.datasets.processed_root,
            dataset_report_root=settings.datasets.reports_root,
            training_config_path=config or settings.anomaly.training_config_path,
            artifact_root=settings.anomaly.artifact_root,
            reports_root=settings.anomaly.reports_root,
        )

    def _active(self) -> dict[ModelType, str]:
        with self._database.session() as session:
            return {
                item.model_type: item.version
                for item in ModelVersionRepository(session).list_active()
            }

    def list_models(self) -> list[ModelDescriptor]:
        """Return only bundle-verified models plus truthful fusion unavailability."""

        active = self._active()
        items: list[ModelDescriptor] = []
        for supervised_manifest in self._supervised().list_models():
            verified_supervised = self._supervised().verify(
                supervised_manifest.model_version
            )
            items.append(
                ModelDescriptor(
                    model_id=str(
                        model_identity("supervised", verified_supervised.model_version)
                    ),
                    engine="supervised",
                    version=verified_supervised.model_version,
                    state="verified",
                    active=(
                        active.get(ModelType.SUPERVISED)
                        == verified_supervised.model_version
                    ),
                    checksum=verified_supervised.artifact_checksum,
                    artifact_available=True,
                    activation_eligible=True,
                    limitations=(
                        "controlled synthetic pipeline verification only",
                        "not a public benchmark or production validation",
                    ),
                )
            )
        for anomaly_manifest in self._anomaly().list_models():
            verified_anomaly = self._anomaly().verify(anomaly_manifest.model_version)
            items.append(
                ModelDescriptor(
                    model_id=str(
                        model_identity("anomaly", verified_anomaly.model_version)
                    ),
                    engine="anomaly",
                    version=verified_anomaly.model_version,
                    state=(
                        "validation_qualified"
                        if verified_anomaly.status == "validation_qualified"
                        else "verified"
                    ),
                    active=(
                        active.get(ModelType.ANOMALY)
                        == verified_anomaly.model_version
                    ),
                    checksum=verified_anomaly.artifact_checksum,
                    artifact_available=True,
                    activation_eligible=(
                        verified_anomaly.status != "validation_qualified"
                    ),
                    activation_ineligibility_reason=(
                        "validation-qualified LOF requires an untouched independent "
                        "holdout before activation"
                        if verified_anomaly.status == "validation_qualified"
                        else None
                    ),
                    limitations=(
                        "LOF is validation-qualified only"
                        if verified_anomaly.status == "validation_qualified"
                        else "controlled synthetic pipeline verification only",
                        "no untouched independent holdout",
                    ),
                )
            )
        return sorted(items, key=lambda item: (item.engine, item.version))

    def get(self, model_id: str) -> ModelDescriptor:
        try:
            identifier = UUID(model_id)
        except ValueError:
            not_found("model")
        for item in self.list_models():
            if UUID(item.model_id) == identifier:
                return item
        not_found("model")

    def active(self) -> list[ModelDescriptor]:
        return [item for item in self.list_models() if item.active]

    def operation_capabilities(self) -> ModelOperationCapabilities:
        """Return read-only readiness for controls shown by the mentor UI."""

        models = self.list_models()
        eligible = tuple(
            item.model_id for item in models if item.activation_eligible
        )
        required_inputs = (
            self._settings.datasets.processed_root / "train.jsonl",
            self._settings.datasets.processed_root / "validation.jsonl",
            self._settings.datasets.reports_root / "dataset_manifest.json",
            self._settings.datasets.reports_root / "split_manifest.json",
            self._settings.supervised.training_config_path,
            self._settings.anomaly.training_config_path,
            Path("configs/models/supervised-corrective-pm-def-001.yaml"),
            Path("configs/models/anomaly-lof-production-candidate.yaml"),
        )
        output_roots = (
            self._settings.supervised.artifact_root,
            self._settings.supervised.reports_root,
            self._settings.anomaly.artifact_root,
            self._settings.anomaly.reports_root,
        )
        training_ready = all(
            path.is_file() and not path.is_symlink() for path in required_inputs
        ) and all(
            path.is_dir() and not path.is_symlink() and os.access(path, os.W_OK)
            for path in output_roots
        )
        return ModelOperationCapabilities(
            training_ready=training_ready,
            activation_ready=bool(eligible),
            eligible_activation_model_ids=eligible,
            training_message=(
                "Controlled training prerequisites are ready."
                if training_ready
                else "Training controls are hidden because the approved data, profiles, "
                "or writable output roots are not all ready."
            ),
            activation_message=(
                "Verified activation-eligible bundles are available."
                if eligible
                else "Activation controls are hidden because no verified eligible bundle "
                "is available."
            ),
        )

    def train(self, request: ModelTrainRequest) -> ModelDescriptor:
        """Run an allowlisted existing pipeline; test evaluation and activation stay separate."""

        profile_paths = {
            "supervised-default": self._settings.supervised.training_config_path,
            "supervised-corrective": Path(
                "configs/models/supervised-corrective-pm-def-001.yaml"
            ),
            "anomaly-default": self._settings.anomaly.training_config_path,
            "anomaly-lof-candidate": Path(
                "configs/models/anomaly-lof-production-candidate.yaml"
            ),
        }
        if request.approved_dataset_identity != "aegishunt-controlled-demo:1.0.0":
            conflict("approved dataset identity does not match the allowlisted profile")
        config_path = profile_paths[request.profile]
        if request.engine == "supervised":
            if not request.profile.startswith("supervised-"):
                raise ApiError(
                    "training profile does not match the requested engine",
                    code="profile_engine_mismatch",
                    status_code=400,
                )
            supervised_config = SupervisedTrainingConfig.load(config_path)
            if supervised_config.model_version != request.new_version:
                conflict("new version must match the allowlisted configuration")
            self._supervised(config_path).train(allow_controlled_demo=True)
        else:
            if not request.profile.startswith("anomaly-"):
                raise ApiError(
                    "training profile does not match the requested engine",
                    code="profile_engine_mismatch",
                    status_code=400,
                )
            anomaly_config = AnomalyTrainingConfig.load(config_path)
            if anomaly_config.model_version != request.new_version:
                conflict("new version must match the allowlisted configuration")
            self._anomaly(config_path).train(allow_controlled_demo=True)
        descriptor = self.get(str(model_identity(request.engine, request.new_version)))
        with self._database.session() as session, session.begin():
            AuditLogRepository(session).record(
                actor=request.actor,
                action="train_controlled_model",
                object_type="model_versions",
                object_id=descriptor.model_id,
                details={
                    "engine": request.engine,
                    "profile": request.profile,
                    "version": request.new_version,
                    "approved_dataset_identity": request.approved_dataset_identity,
                    "reason": request.reason,
                    "activated": False,
                },
            )
        return descriptor

    def importance(self, model_id: str) -> ModelImportance:
        """Return exact verified global sensitivity evidence, never inferred values."""

        descriptor = self.get(model_id)
        if descriptor.engine != "supervised":
            return ModelImportance(
                model_id=descriptor.model_id,
                available=False,
                method=None,
                importance=None,
                message="verified global-importance artifact is unavailable",
            )
        runtime = load_runtime_policy(self._settings.runtime.policy_path)
        try:
            artifact = load_explanation_artifact(
                (
                    self._settings.detection.explanation_artifact_root
                    / runtime.policy.explanation_artifact_version
                ),
                root=self._settings.detection.explanation_artifact_root,
            )
        except DetectionArtifactError:
            return ModelImportance(
                model_id=descriptor.model_id,
                available=False,
                method=None,
                importance=None,
                message="verified global-importance artifact is unavailable",
            )
        report = artifact.native_importance
        if (
            report.status != "available"
            or report.model_version != descriptor.version
            or report.model_id != f"aegishunt-supervised-{descriptor.version}"
        ):
            return ModelImportance(
                model_id=descriptor.model_id,
                available=False,
                method=None,
                importance=None,
                message="verified global-importance artifact does not match this model",
            )
        return ModelImportance(
            model_id=descriptor.model_id,
            available=True,
            method=report.method,
            importance=tuple(
                ModelImportanceEntry(
                    feature_name=item.feature_name,
                    mean=item.mean,
                    standard_deviation=item.standard_deviation,
                )
                for item in report.entries
            ),
            message="verified model-sensitivity evidence",
        )

    def activate(
        self,
        model_id: str,
        *,
        actor: str,
        reason: str,
        expected_active_version: str | None,
    ) -> ModelDescriptor:
        """Verify exact bundle inventory before one optimistic activation."""

        descriptor = self.get(model_id)
        if not descriptor.artifact_available or not descriptor.activation_eligible:
            raise ApiError(
                descriptor.activation_ineligibility_reason
                or "model artifact is unavailable for activation",
                code=(
                    "model_activation_ineligible"
                    if descriptor.artifact_available
                    else "model_unavailable"
                ),
                status_code=409 if descriptor.artifact_available else 503,
            )
        model_type = ModelType(descriptor.engine)
        if model_type is ModelType.SUPERVISED:
            supervised_manifest = self._supervised().verify(descriptor.version)
            algorithm = supervised_manifest.algorithm
            feature_schema = {
                "version": supervised_manifest.feature_schema_version,
                "names": list(supervised_manifest.feature_names),
            }
            training_dataset = (
                f"{supervised_manifest.training_dataset_id}:"
                f"{supervised_manifest.training_dataset_version}"
            )
            metrics = supervised_manifest.validation_metrics.model_dump(mode="json")
        else:
            anomaly_manifest = self._anomaly().verify(descriptor.version)
            algorithm = anomaly_manifest.algorithm
            feature_schema = {
                "version": anomaly_manifest.feature_schema_version,
                "names": list(anomaly_manifest.feature_names),
            }
            training_dataset = (
                f"{anomaly_manifest.training_dataset_id}:"
                f"{anomaly_manifest.training_dataset_version}"
            )
            metrics = anomaly_manifest.validation_metrics.model_dump(mode="json")
        identifier = model_identity(descriptor.engine, descriptor.version)
        with self._database.session() as session, session.begin():
            audit = AuditLogRepository(session)
            repository = ModelVersionRepository(session, audit)
            existing = repository.get_by_type_version(model_type, descriptor.version)
            if existing is None:
                repository.add(
                    ModelVersion(
                        model_id=identifier,
                        model_type=model_type,
                        version=descriptor.version,
                        algorithm=str(algorithm),
                        feature_schema=cast(JsonObject, feature_schema),
                        training_dataset=training_dataset,
                        training_config={"allowlisted_profile": True},
                        metrics=cast(JsonObject, metrics),
                        artifact_path=f"{descriptor.engine}/{descriptor.version}",
                        created_at=utc_now(),
                        status=ModelStatus.VALIDATED,
                    ),
                    actor=actor,
                )
            repository.activate(
                identifier,
                actor=actor,
                reason=reason,
                expected_active_version=expected_active_version,
            )
        return self.get(model_id)
