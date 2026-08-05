"""Read-only global-versus-runtime model and fusion-policy projection."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal
from uuid import UUID

from aegishunt.api.contracts import (
    EffectiveModelDescriptor,
    EffectiveModelState,
    FusionPolicyDescriptor,
)
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.config import ApplicationSettings
from aegishunt.demo import DemoArtifactManager
from aegishunt.errors import AegisHuntError
from aegishunt.ml.anomaly.bundle import load_bundle as load_anomaly_bundle
from aegishunt.ml.fusion.artifacts import (
    POLICY_MANIFEST_FILENAME,
    load_policy,
    sha256_file,
)
from aegishunt.ml.fusion.contracts import PolicyManifest
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised_bundle
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.runtime.contracts import (
    RuntimeArtifactIdentity,
    RuntimeJob,
    RuntimeJobStatus,
)
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.schemas.enums import ModelType
from aegishunt.storage import Database
from aegishunt.storage.repositories import ModelVersionRepository


class EffectiveRuntimeModelService:
    """Resolve immutable latest-job artifacts without changing global pointers."""

    def __init__(self, database: Database, settings: ApplicationSettings) -> None:
        self._database = database
        self._settings = settings

    def read(self) -> EffectiveModelState:
        return self._read_job(self._latest_completed_job())

    def read_for_job(self, job_id: UUID) -> EffectiveModelState:
        """Resolve one explicit completed job without falling back to a newer replay."""

        with self._database.session() as session:
            job = RuntimeJobRepository(session).get(job_id)
        return self._read_job(
            job if job is not None and job.status is RuntimeJobStatus.COMPLETED else None
        )

    def _read_job(self, latest: RuntimeJob | None) -> EffectiveModelState:
        registry = ModelRegistryService(
            self._database,
            self._settings,
        )
        registry_models = registry.list_models()
        global_active = [item for item in registry_models if item.active]
        operations = registry.operation_capabilities(registry_models)
        configured_policy = self._configured_policy()
        if latest is None:
            return EffectiveModelState(
                status="unavailable",
                latest_runtime_job_id=None,
                latest_runtime_job_status=None,
                snapshot_created_at=None,
                global_active_models=global_active,
                effective_models=[],
                configured_fusion_policy=configured_policy,
                effective_fusion_policy=None,
                operations=operations,
                unavailable_reason="no completed runtime job has a pinned model snapshot",
                limitations=(
                    "global active pointers are not changed by demo execution",
                    "effective state is available only from a completed runtime job snapshot",
                ),
            )

        candidates = tuple(self._candidate_settings())
        active_versions = self._active_versions()
        artifacts = {artifact.artifact_type: artifact for artifact in latest.snapshot.artifacts}
        models = [
            self._effective_supervised(
                latest,
                artifacts["supervised_model"],
                candidates,
                active_versions,
            ),
            self._effective_anomaly(
                latest,
                artifacts["anomaly_model"],
                candidates,
                active_versions,
            ),
        ]
        effective_policy = self._effective_policy(
            latest,
            artifacts["fusion_policy"],
            candidates,
        )
        if (
            configured_policy is not None
            and effective_policy is not None
            and configured_policy.artifact_hash == effective_policy.artifact_hash
        ):
            configured_policy = configured_policy.model_copy(
                update={"effective_for_latest_job": True}
            )
        return EffectiveModelState(
            status="available",
            latest_runtime_job_id=latest.job_id,
            latest_runtime_job_status=latest.status.value,
            snapshot_created_at=latest.created_at,
            global_active_models=global_active,
            effective_models=models,
            configured_fusion_policy=configured_policy,
            effective_fusion_policy=effective_policy,
            operations=operations,
            unavailable_reason=None,
            limitations=(
                "runtime-job snapshots are immutable and do not imply global activation",
                "anomaly score is not attack probability",
                "fusion score is not attack probability",
                "LOF remains validation-qualified and is not auto-activated",
            ),
        )

    def _latest_completed_job(self) -> RuntimeJob | None:
        with self._database.session() as session:
            return RuntimeJobRepository(session).latest_with_status(RuntimeJobStatus.COMPLETED)

    def _active_versions(self) -> dict[ModelType, str]:
        with self._database.session() as session:
            return {
                item.model_type: item.version
                for item in ModelVersionRepository(session).list_active()
            }

    def _candidate_settings(self) -> Iterable[ApplicationSettings]:
        yield self._settings
        try:
            sample_root = self._settings.ingestion.sample_root.resolve()
            project_root = sample_root.parent.parent
            environment = DemoArtifactManager(
                self._settings,
                project_root=project_root,
            ).read()
        except (AegisHuntError, OSError, ValueError):
            environment = None
        if environment is not None and environment.settings != self._settings:
            yield environment.settings

    def _effective_supervised(
        self,
        job: RuntimeJob,
        identity: RuntimeArtifactIdentity,
        candidates: tuple[ApplicationSettings, ...],
        active: dict[ModelType, str],
    ) -> EffectiveModelDescriptor:
        for settings in candidates:
            try:
                loaded = load_supervised_bundle(
                    settings.supervised.artifact_root / identity.version,
                    artifact_root=settings.supervised.artifact_root,
                )
            except (AegisHuntError, OSError, ValueError):
                continue
            manifest = loaded.manifest
            if (
                manifest.model_id != identity.artifact_id
                or manifest.artifact_checksum != identity.checksum
                or manifest.feature_schema_version != job.snapshot.feature_schema_version
            ):
                continue
            return EffectiveModelDescriptor(
                model_id=manifest.model_id,
                engine_type="supervised",
                algorithm=manifest.algorithm,
                version=manifest.model_version,
                registry_status="verified",
                source="runtime_job_snapshot",
                runtime_job_id=job.job_id,
                feature_schema_version=manifest.feature_schema_version,
                artifact_hash=identity.checksum,
                threshold=manifest.classification_threshold,
                snapshot_created_at=job.created_at,
                global_pointer_active=(active.get(ModelType.SUPERVISED) == manifest.model_version),
                qualification="verified runtime-pinned model",
                limitations=(
                    "runtime pinning does not activate the global model pointer",
                    "controlled synthetic pipeline verification only",
                ),
            )
        return self._unavailable_model(
            job,
            identity,
            engine_type="supervised",
            global_pointer_active=(active.get(ModelType.SUPERVISED) == identity.version),
            limitation="pinned supervised artifact is no longer readable from a verified root",
        )

    def _effective_anomaly(
        self,
        job: RuntimeJob,
        identity: RuntimeArtifactIdentity,
        candidates: tuple[ApplicationSettings, ...],
        active: dict[ModelType, str],
    ) -> EffectiveModelDescriptor:
        for settings in candidates:
            try:
                loaded = load_anomaly_bundle(
                    settings.anomaly.artifact_root / identity.version,
                    artifact_root=settings.anomaly.artifact_root,
                )
            except (AegisHuntError, OSError, ValueError):
                continue
            manifest = loaded.manifest
            if (
                manifest.model_id != identity.artifact_id
                or manifest.artifact_checksum != identity.checksum
                or manifest.feature_schema_version != job.snapshot.feature_schema_version
            ):
                continue
            status: Literal["verified", "validation_qualified", "unavailable"] = (
                "validation_qualified" if manifest.status == "validation_qualified" else "verified"
            )
            qualification = (
                "validation-qualified candidate; not eligible for activation"
                if status == "validation_qualified"
                else "verified runtime-pinned model"
            )
            limitations = (
                "LOF remains validation-qualified",
                "no untouched independent holdout",
                "anomaly score is not attack probability",
                "runtime pinning does not activate the global model pointer",
            )
            return EffectiveModelDescriptor(
                model_id=manifest.model_id,
                engine_type="anomaly",
                algorithm=manifest.algorithm,
                version=manifest.model_version,
                registry_status=status,
                source="runtime_job_snapshot",
                runtime_job_id=job.job_id,
                feature_schema_version=manifest.feature_schema_version,
                artifact_hash=identity.checksum,
                threshold=manifest.anomaly_threshold,
                snapshot_created_at=job.created_at,
                global_pointer_active=(active.get(ModelType.ANOMALY) == manifest.model_version),
                qualification=qualification,
                limitations=limitations,
            )
        return self._unavailable_model(
            job,
            identity,
            engine_type="anomaly",
            global_pointer_active=active.get(ModelType.ANOMALY) == identity.version,
            limitation="pinned anomaly artifact is no longer readable from a verified root",
        )

    @staticmethod
    def _unavailable_model(
        job: RuntimeJob,
        identity: RuntimeArtifactIdentity,
        *,
        engine_type: Literal["supervised", "anomaly"],
        global_pointer_active: bool,
        limitation: str,
    ) -> EffectiveModelDescriptor:
        return EffectiveModelDescriptor(
            model_id=identity.artifact_id,
            engine_type=engine_type,
            algorithm=None,
            version=identity.version,
            registry_status="unavailable",
            source="runtime_job_snapshot",
            runtime_job_id=job.job_id,
            feature_schema_version=job.snapshot.feature_schema_version,
            artifact_hash=identity.checksum,
            threshold=None,
            snapshot_created_at=job.created_at,
            global_pointer_active=global_pointer_active,
            qualification="identity retained by immutable runtime snapshot",
            limitations=(limitation,),
        )

    def _configured_policy(self) -> FusionPolicyDescriptor | None:
        try:
            runtime = load_runtime_policy(self._settings.runtime.policy_path)
            root = self._settings.runtime.fusion_policy_root
            policy = load_policy(
                root / runtime.policy.fusion_policy_version,
                root=root,
            )
            checksum = sha256_file(
                root / runtime.policy.fusion_policy_version / POLICY_MANIFEST_FILENAME
            )
        except (AegisHuntError, OSError, ValueError):
            return None
        return self._policy_descriptor(
            policy,
            checksum=checksum,
            source="configured_policy",
            runtime_job_id=None,
            configured=True,
            effective=False,
        )

    def _effective_policy(
        self,
        job: RuntimeJob,
        identity: RuntimeArtifactIdentity,
        candidates: tuple[ApplicationSettings, ...],
    ) -> FusionPolicyDescriptor | None:
        for settings in candidates:
            root = settings.runtime.fusion_policy_root
            try:
                policy = load_policy(root / identity.version, root=root)
                checksum = sha256_file(root / identity.version / POLICY_MANIFEST_FILENAME)
            except (AegisHuntError, OSError, ValueError):
                continue
            if (
                policy.policy_id != identity.artifact_id
                or policy.policy_version != identity.version
                or checksum != identity.checksum
                or policy.feature_schema_version != job.snapshot.feature_schema_version
            ):
                continue
            return self._policy_descriptor(
                policy,
                checksum=checksum,
                source="runtime_job_snapshot",
                runtime_job_id=job.job_id,
                configured=False,
                effective=True,
            )
        return None

    @staticmethod
    def _policy_descriptor(
        policy: PolicyManifest,
        *,
        checksum: str,
        source: Literal["configured_policy", "runtime_job_snapshot"],
        runtime_job_id: UUID | None,
        configured: bool,
        effective: bool,
    ) -> FusionPolicyDescriptor:
        return FusionPolicyDescriptor(
            policy_id=policy.policy_id,
            policy_version=policy.policy_version,
            status=policy.status,
            source=source,
            runtime_job_id=runtime_job_id,
            artifact_source="verified JSON/Markdown fusion policy artifact",
            artifact_hash=checksum,
            supervised_weight=policy.selected_weights.supervised_weight,
            anomaly_weight=policy.selected_weights.anomaly_weight,
            rule_weight=None,
            context_weight=None,
            fusion_threshold=policy.selected_threshold,
            feature_schema_version=policy.feature_schema_version,
            evaluation_source=policy.experiment_id,
            recommendation=policy.recommendation_status,
            configured_for_new_jobs=configured,
            effective_for_latest_job=effective,
            limitations=(
                "fusion recommendation remains inconclusive",
                "fusion score is not attack probability",
                "policy contains no sklearn model",
                "fusion was not shown to outperform supervised-only",
            ),
        )
