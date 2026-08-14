"""Isolated, verified model and policy artifacts for the explicit sample demo."""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path

import yaml

from aegishunt.artifact_io import configured_artifact_root
from aegishunt.config import (
    AnomalySettings,
    ApplicationSettings,
    CorrelationSettings,
    DatasetSettings,
    DetectionSettings,
    RuntimeSettings,
    SupervisedSettings,
)
from aegishunt.correlation.config import load_correlation_policy
from aegishunt.datasets.service import DatasetService
from aegishunt.detection.config import load_risk_policy
from aegishunt.errors import DataArtifactError
from aegishunt.explainability.artifacts import (
    ARTIFACT_FILES,
    load_explanation_artifact,
    save_explanation_artifact,
)
from aegishunt.explainability.contracts import ExplanationArtifactManifest
from aegishunt.explainability.global_importance import (
    fixed_validation_permutation_importance,
    native_tree_importance,
)
from aegishunt.explainability.reason_codes import default_reason_catalog
from aegishunt.explainability.reference_profile import build_reference_profile
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION
from aegishunt.ml.anomaly.service import AnomalyTrainingService
from aegishunt.ml.fusion.artifacts import (
    POLICY_MANIFEST_FILENAME,
    load_policy,
    sha256_file,
)
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.service import FusionEvaluationService
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised_bundle
from aegishunt.ml.supervised.config import PORTABLE_DEMO_SELECTION_POLICY_VERSION
from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.service import SupervisedTrainingService, TrainingRunResult
from aegishunt.runtime.config import load_runtime_policy

_ARTIFACT_LOCK = threading.Lock()
_SUPERVISED_VERSION = "12.0.0"
_ANOMALY_VERSION = "1.1.0-candidate"
_FUSION_VERSION = "1.0.0"
_FUSION_EXPERIMENT_ID = "phase-12-controlled-demo-fusion"
_EXPLANATION_VERSION = "1.0.0"
_DEMO_MAXIMUM_ALERTS_PER_GROUP = 5_000
_DEMO_ENVIRONMENT_LIMIT = 100
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True, slots=True)
class DemoArtifactEnvironment:
    """Verified settings rooted in one demo-only namespace."""

    settings: ApplicationSettings
    root: Path
    reused: bool


@dataclass(frozen=True, slots=True)
class _DemoPaths:
    root: Path
    data: Path
    dataset_reports: Path
    supervised_models: Path
    supervised_reports: Path
    anomaly_models: Path
    anomaly_reports: Path
    fusion_models: Path
    fusion_reports: Path
    explanations: Path
    configs: Path


def _paths(root: Path) -> _DemoPaths:
    return _DemoPaths(
        root=root,
        data=root / "dataset" / "data",
        dataset_reports=root / "dataset" / "reports",
        supervised_models=root / "models" / "supervised",
        supervised_reports=root / "reports" / "supervised",
        anomaly_models=root / "models" / "anomaly",
        anomaly_reports=root / "reports" / "anomaly",
        fusion_models=root / "models" / "fusion",
        fusion_reports=root / "reports" / "fusion",
        explanations=root / "models" / "explainability",
        configs=root / "configs",
    )


def _read_yaml(path: Path) -> dict[str, object]:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DataArtifactError("demo source configuration could not be read") from exc
    if not isinstance(payload, dict):
        raise DataArtifactError("demo source configuration is invalid")
    return payload


def _write_yaml(path: Path, payload: dict[str, object]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.safe_dump(payload, sort_keys=False),
            encoding="utf-8",
        )
    except OSError as exc:
        raise DataArtifactError("demo configuration could not be written") from exc


class DemoArtifactManager:
    """Create once, then integrity-check and reuse one isolated demo environment."""

    def __init__(self, settings: ApplicationSettings, *, project_root: Path) -> None:
        self._settings = settings
        self._project_root = project_root.resolve()
        base = configured_artifact_root(
            self._project_root,
            settings.web.demo_artifact_root,
        )
        self._base = base
        versioned_name = f"{settings.web.demo_namespace}-{settings.web.demo_operation_version}"
        self._root = base / versioned_name

    def prepare(self) -> DemoArtifactEnvironment:
        """Prepare on explicit request; GET/status paths never call this method."""

        with _ARTIFACT_LOCK:
            if self._root.exists():
                return DemoArtifactEnvironment(
                    settings=self._verify(_paths(self._root)),
                    root=self._root,
                    reused=True,
                )
            parent = self._root.parent
            staging = parent / f".{self._root.name}.building-{os.getpid()}"
            if staging.exists() or staging.is_symlink():
                raise DataArtifactError("demo artifact staging path already exists")
            try:
                parent.mkdir(parents=True, exist_ok=True)
                staging.mkdir(mode=0o750)
                self._build(_paths(staging))
                staging.rename(self._root)
            except Exception:
                if staging.exists() and staging.is_dir() and not staging.is_symlink():
                    shutil.rmtree(staging)
                raise
            return DemoArtifactEnvironment(
                settings=self._verify(_paths(self._root)),
                root=self._root,
                reused=False,
            )

    def is_prepared(self) -> bool:
        """Verify an existing environment without creating or changing evidence."""

        with _ARTIFACT_LOCK:
            if not self._root.is_dir() or self._root.is_symlink():
                return False
            self._verify(_paths(self._root))
            return True

    def read(self) -> DemoArtifactEnvironment | None:
        """Return an existing verified environment without creating evidence."""

        with _ARTIFACT_LOCK:
            if not self._root.is_dir() or self._root.is_symlink():
                return None
            return DemoArtifactEnvironment(
                settings=self._verify(_paths(self._root)),
                root=self._root,
                reused=True,
            )

    def read_for_fusion_policy(
        self,
        *,
        policy_id: str,
        policy_version: str,
        policy_checksum: str,
    ) -> DemoArtifactEnvironment | None:
        """Resolve historical demo evidence by one immutable runtime identity."""

        if (
            not 1 <= len(policy_id) <= 255
            or not _SEMVER_PATTERN.fullmatch(policy_version)
            or not _SHA256_PATTERN.fullmatch(policy_checksum)
        ):
            raise DataArtifactError("runtime fusion policy identity is invalid")
        with _ARTIFACT_LOCK:
            if not self._base.exists():
                return None
            if not self._base.is_dir() or self._base.is_symlink():
                raise DataArtifactError("demo artifact root is invalid")
            pattern = re.compile(
                rf"^{re.escape(self._settings.web.demo_namespace)}-"
                r"[0-9]+\.[0-9]+\.[0-9]+$"
            )
            try:
                entries = tuple(islice(self._base.iterdir(), _DEMO_ENVIRONMENT_LIMIT + 1))
            except OSError as exc:
                raise DataArtifactError("demo artifact root could not be read") from exc
            if len(entries) > _DEMO_ENVIRONMENT_LIMIT:
                raise DataArtifactError("demo artifact history exceeds the safe scan limit")
            candidates = sorted(
                (entry for entry in entries if pattern.fullmatch(entry.name)),
                key=lambda item: item.name,
            )

            matches: list[Path] = []
            for candidate in candidates:
                if candidate.is_symlink() or not candidate.is_dir():
                    raise DataArtifactError("demo artifact environment is invalid")
                policy_root = _paths(candidate).fusion_models
                policy_directory = policy_root / policy_version
                manifest = policy_directory / POLICY_MANIFEST_FILENAME
                if any(
                    path.is_symlink()
                    for path in (
                        candidate,
                        candidate / "models",
                        candidate / "models" / "fusion",
                        policy_directory,
                        manifest,
                    )
                ):
                    raise DataArtifactError("demo artifact environment cannot traverse a symlink")
                if not manifest.is_file():
                    continue
                if sha256_file(manifest) == policy_checksum:
                    matches.append(candidate)

            if not matches:
                return None
            if len(matches) != 1:
                raise DataArtifactError("runtime fusion policy identity is ambiguous")
            selected = matches[0]
            self._reject_symlink_tree(selected)
            settings = self._verify(
                _paths(selected),
                enforce_current_correlation_capacity=False,
            )
            policy_root = settings.runtime.fusion_policy_root
            policy = load_policy(policy_root / policy_version, root=policy_root)
            if (
                policy.policy_id != policy_id
                or policy.policy_version != policy_version
                or sha256_file(policy_root / policy_version / POLICY_MANIFEST_FILENAME)
                != policy_checksum
            ):
                raise DataArtifactError("runtime fusion policy identity does not match")
            return DemoArtifactEnvironment(
                settings=settings,
                root=selected,
                reused=True,
            )

    @staticmethod
    def _reject_symlink_tree(root: Path) -> None:
        def reject_read_error(error: OSError) -> None:
            raise DataArtifactError("demo artifact environment could not be read") from error

        try:
            for directory, names, filenames in os.walk(
                root,
                followlinks=False,
                onerror=reject_read_error,
            ):
                parent = Path(directory)
                if parent.is_symlink() or any(
                    (parent / name).is_symlink() for name in (*names, *filenames)
                ):
                    raise DataArtifactError("demo artifact environment cannot contain symlinks")
        except OSError as exc:
            raise DataArtifactError("demo artifact environment could not be read") from exc

    def _demo_settings(self, paths: _DemoPaths) -> ApplicationSettings:
        return self._settings.model_copy(
            update={
                "datasets": DatasetSettings(
                    registry_path=self._project_root / "configs/datasets/registry.yaml",
                    label_mapping_root=self._project_root / "configs/label_mappings",
                    raw_root=paths.root / "dataset/raw",
                    interim_root=paths.root / "dataset/interim",
                    processed_root=paths.data,
                    reports_root=paths.dataset_reports,
                    demo_seed=self._settings.datasets.demo_seed,
                ),
                "supervised": SupervisedSettings(
                    training_config_path=paths.configs / "supervised.yaml",
                    artifact_root=paths.supervised_models,
                    reports_root=paths.supervised_reports,
                ),
                "anomaly": AnomalySettings(
                    training_config_path=paths.configs / "anomaly.yaml",
                    artifact_root=paths.anomaly_models,
                    reports_root=paths.anomaly_reports,
                ),
                "detection": DetectionSettings(
                    risk_policy_path=paths.configs / "detection.yaml",
                    explanation_artifact_root=paths.explanations,
                    local_explanation_top_k=self._settings.detection.local_explanation_top_k,
                    local_explanation_max_features=(
                        self._settings.detection.local_explanation_max_features
                    ),
                ),
                "correlation": CorrelationSettings(policy_path=paths.configs / "correlation.yaml"),
                "runtime": RuntimeSettings(
                    policy_path=paths.configs / "runtime.yaml",
                    fusion_policy_root=paths.fusion_models,
                    fusion_evaluation_root=paths.fusion_reports,
                    fusion_evaluation_experiment_id=_FUSION_EXPERIMENT_ID,
                ),
            }
        )

    def _build(self, paths: _DemoPaths) -> None:
        settings = self._demo_settings(paths)
        DatasetService(settings.datasets).build_demo(
            data_root=paths.data,
            report_root=paths.dataset_reports,
            seed=settings.datasets.demo_seed,
        )
        self._bind_demo_dataset_evidence(paths)
        self._verify_dataset_version(paths)
        supervised = SupervisedTrainingService(
            data_root=paths.data,
            dataset_report_root=paths.dataset_reports,
            training_config_path=settings.supervised.training_config_path,
            artifact_root=paths.supervised_models,
            reports_root=paths.supervised_reports,
        )
        supervised_run = supervised.train(
            allow_controlled_demo=True,
            selection_profile="portable_demo",
        )
        self._write_demo_fusion_config(paths, supervised_run)
        fusion_config = FusionExperimentConfig.load(paths.configs / "fusion.yaml")
        if (
            supervised_run.model_version != _SUPERVISED_VERSION
            or supervised_run.model_id != fusion_config.supervised_model_id
            or supervised_run.selected_algorithm != fusion_config.supervised_algorithm
            or supervised_run.selection.hyperparameters != fusion_config.supervised_hyperparameters
            or supervised_run.selection.calibration_method != fusion_config.supervised_calibration
        ):
            raise DataArtifactError("portable demo selection differs from its fusion contract")
        supervised.evaluate_test(allow_controlled_demo=True)

        anomaly = AnomalyTrainingService(
            data_root=paths.data,
            dataset_report_root=paths.dataset_reports,
            training_config_path=settings.anomaly.training_config_path,
            artifact_root=paths.anomaly_models,
            reports_root=paths.anomaly_reports,
        )
        anomaly_run = anomaly.train(allow_controlled_demo=True)
        if (
            anomaly_run.model_version != _ANOMALY_VERSION
            or anomaly_run.selected_algorithm != "local_outlier_factor"
        ):
            raise DataArtifactError("demo anomaly selection differs from approved policy")

        fusion_run = FusionEvaluationService(
            fusion_config_path=paths.configs / "fusion.yaml",
            supervised_config_path=settings.supervised.training_config_path,
            anomaly_config_path=settings.anomaly.training_config_path,
            label_mapping_path=(
                self._project_root / "configs/label_mappings/aegishunt-controlled-demo-v1.yaml"
            ),
            experiment_root=paths.fusion_reports,
            policy_root=paths.fusion_models,
        ).evaluate(allow_controlled_demo=True)
        fusion_checksum = sha256_file(fusion_run.policy_directory / POLICY_MANIFEST_FILENAME)
        self._write_policies(
            paths,
            supervised_model_id=supervised_run.model_id,
            supervised_model_version=supervised_run.model_version,
            anomaly_model_id=anomaly_run.model_id,
            anomaly_model_version=anomaly_run.model_version,
            fusion_policy_id=fusion_run.policy.policy_id,
            fusion_policy_version=fusion_run.policy.policy_version,
            fusion_checksum=fusion_checksum,
        )
        self._write_explanation(paths)

    def _bind_demo_dataset_evidence(self, paths: _DemoPaths) -> None:
        """Pin the isolated anomaly profile to the dataset generated in this namespace.

        The controlled generator is deterministic, but byte-level manifests retain
        execution-environment provenance and toolchain-generated checksums. Requiring
        one old phase-checkpoint manifest rejected a clean CI build before its isolated
        evidence could be used. The derived profile keeps the original validation-only
        policy while binding it to the freshly checksummed dataset and split evidence
        used by this demo run.
        """

        manifest_path = paths.dataset_reports / "dataset_manifest.json"
        split_path = paths.dataset_reports / "split_manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            split = json.loads(split_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DataArtifactError("demo dataset evidence could not be read") from exc
        if not isinstance(manifest, dict) or not isinstance(split, dict):
            raise DataArtifactError("demo dataset evidence is invalid")
        if (
            manifest.get("dataset_id") != "aegishunt-controlled-demo"
            or manifest.get("dataset_version") != self._settings.web.demo_dataset_version
            or split.get("dataset_id") != manifest.get("dataset_id")
            or split.get("dataset_version") != manifest.get("dataset_version")
            or split.get("overlap_validation_result") != "pass"
        ):
            raise DataArtifactError("demo dataset identity or split validation differs")

        supervised = _read_yaml(
            self._project_root / "configs/models/supervised-corrective-pm-def-001.yaml"
        )
        supervised.update(
            {
                "config_schema_version": "1.0.0",
                "experiment_id": "phase-12-controlled-demo-supervised",
                "model_version": _SUPERVISED_VERSION,
                "selection_policy_version": (PORTABLE_DEMO_SELECTION_POLICY_VERSION),
            }
        )
        supervised.pop("corrective_run", None)
        _write_yaml(paths.configs / "supervised.yaml", supervised)

        anomaly = _read_yaml(
            self._project_root / "configs/models/anomaly-lof-production-candidate.yaml"
        )
        protocol = anomaly.get("corrective_protocol")
        if not isinstance(protocol, dict):
            raise DataArtifactError("demo anomaly evidence protocol is invalid")
        protocol["dataset_manifest_checksum"] = sha256_file(manifest_path)
        protocol["split_manifest_checksum"] = sha256_file(split_path)
        _write_yaml(paths.configs / "anomaly.yaml", anomaly)

    def _write_demo_fusion_config(
        self,
        paths: _DemoPaths,
        supervised: TrainingRunResult,
    ) -> None:
        """Bind a fresh controlled fusion experiment to the demo model identity."""

        fusion = _read_yaml(self._project_root / "configs/models/fusion.yaml")
        fusion.update(
            {
                "experiment_id": _FUSION_EXPERIMENT_ID,
                "policy_id": f"{self._settings.web.demo_namespace}-fusion",
                "supervised_model_id": supervised.model_id,
                "supervised_model_version": supervised.model_version,
            }
        )
        _write_yaml(paths.configs / "fusion.yaml", fusion)

    def _verify_dataset_version(self, paths: _DemoPaths) -> None:
        """Require the configured demo contract to match registered evidence."""

        gate = SupervisedDatasetGate(paths.data, paths.dataset_reports)
        if (
            gate.evidence.dataset_manifest.dataset_version
            != self._settings.web.demo_dataset_version
        ):
            raise DataArtifactError("demo dataset version differs from configuration")

    def _write_policies(
        self,
        paths: _DemoPaths,
        *,
        supervised_model_id: str,
        supervised_model_version: str,
        anomaly_model_id: str,
        anomaly_model_version: str,
        fusion_policy_id: str,
        fusion_policy_version: str,
        fusion_checksum: str,
    ) -> None:
        risk = _read_yaml(self._project_root / "configs/models/detection.yaml")
        risk.update(
            {
                "policy_id": f"{self._settings.web.demo_namespace}-risk",
                "required_supervised_model_id": supervised_model_id,
                "required_supervised_model_version": supervised_model_version,
                "required_anomaly_model_id": anomaly_model_id,
                "required_anomaly_model_version": anomaly_model_version,
                "required_fusion_policy_id": fusion_policy_id,
                "required_fusion_policy_version": fusion_policy_version,
                "required_fusion_policy_checksum": fusion_checksum,
                "alert_threshold": 0.0,
                "created_at": "2026-07-26T00:00:00Z",
            }
        )
        _write_yaml(paths.configs / "detection.yaml", risk)

        correlation = _read_yaml(self._project_root / "configs/correlation.yaml")
        correlation.update(
            {
                "policy_id": f"{self._settings.web.demo_namespace}-correlation",
                "group_score_threshold": 0.0,
                "hypothesis_generation_threshold": 0.0,
                "maximum_alerts_per_group": _DEMO_MAXIMUM_ALERTS_PER_GROUP,
            }
        )
        _write_yaml(paths.configs / "correlation.yaml", correlation)

        runtime = _read_yaml(self._project_root / "configs/runtime.yaml")
        runtime.update(
            {
                "policy_id": f"{self._settings.web.demo_namespace}-runtime",
                "supervised_model_version": supervised_model_version,
                "anomaly_model_version": anomaly_model_version,
                "fusion_policy_version": fusion_policy_version,
            }
        )
        _write_yaml(paths.configs / "runtime.yaml", runtime)

    def _write_explanation(self, paths: _DemoPaths) -> None:
        supervised = load_supervised_bundle(
            paths.supervised_models / _SUPERVISED_VERSION,
            artifact_root=paths.supervised_models,
        )
        anomaly = AnomalyTrainingService(
            data_root=paths.data,
            dataset_report_root=paths.dataset_reports,
            training_config_path=paths.configs / "anomaly.yaml",
            artifact_root=paths.anomaly_models,
            reports_root=paths.anomaly_reports,
        ).verify(_ANOMALY_VERSION)
        fusion = load_policy(
            paths.fusion_models / _FUSION_VERSION,
            root=paths.fusion_models,
        )
        risk = load_risk_policy(paths.configs / "detection.yaml")
        gate = SupervisedDatasetGate(paths.data, paths.dataset_reports)
        data = gate.load_training_validation(cv_folds=3)
        benign_indices = [
            index for index, label in enumerate(data.train.labels.tolist()) if label == 0
        ]
        created_at = datetime.now(UTC)
        reference = build_reference_profile(
            profile_id=f"{self._settings.web.demo_namespace}-reference",
            profile_version=_EXPLANATION_VERSION,
            dataset_id=gate.evidence.dataset_manifest.dataset_id,
            dataset_version=gate.evidence.dataset_manifest.dataset_version,
            dataset_checksum=gate.evidence.dataset_manifest_checksum,
            split_checksum=gate.evidence.split_manifest_checksum,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=supervised.manifest.feature_names,
            rows=tuple(
                tuple(float(value) for value in data.train.features[index])
                for index in benign_indices
            ),
            labels=tuple(0 for _ in benign_indices),
            group_ids=tuple(str(data.train.groups[index]) for index in benign_indices),
            source_partition="train",
            git_commit_sha=supervised.manifest.git_commit_sha,
            created_at=created_at,
        )
        native = native_tree_importance(
            supervised.estimator,
            report_id=f"{self._settings.web.demo_namespace}-native",
            model_id=supervised.manifest.model_id,
            model_version=supervised.manifest.model_version,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=supervised.manifest.feature_names,
            created_at=created_at,
        )
        permutation = fixed_validation_permutation_importance(
            supervised.estimator,
            report_id=f"{self._settings.web.demo_namespace}-permutation",
            model_id=supervised.manifest.model_id,
            model_version=supervised.manifest.model_version,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=supervised.manifest.feature_names,
            rows=tuple(tuple(float(value) for value in row) for row in data.validation.features),
            labels=tuple(int(value) for value in data.validation.labels),
            group_ids=tuple(str(value) for value in data.validation.groups),
            source_partition="validation",
            scoring_metric="balanced_accuracy",
            random_seed=5105,
            repeats=5,
            created_at=created_at,
        )
        manifest = ExplanationArtifactManifest(
            manifest_schema_version="1.0.0",
            artifact_id=f"{self._settings.web.demo_namespace}-explanation",
            artifact_version=_EXPLANATION_VERSION,
            file_inventory=tuple(sorted(ARTIFACT_FILES)),
            reference_profile_id=reference.profile_id,
            reference_profile_version=reference.profile_version,
            native_importance_report_id=native.report_id,
            permutation_importance_report_id=permutation.report_id,
            reason_catalog_id="aegishunt-phase-08-reason-codes",
            reason_catalog_version="1.0.0",
            supervised_model_id=supervised.manifest.model_id,
            supervised_model_version=supervised.manifest.model_version,
            anomaly_model_id=anomaly.model_id,
            anomaly_model_version=anomaly.model_version,
            fusion_policy_id=fusion.policy_id,
            fusion_policy_version=fusion.policy_version,
            risk_policy_id=risk.policy.policy_id,
            risk_policy_version=risk.policy.policy_version,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            pipeline_verification_only=True,
            public_benchmark=False,
            created_at=created_at,
        )
        save_explanation_artifact(
            root=paths.explanations,
            manifest=manifest,
            reference_profile=reference,
            native_importance=native,
            permutation_importance=permutation,
            reason_catalog=default_reason_catalog(),
            protocol=(
                "# Phase 12 controlled sample explanation protocol\n\n"
                "Validation-only, non-causal pipeline evidence. No public benchmark, "
                "production validation, or attack attribution is claimed.\n"
            ),
        )

    def _verify(
        self,
        paths: _DemoPaths,
        *,
        enforce_current_correlation_capacity: bool = True,
    ) -> ApplicationSettings:
        settings = self._demo_settings(paths)
        self._verify_dataset_version(paths)
        SupervisedTrainingService(
            data_root=paths.data,
            dataset_report_root=paths.dataset_reports,
            training_config_path=settings.supervised.training_config_path,
            artifact_root=paths.supervised_models,
            reports_root=paths.supervised_reports,
        ).verify(_SUPERVISED_VERSION)
        AnomalyTrainingService(
            data_root=paths.data,
            dataset_report_root=paths.dataset_reports,
            training_config_path=settings.anomaly.training_config_path,
            artifact_root=paths.anomaly_models,
            reports_root=paths.anomaly_reports,
        ).verify(_ANOMALY_VERSION)
        load_policy(paths.fusion_models / _FUSION_VERSION, root=paths.fusion_models)
        load_risk_policy(settings.detection.risk_policy_path)
        load_explanation_artifact(
            paths.explanations / _EXPLANATION_VERSION,
            root=paths.explanations,
        )
        load_runtime_policy(settings.runtime.policy_path)
        correlation = load_correlation_policy(settings.correlation.policy_path)
        if (
            enforce_current_correlation_capacity
            and correlation.policy.maximum_alerts_per_group != _DEMO_MAXIMUM_ALERTS_PER_GROUP
        ):
            raise DataArtifactError("demo correlation capacity differs from the operation contract")
        return settings
