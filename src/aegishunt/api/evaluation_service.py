"""Read-only verified evaluation projections; GET calls never create evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from aegishunt.api.contracts import (
    EvaluationDescriptor,
    FusionEvaluationDiscovery,
)
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.config import ApplicationSettings
from aegishunt.errors import AegisHuntError
from aegishunt.ml.anomaly.service import AnomalyTrainingService
from aegishunt.ml.fusion.artifacts import load_policy, sha256_file
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.contracts import (
    FusionSelectionRecord,
    Phase7DatasetManifest,
    Phase7SplitManifest,
    PolicyManifest,
)
from aegishunt.ml.supervised.service import SupervisedTrainingService
from aegishunt.schemas.base import JsonObject
from aegishunt.storage import Database

_EXPERIMENT_FILES = (
    "phase_07_experiment_protocol.json",
    "phase_07_dataset_manifest.json",
    "phase_07_split_manifest.json",
    "fusion_config.json",
    "fusion_weight_results.csv",
    "fusion_threshold_results.csv",
    "fusion_selection.json",
    "known_attack_metrics.csv",
    "unseen_attack_metrics.csv",
    "leave_one_family_out.csv",
    "temporal_holdout.csv",
    "parameter_shift.csv",
    "fusion_comparison.csv",
    "score_distributions.csv",
    "metric_deltas.csv",
    "confidence_intervals.json",
    "latency_results.csv",
    "experiment_summary.md",
)
_POLICY_FILES = (
    "fusion_policy_manifest.json",
    "fusion_policy_checksums.json",
    "fusion_policy_card.md",
)
_FUSION_LIMITATIONS = (
    "fusion was not shown to outperform supervised-only",
    "LOAO fusion was weaker than anomaly-only",
    "held-out exfiltration and reconnaissance misses are retained",
    "fusion score is not attack probability",
)


def _directory_hash(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _csv_value(value: str) -> object:
    normalized = value.strip()
    if normalized == "":
        return None
    if normalized.lower() in {"true", "false"}:
        return normalized.lower() == "true"
    try:
        integer = int(normalized)
    except ValueError:
        try:
            number = float(normalized)
        except ValueError:
            return normalized
        return number if math.isfinite(number) else normalized
    return integer


def _read_csv(path: Path) -> list[JsonObject]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = [
            cast(
                JsonObject,
                {name: _csv_value(value) for name, value in row.items()},
            )
            for row in csv.DictReader(stream)
        ]
    if not rows:
        raise ValueError("registered fusion evaluation CSV is empty")
    return rows


class FusionEvaluationArtifactReader:
    """Verify and project an existing Phase 7 experiment without recomputation."""

    def __init__(self, settings: ApplicationSettings) -> None:
        self._settings = settings
        self._experiment_id = settings.runtime.fusion_evaluation_experiment_id
        self._experiment = settings.runtime.fusion_evaluation_root / self._experiment_id

    def read(
        self,
    ) -> tuple[EvaluationDescriptor | None, FusionEvaluationDiscovery]:
        expected = tuple(f"experiment/{name}" for name in _EXPERIMENT_FILES) + tuple(
            f"policy/{name}" for name in _POLICY_FILES
        )
        try:
            missing = self._missing_experiment_files()
            policy_directory, policy = self._matching_policy()
        except (AegisHuntError, OSError, ValueError) as exc:
            return None, FusionEvaluationDiscovery(
                status="invalid",
                experiment_id=self._experiment_id,
                run_id=None,
                recommendation="inconclusive",
                metrics_available=False,
                expected_artifacts=expected,
                missing_artifacts=(),
                invalid_reason=str(exc)[:500],
                artifact_hash=None,
                dataset_reference=None,
                split_reference=None,
                limitations=_FUSION_LIMITATIONS,
            )
        if policy_directory is None or policy is None:
            missing = (
                *missing,
                "policy/<version-matching-experiment>/fusion_policy_manifest.json",
                "policy/<version-matching-experiment>/fusion_policy_checksums.json",
                "policy/<version-matching-experiment>/fusion_policy_card.md",
            )
        if missing:
            return None, FusionEvaluationDiscovery(
                status="unavailable",
                experiment_id=self._experiment_id,
                run_id=None,
                recommendation="inconclusive",
                metrics_available=False,
                expected_artifacts=expected,
                missing_artifacts=tuple(sorted(set(missing))),
                invalid_reason=None,
                artifact_hash=None,
                dataset_reference=None,
                split_reference=None,
                limitations=(
                    *_FUSION_LIMITATIONS,
                    "registered Phase 7 machine evidence is absent; release metadata "
                    "retains the inconclusive conclusion but is not a metric artifact",
                ),
            )
        assert policy_directory is not None
        assert policy is not None
        try:
            descriptor = self._verified_descriptor(policy_directory, policy)
        except (AegisHuntError, OSError, ValueError, ValidationError) as exc:
            return None, FusionEvaluationDiscovery(
                status="invalid",
                experiment_id=self._experiment_id,
                run_id=None,
                recommendation="inconclusive",
                metrics_available=False,
                expected_artifacts=expected,
                missing_artifacts=(),
                invalid_reason=str(exc)[:500],
                artifact_hash=None,
                dataset_reference=None,
                split_reference=None,
                limitations=_FUSION_LIMITATIONS,
            )
        return descriptor, FusionEvaluationDiscovery(
            status="available",
            experiment_id=self._experiment_id,
            run_id=descriptor.run_id,
            recommendation=policy.recommendation_status,
            metrics_available=True,
            expected_artifacts=expected,
            missing_artifacts=(),
            invalid_reason=None,
            artifact_hash=cast(str, descriptor.provenance["artifact_hash"]),
            dataset_reference=cast(
                str,
                descriptor.provenance["dataset_reference"],
            ),
            split_reference=cast(
                str,
                descriptor.provenance["split_reference"],
            ),
            limitations=descriptor.limitations,
        )

    def _missing_experiment_files(self) -> tuple[str, ...]:
        if not self._experiment.is_dir() or self._experiment.is_symlink():
            return tuple(f"experiment/{name}" for name in _EXPERIMENT_FILES)
        actual = {item.name for item in self._experiment.iterdir()}
        expected = set(_EXPERIMENT_FILES)
        if actual - expected:
            raise ValueError("registered fusion evaluation inventory has extra files")
        return tuple(
            f"experiment/{name}"
            for name in _EXPERIMENT_FILES
            if (not (self._experiment / name).is_file() or (self._experiment / name).is_symlink())
        )

    def _matching_policy(self) -> tuple[Path | None, PolicyManifest | None]:
        root = self._settings.runtime.fusion_policy_root
        if not root.is_dir() or root.is_symlink():
            return None, None
        matches: list[tuple[Path, PolicyManifest]] = []
        candidates = sorted(root.iterdir(), key=lambda item: item.name)
        if len(candidates) > 100:
            raise ValueError("fusion policy registry exceeds the discovery bound")
        for path in candidates:
            if not path.is_dir() or path.is_symlink():
                continue
            try:
                policy = load_policy(path, root=root)
            except AegisHuntError:
                continue
            if policy.experiment_id == self._experiment_id:
                matches.append((path, policy))
        if len(matches) > 1:
            raise ValueError("multiple policies reference the registered experiment")
        return matches[0] if matches else (None, None)

    def _verified_descriptor(
        self,
        policy_directory: Path,
        policy: PolicyManifest,
    ) -> EvaluationDescriptor:
        files = tuple(self._experiment / name for name in _EXPERIMENT_FILES)
        if {item.name for item in self._experiment.iterdir()} != set(_EXPERIMENT_FILES):
            raise ValueError("registered fusion evaluation inventory is not exact")
        if any(not item.is_file() or item.is_symlink() for item in files):
            raise ValueError("registered fusion evaluation requires regular files")
        config = FusionExperimentConfig.load(self._experiment / "fusion_config.json")
        selection = FusionSelectionRecord.model_validate_json(
            (self._experiment / "fusion_selection.json").read_text(encoding="utf-8")
        )
        dataset = Phase7DatasetManifest.model_validate_json(
            (self._experiment / "phase_07_dataset_manifest.json").read_text(encoding="utf-8")
        )
        split = Phase7SplitManifest.model_validate_json(
            (self._experiment / "phase_07_split_manifest.json").read_text(encoding="utf-8")
        )
        checks = {
            "dataset_manifest_checksum": "phase_07_dataset_manifest.json",
            "split_manifest_checksum": "phase_07_split_manifest.json",
            "experiment_protocol_checksum": "phase_07_experiment_protocol.json",
            "selection_evidence_checksum": "fusion_selection.json",
            "known_evidence_checksum": "known_attack_metrics.csv",
            "unseen_evidence_checksum": "unseen_attack_metrics.csv",
            "temporal_evidence_checksum": "temporal_holdout.csv",
            "parameter_shift_evidence_checksum": "parameter_shift.csv",
            "confidence_interval_checksum": "confidence_intervals.json",
        }
        if any(
            getattr(policy, field) != sha256_file(self._experiment / filename)
            for field, filename in checks.items()
        ):
            raise ValueError("fusion evaluation checksum differs from policy evidence")
        if (
            config.experiment_id != self._experiment_id
            or selection.experiment_id != self._experiment_id
            or policy.experiment_id != self._experiment_id
            or selection.policy_id != policy.policy_id
            or selection.policy_version != policy.policy_version
            or selection.recommendation_status != policy.recommendation_status
            or dataset.dataset_id != policy.dataset_id
            or dataset.dataset_version != policy.dataset_version
            or split.dataset_id != dataset.dataset_id
            or split.dataset_version != dataset.dataset_version
        ):
            raise ValueError("fusion evaluation identities are inconsistent")
        confidence = json.loads(
            (self._experiment / "confidence_intervals.json").read_text(encoding="utf-8")
        )
        if not isinstance(confidence, list):
            raise ValueError("fusion confidence interval evidence is invalid")
        policy_files = tuple(policy_directory / name for name in _POLICY_FILES)
        artifact_hash = _directory_hash((*files, *policy_files))
        dataset_reference = (
            f"{dataset.dataset_id}:{dataset.dataset_version}:{policy.dataset_manifest_checksum}"
        )
        split_reference = (
            f"{split.dataset_id}:{split.dataset_version}:{policy.split_manifest_checksum}"
        )
        metrics = cast(
            JsonObject,
            {
                "recommendation": selection.recommendation_status,
                "recommendation_rationale": list(selection.recommendation_rationale),
                "selected_candidate_id": selection.selected_candidate_id,
                "selected_weights": selection.selected_weights.model_dump(mode="json"),
                "selected_threshold": selection.selected_threshold,
                "known_attack_comparison": _read_csv(self._experiment / "known_attack_metrics.csv"),
                "unseen_family_comparison": _read_csv(
                    self._experiment / "unseen_attack_metrics.csv"
                ),
                "supervised_anomaly_fusion_comparison": _read_csv(
                    self._experiment / "fusion_comparison.csv"
                ),
                "confidence_intervals": [
                    item
                    for item in confidence
                    if isinstance(item, dict)
                    and item.get("experiment_kind") in {"known_attack", "leave_one_family_out"}
                ],
            },
        )
        return EvaluationDescriptor(
            run_id=f"fusion:{self._experiment_id}",
            engine="fusion",
            version=policy.policy_version,
            available=True,
            verification="verified",
            metrics=metrics,
            provenance={
                "artifact_hash": artifact_hash,
                "policy_manifest_hash": sha256_file(
                    policy_directory / "fusion_policy_manifest.json"
                ),
                "dataset_reference": dataset_reference,
                "split_reference": split_reference,
                "feature_schema_version": policy.feature_schema_version,
                "recommendation": policy.recommendation_status,
                "known_unseen_distinction": "explicit",
                "historical_frozen_test_reused": (dataset.historical_frozen_test_reused),
                "pipeline_verification_only": policy.pipeline_verification_only,
                "public_benchmark": policy.public_benchmark,
            },
            limitations=_FUSION_LIMITATIONS,
        )


class EvaluationCatalogService:
    """Expose verified bundle evidence and registered Phase 7 evidence."""

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
                    anomaly_manifest.frozen_test_metrics or anomaly_manifest.validation_metrics
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
        fusion, _ = FusionEvaluationArtifactReader(self._settings).read()
        if fusion is not None:
            output.append(fusion)
        return sorted(output, key=lambda item: (item.engine, item.version))

    def fusion_discovery(self) -> FusionEvaluationDiscovery:
        """Return explicit availability without creating an unavailable result row."""

        _, discovery = FusionEvaluationArtifactReader(self._settings).read()
        return discovery
