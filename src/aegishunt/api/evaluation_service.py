"""Read-only verified evaluation projections; GET calls never create evidence."""

from __future__ import annotations

import csv
import hashlib
import json
import math
from datetime import datetime
from pathlib import Path
from statistics import fmean
from typing import Literal, cast
from uuid import UUID

from pydantic import ValidationError

from aegishunt.api.contracts import (
    EvaluationComparisonRow,
    EvaluationConfidenceInterval,
    EvaluationDescriptor,
    EvaluationLoaoAggregate,
    EvaluationLoaoRow,
    EvaluationSummary,
    EvaluationSummaryProvenance,
    FusionEvaluationDiscovery,
    FusionPolicyDescriptor,
)
from aegishunt.api.demo_service import SampleDemoService
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.api.runtime_model_service import EffectiveRuntimeModelService
from aegishunt.config import ApplicationSettings
from aegishunt.demo import DemoArtifactManager
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
_MODE_ENGINES = {
    "supervised_only": "supervised",
    "anomaly_only": "anomaly",
    "dual_engine_fusion": "fusion",
}
_SUMMARY_UNAVAILABLE = (
    "No verified evaluation is available yet. Run the controlled demo from "
    "Overview to prepare the checked model and evaluation artifacts."
)
_DEMO_EVALUATION_CHECKSUM_MANIFEST = Path("configs/models/phase-12-demo-evaluation-checksums.json")
_LOAO_EVIDENCE_FILENAME = "leave_one_family_out.csv"


def _directory_hash(paths: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _csv_value(value: object) -> object:
    if not isinstance(value, str):
        raise ValueError("registered fusion evaluation CSV row is malformed")
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
        reader = csv.DictReader(stream)
        if not reader.fieldnames or any(
            not isinstance(name, str) or not name for name in reader.fieldnames
        ):
            raise ValueError("registered fusion evaluation CSV header is malformed")
        rows = []
        for row in reader:
            if None in row or set(row) != set(reader.fieldnames):
                raise ValueError("registered fusion evaluation CSV row is malformed")
            rows.append(
                cast(
                    JsonObject,
                    {name: _csv_value(value) for name, value in row.items()},
                )
            )
    if not rows:
        raise ValueError("registered fusion evaluation CSV is empty")
    return rows


def _required_text(row: JsonObject, field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError("fusion evaluation row has an invalid text field")
    return value


def _required_float(row: JsonObject, field: str) -> float:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("fusion evaluation row has an invalid numeric field")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("fusion evaluation row has a non-finite numeric field")
    return result


def _required_int(row: JsonObject, field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("fusion evaluation row has an invalid integer field")
    return value


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


class DemoEvaluationSummaryService:
    """Project the latest runtime-pinned demo evaluation without mutation."""

    def __init__(self, database: Database, settings: ApplicationSettings) -> None:
        self._database = database
        self._settings = settings

    def read(self) -> EvaluationSummary:
        try:
            demo_job = SampleDemoService(
                self._database,
                self._settings,
            ).latest_completed_runtime_job()
        except (AegisHuntError, OSError, ValueError):
            return self._invalid()
        if demo_job is None:
            return self._unavailable()
        artifacts = {artifact.artifact_type: artifact for artifact in demo_job.snapshot.artifacts}
        fusion_identity = artifacts["fusion_policy"]
        runtime = EffectiveRuntimeModelService(
            self._database,
            self._settings,
        ).read_for_job(demo_job.job_id)
        effective = runtime.effective_fusion_policy
        if runtime.status != "available" or runtime.latest_runtime_job_id is None:
            return self._unavailable()
        if (
            effective is None
            or effective.source != "runtime_job_snapshot"
            or not effective.effective_for_latest_job
            or effective.runtime_job_id != runtime.latest_runtime_job_id
            or runtime.snapshot_created_at is None
        ):
            return self._invalid()
        try:
            project_root = self._settings.ingestion.sample_root.resolve().parent.parent
            environment = DemoArtifactManager(
                self._settings,
                project_root=project_root,
            ).read_for_fusion_policy(
                policy_id=fusion_identity.artifact_id,
                policy_version=fusion_identity.version,
                policy_checksum=fusion_identity.checksum,
            )
        except (AegisHuntError, OSError, ValueError):
            return self._invalid()
        if environment is None:
            return self._unavailable()
        reader = FusionEvaluationArtifactReader(environment.settings)
        descriptor, discovery = reader.read()
        if discovery.status == "unavailable":
            return self._unavailable()
        if discovery.status != "available" or descriptor is None:
            return self._invalid()
        try:
            return self._verified_summary(
                environment.settings,
                descriptor,
                effective_policy=effective,
                runtime_job_id=runtime.latest_runtime_job_id,
                snapshot_created_at=runtime.snapshot_created_at,
                checksum_manifest_path=(project_root / _DEMO_EVALUATION_CHECKSUM_MANIFEST),
            )
        except (
            AegisHuntError,
            KeyError,
            OSError,
            TypeError,
            ValueError,
            ValidationError,
        ):
            return self._invalid()

    @staticmethod
    def _unavailable() -> EvaluationSummary:
        return EvaluationSummary(
            status="unavailable",
            message=_SUMMARY_UNAVAILABLE,
            limitations=(
                "page reads never prepare demo artifacts",
                "no metric is shown without verified machine evidence",
            ),
        )

    @staticmethod
    def _invalid() -> EvaluationSummary:
        return EvaluationSummary(
            status="invalid",
            message=(
                "The prepared evaluation evidence failed integrity or identity "
                "verification. Run the controlled demo again only after reviewing "
                "the local artifact state."
            ),
            limitations=(
                "invalid evidence fails closed",
                "server filesystem paths are not disclosed",
            ),
        )

    def _verified_summary(
        self,
        settings: ApplicationSettings,
        descriptor: EvaluationDescriptor,
        *,
        effective_policy: FusionPolicyDescriptor,
        runtime_job_id: UUID,
        snapshot_created_at: datetime,
        checksum_manifest_path: Path,
    ) -> EvaluationSummary:
        experiment_id = settings.runtime.fusion_evaluation_experiment_id
        experiment = settings.runtime.fusion_evaluation_root / experiment_id
        policy_directory = settings.runtime.fusion_policy_root / effective_policy.policy_version
        policy = load_policy(policy_directory, root=settings.runtime.fusion_policy_root)
        selection = FusionSelectionRecord.model_validate_json(
            (experiment / "fusion_selection.json").read_text(encoding="utf-8")
        )
        dataset = Phase7DatasetManifest.model_validate_json(
            (experiment / "phase_07_dataset_manifest.json").read_text(encoding="utf-8")
        )
        split = Phase7SplitManifest.model_validate_json(
            (experiment / "phase_07_split_manifest.json").read_text(encoding="utf-8")
        )
        provenance = descriptor.provenance
        if (
            effective_policy.evaluation_source != experiment_id
            or descriptor.run_id != f"fusion:{experiment_id}"
            or descriptor.version != effective_policy.policy_version
            or policy.policy_id != effective_policy.policy_id
            or policy.policy_version != effective_policy.policy_version
            or policy.experiment_id != experiment_id
            or policy.recommendation_status != effective_policy.recommendation
            or policy.feature_schema_version != effective_policy.feature_schema_version
            or policy.selected_weights.supervised_weight != effective_policy.supervised_weight
            or policy.selected_weights.anomaly_weight != effective_policy.anomaly_weight
            or policy.selected_threshold != effective_policy.fusion_threshold
            or selection.selected_weights != policy.selected_weights
            or selection.selected_threshold != policy.selected_threshold
            or selection.recommendation_status != policy.recommendation_status
            or dataset.dataset_id != policy.dataset_id
            or dataset.dataset_version != policy.dataset_version
            or split.dataset_id != dataset.dataset_id
            or split.dataset_version != dataset.dataset_version
            or provenance.get("policy_manifest_hash") != effective_policy.artifact_hash
            or sha256_file(policy_directory / "fusion_policy_manifest.json")
            != effective_policy.artifact_hash
        ):
            raise ValueError("runtime policy and evaluation identities differ")
        loao_evidence_checksum = self._verify_loao_checksum(
            experiment,
            experiment_id=experiment_id,
            manifest_path=checksum_manifest_path,
        )
        known = self._known_rows(experiment / "known_attack_metrics.csv")
        loao = self._loao_rows(
            experiment / "leave_one_family_out.csv",
            expected_families=dataset.attack_families,
        )
        aggregates = {
            engine: fmean(item.recall for item in loao if item.engine == engine)
            for engine in ("supervised", "anomaly", "fusion")
        }
        confidence = self._confidence_summary(experiment / "confidence_intervals.json")
        artifact_hash = provenance.get("artifact_hash")
        if not isinstance(artifact_hash, str):
            raise ValueError("evaluation artifact identity is unavailable")
        return EvaluationSummary(
            status="available",
            message="Verified controlled evaluation for the latest completed analysis.",
            evidence_class="controlled_synthetic_evaluation",
            experiment_id=experiment_id,
            dataset_id=dataset.dataset_id,
            dataset_version=dataset.dataset_version,
            row_count=dataset.row_count,
            group_count=dataset.group_count,
            supervised_weight=policy.selected_weights.supervised_weight,
            anomaly_weight=policy.selected_weights.anomaly_weight,
            selected_threshold=policy.selected_threshold,
            recommendation=policy.recommendation_status,
            known_comparison=known,
            loao_comparison=loao,
            loao_aggregate=EvaluationLoaoAggregate(
                supervised_recall=aggregates["supervised"],
                anomaly_recall=aggregates["anomaly"],
                fusion_recall=aggregates["fusion"],
            ),
            confidence_intervals=confidence,
            provenance=EvaluationSummaryProvenance(
                runtime_job_id=runtime_job_id,
                snapshot_created_at=snapshot_created_at,
                policy_id=policy.policy_id,
                policy_version=policy.policy_version,
                policy_manifest_hash=effective_policy.artifact_hash,
                evaluation_artifact_hash=artifact_hash,
                loao_evidence_checksum=loao_evidence_checksum,
                dataset_manifest_checksum=policy.dataset_manifest_checksum,
                split_manifest_checksum=policy.split_manifest_checksum,
                feature_schema_version=policy.feature_schema_version,
            ),
            limitations=(
                "controlled synthetic evaluation; not a public benchmark",
                "fusion matched but did not outperform supervised-only on known groups",
                "fusion was weaker than anomaly-only on family-macro LOAO Recall",
                "fusion score is not attack probability",
            ),
        )

    @staticmethod
    def _verify_loao_checksum(
        experiment: Path,
        *,
        experiment_id: str,
        manifest_path: Path,
    ) -> str:
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ValueError("demo evaluation checksum manifest is unavailable")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version",
            "experiment_id",
            "file_inventory",
            "checksums",
        }:
            raise ValueError("demo evaluation checksum manifest is invalid")
        inventory = payload.get("file_inventory")
        checksums = payload.get("checksums")
        if (
            payload.get("schema_version") != "1.0.0"
            or payload.get("experiment_id") != experiment_id
            or inventory != [_LOAO_EVIDENCE_FILENAME]
            or not isinstance(checksums, dict)
            or set(checksums) != {_LOAO_EVIDENCE_FILENAME}
        ):
            raise ValueError("demo evaluation checksum identity is invalid")
        expected = checksums.get(_LOAO_EVIDENCE_FILENAME)
        if (
            not isinstance(expected, str)
            or len(expected) != 64
            or any(character not in "0123456789abcdef" for character in expected)
            or sha256_file(experiment / _LOAO_EVIDENCE_FILENAME) != expected
        ):
            raise ValueError("demo LOAO evidence checksum failed")
        return expected

    @staticmethod
    def _known_rows(path: Path) -> tuple[EvaluationComparisonRow, ...]:
        rows = _read_csv(path)
        if {row.get("mode") for row in rows} != set(_MODE_ENGINES) or len(rows) != 3:
            raise ValueError("known comparison requires one row per engine")
        output: list[EvaluationComparisonRow] = []
        for row in rows:
            mode = _required_text(row, "mode")
            if mode not in _MODE_ENGINES:
                raise ValueError("known comparison mode is invalid")
            output.append(
                EvaluationComparisonRow(
                    engine=cast(
                        Literal["supervised", "anomaly", "fusion"],
                        _MODE_ENGINES[mode],
                    ),
                    mode=cast(
                        Literal[
                            "supervised_only",
                            "anomaly_only",
                            "dual_engine_fusion",
                        ],
                        mode,
                    ),
                    recall=_required_float(row, "recall"),
                    f1=_required_float(row, "f1"),
                    macro_f1=_required_float(row, "macro_f1"),
                    pr_auc=_required_float(row, "pr_auc"),
                    false_positive_rate=_required_float(row, "false_positive_rate"),
                    tn=_required_int(row, "tn"),
                    fp=_required_int(row, "fp"),
                    fn=_required_int(row, "fn"),
                    tp=_required_int(row, "tp"),
                )
            )
        order = {"supervised": 0, "anomaly": 1, "fusion": 2}
        return tuple(sorted(output, key=lambda item: order[item.engine]))

    @staticmethod
    def _loao_rows(
        path: Path,
        *,
        expected_families: tuple[str, ...],
    ) -> tuple[EvaluationLoaoRow, ...]:
        rows = _read_csv(path)
        actual_families = {_required_text(row, "held_out_family") for row in rows}
        if actual_families != set(expected_families) or len(rows) != 3 * len(expected_families):
            raise ValueError("LOAO comparison family inventory is invalid")
        output: list[EvaluationLoaoRow] = []
        identities: set[tuple[str, str]] = set()
        for row in rows:
            family = _required_text(row, "held_out_family")
            mode = _required_text(row, "mode")
            if mode not in _MODE_ENGINES or (family, mode) in identities:
                raise ValueError("LOAO comparison engine inventory is invalid")
            identities.add((family, mode))
            output.append(
                EvaluationLoaoRow(
                    held_out_family=family,
                    engine=cast(
                        Literal["supervised", "anomaly", "fusion"],
                        _MODE_ENGINES[mode],
                    ),
                    mode=cast(
                        Literal[
                            "supervised_only",
                            "anomaly_only",
                            "dual_engine_fusion",
                        ],
                        mode,
                    ),
                    recall=_required_float(row, "recall"),
                    false_positive_rate=_required_float(row, "false_positive_rate"),
                    evaluation_row_count=_required_int(row, "evaluation_row_count"),
                    evaluation_group_count=_required_int(row, "evaluation_group_count"),
                )
            )
        engine_order = {"supervised": 0, "anomaly": 1, "fusion": 2}
        family_order = {family: index for index, family in enumerate(expected_families)}
        return tuple(
            sorted(
                output,
                key=lambda item: (
                    family_order[item.held_out_family],
                    engine_order[item.engine],
                ),
            )
        )

    @staticmethod
    def _confidence_summary(
        path: Path,
    ) -> tuple[EvaluationConfidenceInterval, ...]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError("confidence interval evidence is invalid")
        known = next(
            (
                item
                for item in payload
                if isinstance(item, dict) and item.get("experiment_kind") == "known_attack"
            ),
            None,
        )
        if not isinstance(known, dict):
            raise ValueError("known comparison confidence interval is missing")
        intervals = known.get("delta_intervals")
        if not isinstance(intervals, dict):
            raise ValueError("confidence interval deltas are invalid")
        output: list[EvaluationConfidenceInterval] = []
        metric_fields = {
            "recall": "recall",
            "macro_f1": "macro_f1",
            "pr_auc": "pr_auc",
            "false_positive_rate": "benign_false_positive_rate",
        }
        for comparison in ("fusion_minus_supervised", "fusion_minus_anomaly"):
            for metric, source_metric in metric_fields.items():
                record = intervals.get(f"{comparison}.{source_metric}")
                if not isinstance(record, dict) or record.get("unavailable_reason") is not None:
                    raise ValueError("required confidence interval is unavailable")
                output.append(
                    EvaluationConfidenceInterval(
                        comparison=cast(
                            Literal[
                                "fusion_minus_supervised",
                                "fusion_minus_anomaly",
                            ],
                            comparison,
                        ),
                        metric=cast(
                            Literal[
                                "recall",
                                "macro_f1",
                                "pr_auc",
                                "false_positive_rate",
                            ],
                            metric,
                        ),
                        confidence_level=float(record["confidence_level"]),
                        lower=float(record["lower"]),
                        upper=float(record["upper"]),
                        requested_draws=int(record["requested_draws"]),
                        successful_draws=int(record["successful_draws"]),
                    )
                )
        return tuple(output)


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
