"""Phase 5 orchestration with an explicit selection/test boundary."""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import sklearn

from aegishunt.datasets.io import sha256_file
from aegishunt.flows.registry import feature_names
from aegishunt.ml.supervised.artifacts import ExperimentStore
from aegishunt.ml.supervised.bundle import (
    candidate_bytes,
    load_bundle,
    load_manifest,
    load_selection_artifact,
    manifest_as_safe_json,
    save_bundle,
    sha256_bytes,
    trusted_types,
)
from aegishunt.ml.supervised.candidates import PREPROCESSING_VERSION
from aegishunt.ml.supervised.config import SupervisedTrainingConfig
from aegishunt.ml.supervised.contracts import (
    BundleManifest,
    FrozenTestReport,
    ModelSelectionRecord,
    PredictionResult,
)
from aegishunt.ml.supervised.data import SupervisedDatasetGate
from aegishunt.ml.supervised.errors import ArtifactError, DatasetGateError
from aegishunt.ml.supervised.frozen import evaluate_frozen_test
from aegishunt.ml.supervised.model_card import render_model_card
from aegishunt.ml.supervised.prediction import PredictionBatch, predict_batch
from aegishunt.ml.supervised.selection import (
    FittedCandidate,
    evaluate_candidates,
    select_main_candidate,
)


@dataclass(frozen=True, slots=True)
class TrainingRunResult:
    experiment_id: str
    model_id: str
    model_version: str
    selected_algorithm: str
    pipeline_verification_only: bool
    selection: ModelSelectionRecord


@dataclass(frozen=True, slots=True)
class FrozenRunResult:
    report: FrozenTestReport
    bundle_version: str
    pipeline_verification_only: bool


class SupervisedTrainingService:
    """Run controlled supervised experiments without implicit test access."""

    def __init__(
        self,
        *,
        data_root: Path,
        dataset_report_root: Path,
        training_config_path: Path,
        artifact_root: Path,
        reports_root: Path,
    ) -> None:
        self._data_root = data_root
        self._dataset_report_root = dataset_report_root
        self._training_config_path = training_config_path
        self._artifact_root = artifact_root
        self._reports_root = reports_root

    def _config(self) -> SupervisedTrainingConfig:
        return SupervisedTrainingConfig.load(self._training_config_path)

    @staticmethod
    def _git_commit() -> str | None:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        commit = result.stdout.strip()
        return commit if result.returncode == 0 and len(commit) == 40 else None

    @staticmethod
    def _require_controlled_permission(dataset_type: str, allowed: bool) -> bool:
        controlled = dataset_type == "controlled_demo"
        if controlled and not allowed:
            raise DatasetGateError(
                "controlled-demo training requires explicit pipeline-verification permission"
            )
        return controlled

    @staticmethod
    def _selection_record(
        selected: FittedCandidate,
        config: SupervisedTrainingConfig,
        gate: SupervisedDatasetGate,
        *,
        config_checksum: str,
        model_payload: bytes,
        pipeline_verification_only: bool,
    ) -> ModelSelectionRecord:
        evidence = gate.evidence
        result = selected.result
        return ModelSelectionRecord(
            record_schema_version="1.0.0",
            status="frozen",
            experiment_id=config.experiment_id,
            model_id=f"aegishunt-supervised-{config.model_version}",
            model_version=config.model_version,
            algorithm=result.algorithm,
            hyperparameters=result.hyperparameters,
            preprocessing_version=PREPROCESSING_VERSION,
            calibration_method=result.calibration_method,
            threshold=result.threshold,
            selection_policy_version=config.selection_policy_version,
            selection_rationale=(
                "validation Macro F1 was the primary objective",
                "PR-AUC, recall, FPR, Brier score, fold stability, latency, and size broke ties",
                "Accuracy and frozen-test evidence were not selection keys",
            ),
            dataset_id=evidence.dataset_manifest.dataset_id,
            dataset_version=evidence.dataset_manifest.dataset_version,
            dataset_manifest_checksum=evidence.dataset_manifest_checksum,
            split_manifest_checksum=evidence.split_manifest_checksum,
            feature_schema_version=evidence.dataset_manifest.feature_schema_version,
            feature_names=feature_names(),
            expected_dtype="float64",
            label_mapping_version=evidence.dataset_manifest.label_mapping_version,
            random_seed=config.random_seed,
            training_config_checksum=config_checksum,
            selection_artifact_filename="selection.skops",
            selection_artifact_checksum=sha256_bytes(model_payload),
            trusted_types=trusted_types(model_payload),
            validation_metrics=result.validation_metrics,
            cv_mean_metrics=result.cv_mean_metrics,
            cv_std_metrics=result.cv_std_metrics,
            operational_metrics=result.operational_metrics,
            pipeline_verification_only=pipeline_verification_only,
            test_data_accessed=False,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _write_training_artifacts(
        store: ExperimentStore,
        config: SupervisedTrainingConfig,
        candidates: tuple[FittedCandidate, ...],
        selection: ModelSelectionRecord,
        model_payload: bytes,
    ) -> None:
        store.write_json("training_config.json", config)
        store.write_json(
            "candidate_models.json",
            [candidate.model_dump(mode="json") for candidate in config.candidates],
        )
        hyperparameter_rows: list[dict[str, object]] = []
        fold_rows: list[dict[str, object]] = []
        threshold_rows: list[dict[str, object]] = []
        calibration_payload: dict[str, object] = {}
        validation_payload: dict[str, object] = {}
        comparison_rows: list[dict[str, object]] = []
        latency_rows: list[dict[str, object]] = []
        for candidate in candidates:
            result = candidate.result
            validation_payload[result.algorithm] = result.validation_metrics.model_dump(mode="json")
            calibration_payload[result.algorithm] = [
                item.model_dump(mode="json") for item in result.calibration_candidates
            ]
            for tuning_index, tuning in enumerate(candidate.tuning_results):
                hyperparameter_rows.append(
                    {
                        "algorithm": result.algorithm,
                        "candidate_index": tuning_index,
                        "parameters": json.dumps(tuning.parameters, sort_keys=True),
                        "status": tuning.status,
                        "failure_code": tuning.failure_code or "",
                        "macro_f1_mean": tuning.mean_metrics.get("macro_f1"),
                        "pr_auc_mean": tuning.mean_metrics.get("pr_auc"),
                        "training_duration_seconds": tuning.training_duration_seconds,
                    }
                )
                for fold in tuning.folds:
                    fold_rows.append(
                        {
                            "algorithm": result.algorithm,
                            "candidate_index": tuning_index,
                            "fold_index": fold.evidence.fold_index,
                            "train_rows": fold.evidence.train_rows,
                            "validation_rows": fold.evidence.validation_rows,
                            "train_groups": len(fold.evidence.train_groups),
                            "validation_groups": len(fold.evidence.validation_groups),
                            "group_overlap": len(fold.evidence.group_overlap),
                            "source_overlap": len(fold.evidence.source_overlap),
                            "session_overlap": len(fold.evidence.session_overlap),
                            "scenario_overlap": len(fold.evidence.scenario_overlap),
                            "macro_f1": fold.metrics.macro_f1,
                            "pr_auc": fold.metrics.pr_auc,
                        }
                    )
            for threshold in result.threshold_results:
                threshold_rows.append(
                    {
                        "algorithm": result.algorithm,
                        "threshold": threshold.threshold,
                        "macro_f1": threshold.metrics.macro_f1,
                        "recall": threshold.metrics.recall,
                        "false_positive_rate": threshold.metrics.false_positive_rate,
                        "selected": threshold.threshold == result.threshold,
                    }
                )
            comparison_rows.append(
                {
                    "algorithm": result.algorithm,
                    "macro_f1": result.validation_metrics.macro_f1,
                    "pr_auc": result.validation_metrics.pr_auc,
                    "recall": result.validation_metrics.recall,
                    "false_positive_rate": result.validation_metrics.false_positive_rate,
                    "brier_score": result.validation_metrics.brier_score,
                    "cv_macro_f1_std": result.cv_std_metrics.get("macro_f1"),
                    "selected": result.algorithm == selection.algorithm,
                }
            )
            operational = result.operational_metrics
            latency_rows.append(
                {
                    "algorithm": result.algorithm,
                    "batch_size": operational.batch_size,
                    "repetitions": operational.repetitions,
                    "batch_p50_ms": operational.batch_latency_p50_ms,
                    "batch_p95_ms": operational.batch_latency_p95_ms,
                    "batch_p99_ms": operational.batch_latency_p99_ms,
                    "per_sample_p50_ms": operational.per_sample_latency_p50_ms,
                    "throughput_samples_per_second": operational.throughput_samples_per_second,
                    "serialized_size_bytes": operational.serialized_size_bytes,
                    "peak_memory_bytes": operational.peak_memory_bytes or "",
                }
            )
        store.write_csv("hyperparameter_results.csv", hyperparameter_rows)
        store.write_csv("cross_validation_results.csv", fold_rows)
        store.write_json("validation_metrics.json", validation_payload)
        store.write_csv("threshold_results.csv", threshold_rows)
        store.write_json("calibration_metrics.json", calibration_payload)
        store.write_csv("model_comparison.csv", comparison_rows)
        store.write_csv("latency_results.csv", latency_rows)
        store.write_bytes("selection.skops", model_payload)
        store.write_json("model_selection.json", selection)

    def train(self, *, allow_controlled_demo: bool = False) -> TrainingRunResult:
        """Create a validation-frozen selection record without opening test rows."""

        config = self._config()
        if (self._reports_root / config.experiment_id).exists():
            raise ArtifactError("supervised experiment already exists")
        gate = SupervisedDatasetGate(self._data_root, self._dataset_report_root)
        pipeline_only = self._require_controlled_permission(
            gate.evidence.dataset_manifest.dataset_type,
            allow_controlled_demo,
        )
        data = gate.load_training_validation(cv_folds=config.cv_folds)
        candidates = evaluate_candidates(data, config)
        selected = select_main_candidate(candidates)
        model_payload = candidate_bytes(selected)
        selection = self._selection_record(
            selected,
            config,
            gate,
            config_checksum=sha256_file(self._training_config_path),
            model_payload=model_payload,
            pipeline_verification_only=pipeline_only,
        )
        store = ExperimentStore.create(self._reports_root, config.experiment_id)
        self._write_training_artifacts(store, config, candidates, selection, model_payload)
        return TrainingRunResult(
            experiment_id=config.experiment_id,
            model_id=selection.model_id,
            model_version=selection.model_version,
            selected_algorithm=selection.algorithm,
            pipeline_verification_only=pipeline_only,
            selection=selection,
        )

    def evaluate_test(self, *, allow_controlled_demo: bool = False) -> FrozenRunResult:
        """Explicitly perform the single frozen-test evaluation and finalize the bundle."""

        config = self._config()
        store = ExperimentStore.open(self._reports_root, config.experiment_id)
        if store.exists("frozen_test_metrics.json"):
            raise ArtifactError("frozen test evaluation already exists")
        selection = store.read_selection()
        if selection.training_config_checksum != sha256_file(self._training_config_path):
            raise ArtifactError("training configuration changed after model selection")
        gate = SupervisedDatasetGate(self._data_root, self._dataset_report_root)
        pipeline_only = self._require_controlled_permission(
            gate.evidence.dataset_manifest.dataset_type,
            allow_controlled_demo,
        )
        if pipeline_only != selection.pipeline_verification_only:
            raise ArtifactError("dataset research boundary changed after model selection")
        estimator, calibrator = load_selection_artifact(store.directory, selection)
        selection_payload = store.path("model_selection.json").read_bytes()
        test = gate.load_frozen_test(selection)
        frozen = evaluate_frozen_test(
            estimator,
            calibrator,
            selection,
            test,
            config,
            selection_record_checksum=hashlib.sha256(selection_payload).hexdigest(),
        )
        model_payload = store.path("selection.skops").read_bytes()
        model_card = render_model_card(
            selection,
            frozen,
            gate.evidence.dataset_manifest,
            gate.evidence.split_manifest,
        )
        manifest = BundleManifest(
            manifest_schema_version="1.0.0",
            model_id=selection.model_id,
            model_version=selection.model_version,
            model_type="supervised",
            algorithm=selection.algorithm,
            artifact_filename="model.skops",
            artifact_checksum=selection.selection_artifact_checksum,
            trusted_types=selection.trusted_types,
            preprocessing_version=selection.preprocessing_version,
            calibration_method=selection.calibration_method,
            classification_threshold=selection.threshold,
            feature_names=selection.feature_names,
            feature_schema_version=selection.feature_schema_version,
            expected_dtype=selection.expected_dtype,
            training_dataset_id=selection.dataset_id,
            training_dataset_version=selection.dataset_version,
            dataset_manifest_checksum=selection.dataset_manifest_checksum,
            split_manifest_checksum=selection.split_manifest_checksum,
            label_mapping_version=selection.label_mapping_version,
            training_config_checksum=selection.training_config_checksum,
            random_seed=selection.random_seed,
            hyperparameters=selection.hyperparameters,
            validation_metrics=selection.validation_metrics,
            frozen_test_metrics=frozen.metrics,
            pipeline_verification_only=selection.pipeline_verification_only,
            python_version=platform.python_version(),
            sklearn_version=sklearn.__version__,
            git_commit_sha=self._git_commit(),
            status="validated",
            created_at=datetime.now(UTC),
        )
        store.write_json("frozen_test_metrics.json", frozen)
        matrix = frozen.metrics.confusion_matrix
        store.write_csv(
            "confusion_matrix.csv",
            [
                {
                    "actual": "benign",
                    "predicted_benign": matrix[0][0],
                    "predicted_malicious": matrix[0][1],
                },
                {
                    "actual": "malicious",
                    "predicted_benign": matrix[1][0],
                    "predicted_malicious": matrix[1][1],
                },
            ],
        )
        classification_report = {
            name: value.model_dump(mode="json")
            for name, value in frozen.metrics.per_class.items()
        }
        store.write_json(
            "classification_report.json",
            classification_report,
        )
        store.write_text("model_card.md", model_card)
        store.write_json("model_bundle_manifest.json", manifest)
        save_bundle(self._artifact_root, manifest, model_payload, model_card)
        return FrozenRunResult(
            report=frozen,
            bundle_version=manifest.model_version,
            pipeline_verification_only=pipeline_only,
        )

    def list_models(self) -> tuple[BundleManifest, ...]:
        if not self._artifact_root.is_dir():
            return ()
        manifests = [
            load_manifest(path, artifact_root=self._artifact_root)
            for path in sorted(self._artifact_root.iterdir())
            if path.is_dir() and not path.name.startswith(".")
        ]
        return tuple(manifests)

    def describe(self, model_version: str) -> str:
        manifest = load_manifest(
            self._artifact_root / model_version,
            artifact_root=self._artifact_root,
        )
        return manifest_as_safe_json(manifest)

    def verify(self, model_version: str) -> BundleManifest:
        return load_bundle(
            self._artifact_root / model_version,
            artifact_root=self._artifact_root,
        ).manifest

    def predict(
        self,
        model_version: str,
        batch: PredictionBatch,
    ) -> tuple[PredictionResult, ...]:
        model = load_bundle(
            self._artifact_root / model_version,
            artifact_root=self._artifact_root,
        )
        return predict_batch(model, batch)
