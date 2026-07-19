"""Phase 6 orchestration with explicit benign-fit, selection, and test boundaries."""

from __future__ import annotations

import hashlib
import platform
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import sklearn

from aegishunt.datasets.io import sha256_file
from aegishunt.flows.registry import feature_names
from aegishunt.ml.anomaly.artifacts import AnomalyExperimentStore
from aegishunt.ml.anomaly.bundle import (
    LoadedAnomalyModel,
    load_bundle,
    load_manifest,
    load_selection_artifact,
    manifest_as_safe_json,
    require_available_bundle_version,
    save_bundle,
    sha256_bytes,
    trusted_types,
)
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.anomaly.contracts import (
    AnomalyBundleManifest,
    AnomalyFrozenTestReport,
    AnomalyPredictionResult,
    AnomalySelectionRecord,
    CandidateSmokeResult,
)
from aegishunt.ml.anomaly.data import AnomalyDatasetGate
from aegishunt.ml.anomaly.errors import AnomalyArtifactError, AnomalyDatasetError
from aegishunt.ml.anomaly.frozen import evaluate_frozen_test
from aegishunt.ml.anomaly.model_card import render_candidate_model_card, render_model_card
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
from aegishunt.ml.anomaly.reporting import write_frozen_artifacts, write_training_artifacts
from aegishunt.ml.anomaly.selection import (
    FittedAnomalyCandidate,
    evaluate_isolation_forest_candidates,
    evaluate_lof_candidate,
    one_class_svm_status,
    select_production_candidate,
)
from aegishunt.ml.anomaly.smoke import (
    SMOKE_FIXTURE_ID,
    predefined_sample_anomaly,
    smoke_fixture_checksum,
)


@dataclass(frozen=True, slots=True)
class AnomalyTrainingRunResult:
    experiment_id: str
    model_id: str
    model_version: str
    selected_candidate_id: str
    selected_algorithm: str
    pipeline_verification_only: bool
    status: str
    candidate_smoke_passed: bool | None
    selection: AnomalySelectionRecord


@dataclass(frozen=True, slots=True)
class AnomalyFrozenRunResult:
    report: AnomalyFrozenTestReport
    bundle_version: str
    pipeline_verification_only: bool


class AnomalyTrainingService:
    """Select a benign-baseline detector without implicit frozen-test access."""

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

    def _config(self) -> AnomalyTrainingConfig:
        return AnomalyTrainingConfig.load(self._training_config_path)

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
            raise AnomalyDatasetError(
                "controlled-demo anomaly work requires explicit pipeline-verification permission"
            )
        return controlled

    @staticmethod
    def _require_complete(selected: FittedAnomalyCandidate) -> None:
        result = selected.result
        if any(
            value is None
            for value in (
                result.selected_threshold,
                result.validation_metrics,
                result.normalizer,
                result.operational_metrics,
            )
        ):
            raise AnomalyArtifactError("selected anomaly candidate evidence is incomplete")

    @staticmethod
    def _require_corrective_evidence(
        config: AnomalyTrainingConfig,
        data: object,
    ) -> None:
        from aegishunt.ml.anomaly.data import AnomalyTrainingData

        if not isinstance(data, AnomalyTrainingData):
            raise AnomalyArtifactError("corrective anomaly data contract is invalid")
        protocol = config.corrective_protocol
        evidence = data.evidence
        if protocol is None:
            return
        actual = (
            evidence.dataset_manifest.dataset_id,
            evidence.dataset_manifest.dataset_version,
            evidence.dataset_manifest_checksum,
            evidence.split_manifest_checksum,
            len(data.benign_train.rows),
            len(set(data.benign_train.groups.tolist())),
            len(data.validation.rows),
            len(set(data.validation.groups.tolist())),
        )
        expected = (
            protocol.dataset_id,
            protocol.dataset_version,
            protocol.dataset_manifest_checksum,
            protocol.split_manifest_checksum,
            protocol.expected_benign_training_rows,
            protocol.expected_benign_training_groups,
            protocol.expected_validation_rows,
            protocol.expected_validation_groups,
        )
        if actual != expected:
            raise AnomalyArtifactError("corrective anomaly evidence differs from registration")

    def _save_validation_candidate(
        self,
        *,
        store: AnomalyExperimentStore,
        selection: AnomalySelectionRecord,
        selected: FittedAnomalyCandidate,
        gate: AnomalyDatasetGate,
    ) -> CandidateSmokeResult:
        evidence = gate.evidence
        fixture_checksum = smoke_fixture_checksum()
        draft_manifest = AnomalyBundleManifest(
            manifest_schema_version="1.1.0",
            model_id=selection.model_id,
            model_version=selection.model_version,
            model_type="anomaly",
            algorithm=selection.algorithm,
            artifact_filename="model.skops",
            artifact_checksum=selection.selection_artifact_checksum,
            trusted_types=selection.trusted_types,
            preprocessing=selection.preprocessing,
            raw_score_method=selection.raw_score_method,
            canonical_score_transform=selection.canonical_score_transform,
            normalizer=selection.normalizer,
            anomaly_threshold=selection.threshold,
            threshold_policy=selection.threshold_policy,
            false_positive_rate_limit=selection.false_positive_rate_limit,
            feature_names=selection.feature_names,
            feature_schema_version=selection.feature_schema_version,
            expected_dtype=selection.expected_dtype,
            training_dataset_id=selection.dataset_id,
            training_dataset_version=selection.dataset_version,
            dataset_manifest_checksum=selection.dataset_manifest_checksum,
            split_manifest_checksum=selection.split_manifest_checksum,
            label_mapping_version=selection.label_mapping_version,
            training_config_checksum=selection.training_config_checksum,
            benign_training_rows=selection.benign_training_rows,
            benign_training_groups=selection.benign_training_groups,
            benign_training_identity_digest=selection.benign_training_identity_digest,
            random_seed=selection.random_seed,
            hyperparameters=selection.hyperparameters,
            validation_metrics=selection.validation_metrics,
            frozen_test_metrics=None,
            operational_metrics=selection.operational_metrics,
            pipeline_verification_only=selection.pipeline_verification_only,
            python_version=platform.python_version(),
            sklearn_version=sklearn.__version__,
            git_commit_sha=self._git_commit(),
            status="validation_qualified",
            candidate_smoke_fixture_checksum=fixture_checksum,
            # This manifest is in-memory scoring context only. It is never persisted
            # unless the fixed smoke assertion below actually succeeds.
            candidate_smoke_test_passed=True,
            untouched_independent_holdout_available=False,
            created_at=datetime.now(UTC),
        )
        smoke_batch = AnomalyPredictionBatch(
            feature_schema_version=selection.feature_schema_version,
            feature_names=selection.feature_names,
            dtype="float64",
            rows=(predefined_sample_anomaly(),),
        )
        before_save = score_batch(
            LoadedAnomalyModel(selected.estimator, draft_manifest), smoke_batch
        )[0]
        if not before_save.is_anomaly:
            store.write_json(
                "candidate_smoke_test.json",
                CandidateSmokeResult(
                    result_schema_version="1.0.0",
                    fixture_id=SMOKE_FIXTURE_ID,
                    fixture_checksum=fixture_checksum,
                    affected_selection=False,
                    ran_after_selection_freeze=True,
                    independently_reloaded=False,
                    prediction=before_save,
                    passed=False,
                    evaluated_at=datetime.now(UTC),
                ),
            )
            raise AnomalyArtifactError("validation candidate failed the fixed smoke decision")
        manifest = draft_manifest
        card = render_candidate_model_card(
            selection,
            evidence.dataset_manifest,
            evidence.split_manifest,
            before_save,
        )
        save_bundle(self._artifact_root, manifest, selected.model_payload, card)
        loaded = load_bundle(
            self._artifact_root / selection.model_version,
            artifact_root=self._artifact_root,
        )
        after_reload = score_batch(loaded, smoke_batch)[0]
        if before_save.model_dump(exclude={"scored_at"}) != after_reload.model_dump(
            exclude={"scored_at"}
        ):
            raise AnomalyArtifactError("candidate smoke result changed after bundle reload")
        smoke = CandidateSmokeResult(
            result_schema_version="1.0.0",
            fixture_id=SMOKE_FIXTURE_ID,
            fixture_checksum=fixture_checksum,
            affected_selection=False,
            ran_after_selection_freeze=True,
            independently_reloaded=True,
            prediction=after_reload,
            passed=True,
            evaluated_at=datetime.now(UTC),
        )
        store.write_json("candidate_smoke_test.json", smoke)
        store.write_json(
            "independent_holdout_status.json",
            {
                "schema_version": "1.0.0",
                "available": False,
                "checked_without_scoring_or_label_access": True,
                "registered_row_count": evidence.dataset_manifest.row_count,
                "assigned_row_count": sum(evidence.split_manifest.row_counts.values()),
                "reason": (
                    "all registered rows are assigned to train, validation, or the "
                    "previously viewed original test partition"
                ),
                "candidate_status": "validation_qualified",
            },
        )
        return smoke

    def train(self, *, allow_controlled_demo: bool = False) -> AnomalyTrainingRunResult:
        """Freeze validation-selected anomaly evidence without reading test rows."""

        config = self._config()
        if (self._reports_root / config.experiment_id).exists():
            raise AnomalyArtifactError("anomaly experiment already exists")
        if config.candidate_status == "validation_qualified":
            require_available_bundle_version(self._artifact_root, config.model_version)
        gate = AnomalyDatasetGate(self._data_root, self._dataset_report_root)
        pipeline_only = self._require_controlled_permission(
            gate.evidence.dataset_manifest.dataset_type,
            allow_controlled_demo,
        )
        data = gate.load_training_validation(minimum_benign_groups=config.minimum_benign_groups)
        self._require_corrective_evidence(config, data)
        evaluated = evaluate_isolation_forest_candidates(data, config)
        lof_evaluation = evaluate_lof_candidate(data, config)
        selection_candidates = evaluated.fitted
        if config.lof_production_eligible:
            if lof_evaluation.fitted is None:
                raise AnomalyArtifactError(
                    "production-eligible LOF candidate did not produce complete evidence"
                )
            selection_candidates = (*selection_candidates, lof_evaluation.fitted)
        selected = select_production_candidate(
            selection_candidates,
            selection_policy_version=config.selection_policy_version,
        )
        self._require_complete(selected)
        result = selected.result
        assert result.selected_threshold is not None
        assert result.validation_metrics is not None
        assert result.normalizer is not None
        assert result.operational_metrics is not None
        selected_threshold = next(
            item for item in result.threshold_results if item.threshold == result.selected_threshold
        )
        lof = lof_evaluation.comparator
        one_class_svm = one_class_svm_status(config)
        evidence = data.evidence
        selection = AnomalySelectionRecord(
            record_schema_version=config.config_schema_version,
            status=(
                "validation_qualified"
                if config.candidate_status == "validation_qualified"
                else "frozen"
            ),
            experiment_id=config.experiment_id,
            model_id=f"aegishunt-anomaly-{config.model_version}",
            model_version=config.model_version,
            algorithm=result.algorithm,
            selected_candidate_id=result.candidate_id,
            hyperparameters=result.hyperparameters,
            preprocessing="standard_scaler",
            raw_score_method="score_samples",
            canonical_score_transform="negative_raw_score",
            normalizer=result.normalizer,
            threshold=result.selected_threshold,
            threshold_policy="validation_benign_fpr_constrained",
            false_positive_rate_limit=config.false_positive_rate_limit,
            selection_policy_version=config.selection_policy_version,
            selection_rationale=(
                (
                    "LOF production-candidate eligibility was authorized by ADR 0015"
                    if result.algorithm == "local_outlier_factor"
                    else "Isolation Forest is the roadmap-defined anomaly algorithm"
                ),
                "every estimator and preprocessing step fit benign training rows only",
                "validation benign FPR constraint preceded PR-AUC/F1/recall tie-breaks",
                "the previously viewed frozen test was not accessed or used for selection",
                *(
                    (
                        "corrective search used fixed configuration complexity and stable ID "
                        "tie-breaks without runtime latency or test evidence",
                    )
                    if config.selection_policy_version == "1.0.1"
                    else ()
                ),
                *(
                    (
                        "policy 2.0.0 compared the registered Isolation Forest matrix and "
                        "fixed novelty-mode LOF using validation utility only",
                        "this post-hoc eligibility decision requires a new independent holdout",
                    )
                    if config.selection_policy_version == "2.0.0"
                    else ()
                ),
            ),
            dataset_id=evidence.dataset_manifest.dataset_id,
            dataset_version=evidence.dataset_manifest.dataset_version,
            dataset_manifest_checksum=evidence.dataset_manifest_checksum,
            split_manifest_checksum=evidence.split_manifest_checksum,
            feature_schema_version=evidence.dataset_manifest.feature_schema_version,
            feature_names=feature_names(),
            expected_dtype="float64",
            label_mapping_version=evidence.dataset_manifest.label_mapping_version,
            benign_training_rows=len(data.benign_train.rows),
            benign_training_groups=tuple(sorted(set(data.benign_train.groups.tolist()))),
            benign_training_identity_digest=data.manifest.benign_row_identity_digest,
            validation_rows=len(data.validation.rows),
            validation_groups=tuple(sorted(set(data.validation.groups.tolist()))),
            random_seed=config.random_seed,
            training_config_checksum=sha256_file(self._training_config_path),
            selection_artifact_filename="selection.skops",
            selection_artifact_checksum=sha256_bytes(selected.model_payload),
            trusted_types=trusted_types(selected.model_payload),
            validation_metrics=result.validation_metrics,
            group_stability=selected_threshold.group_stability,
            operational_metrics=result.operational_metrics,
            lof_comparison=lof,
            one_class_svm_comparison=one_class_svm,
            pipeline_verification_only=pipeline_only,
            test_data_accessed=False,
            created_at=datetime.now(UTC),
        )
        store = AnomalyExperimentStore.create(self._reports_root, config.experiment_id)
        write_training_artifacts(
            store,
            config,
            data.manifest,
            evaluated.results,
            lof,
            one_class_svm,
            result,
            selection,
            selected.model_payload,
            selected.validation_labels,
            selected.validation_raw_scores,
            selected.validation_normalized_scores,
        )
        smoke: CandidateSmokeResult | None = None
        if config.candidate_status == "validation_qualified":
            smoke = self._save_validation_candidate(
                store=store,
                selection=selection,
                selected=selected,
                gate=gate,
            )
        return AnomalyTrainingRunResult(
            experiment_id=config.experiment_id,
            model_id=selection.model_id,
            model_version=selection.model_version,
            selected_candidate_id=selection.selected_candidate_id,
            selected_algorithm=selection.algorithm,
            pipeline_verification_only=pipeline_only,
            status=config.candidate_status,
            candidate_smoke_passed=smoke.passed if smoke is not None else None,
            selection=selection,
        )

    def evaluate_test(self, *, allow_controlled_demo: bool = False) -> AnomalyFrozenRunResult:
        """Run the explicit one-time test and finalize the safe anomaly bundle."""

        config = self._config()
        if config.candidate_status == "validation_qualified":
            raise AnomalyArtifactError(
                "validation-qualified corrective candidate requires a new independent holdout"
            )
        store = AnomalyExperimentStore.open(self._reports_root, config.experiment_id)
        if store.exists("anomaly_frozen_test_metrics.json"):
            raise AnomalyArtifactError("anomaly frozen test evaluation already exists")
        require_available_bundle_version(self._artifact_root, config.model_version)
        selection = store.read_selection()
        config_checksum = sha256_file(self._training_config_path)
        if selection.training_config_checksum != config_checksum:
            raise AnomalyArtifactError("anomaly configuration changed after model selection")
        gate = AnomalyDatasetGate(self._data_root, self._dataset_report_root)
        pipeline_only = self._require_controlled_permission(
            gate.evidence.dataset_manifest.dataset_type,
            allow_controlled_demo,
        )
        if pipeline_only != selection.pipeline_verification_only:
            raise AnomalyArtifactError("anomaly dataset research boundary changed after selection")
        estimator = load_selection_artifact(store.directory, selection)
        selection_payload = store.path("anomaly_model_selection.json").read_bytes()
        test = gate.load_frozen_test(selection)
        frozen = evaluate_frozen_test(
            estimator,
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
        manifest = AnomalyBundleManifest(
            manifest_schema_version="1.0.0",
            model_id=selection.model_id,
            model_version=selection.model_version,
            model_type="anomaly",
            algorithm=selection.algorithm,
            artifact_filename="model.skops",
            artifact_checksum=selection.selection_artifact_checksum,
            trusted_types=selection.trusted_types,
            preprocessing=selection.preprocessing,
            raw_score_method=selection.raw_score_method,
            canonical_score_transform=selection.canonical_score_transform,
            normalizer=selection.normalizer,
            anomaly_threshold=selection.threshold,
            threshold_policy=selection.threshold_policy,
            false_positive_rate_limit=selection.false_positive_rate_limit,
            feature_names=selection.feature_names,
            feature_schema_version=selection.feature_schema_version,
            expected_dtype=selection.expected_dtype,
            training_dataset_id=selection.dataset_id,
            training_dataset_version=selection.dataset_version,
            dataset_manifest_checksum=selection.dataset_manifest_checksum,
            split_manifest_checksum=selection.split_manifest_checksum,
            label_mapping_version=selection.label_mapping_version,
            training_config_checksum=selection.training_config_checksum,
            benign_training_rows=selection.benign_training_rows,
            benign_training_groups=selection.benign_training_groups,
            benign_training_identity_digest=selection.benign_training_identity_digest,
            random_seed=selection.random_seed,
            hyperparameters=selection.hyperparameters,
            validation_metrics=selection.validation_metrics,
            frozen_test_metrics=frozen.metrics,
            operational_metrics=selection.operational_metrics,
            pipeline_verification_only=selection.pipeline_verification_only,
            python_version=platform.python_version(),
            sklearn_version=sklearn.__version__,
            git_commit_sha=self._git_commit(),
            status="validated",
            created_at=datetime.now(UTC),
        )
        write_frozen_artifacts(store, frozen, manifest, model_card)
        save_bundle(self._artifact_root, manifest, model_payload, model_card)
        return AnomalyFrozenRunResult(
            report=frozen,
            bundle_version=manifest.model_version,
            pipeline_verification_only=pipeline_only,
        )

    def list_models(self) -> tuple[AnomalyBundleManifest, ...]:
        if not self._artifact_root.is_dir():
            return ()
        return tuple(
            load_manifest(path, artifact_root=self._artifact_root)
            for path in sorted(self._artifact_root.iterdir())
            if path.is_dir() and not path.name.startswith(".")
        )

    def describe(self, model_version: str) -> str:
        return manifest_as_safe_json(
            load_manifest(
                self._artifact_root / model_version,
                artifact_root=self._artifact_root,
            )
        )

    def verify(self, model_version: str) -> AnomalyBundleManifest:
        return load_bundle(
            self._artifact_root / model_version,
            artifact_root=self._artifact_root,
        ).manifest

    def predict(
        self,
        model_version: str,
        batch: AnomalyPredictionBatch,
    ) -> tuple[AnomalyPredictionResult, ...]:
        model = load_bundle(
            self._artifact_root / model_version,
            artifact_root=self._artifact_root,
        )
        return score_batch(model, batch)
