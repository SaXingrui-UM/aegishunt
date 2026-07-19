"""Application service for the complete offline Phase 7 research workflow."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import sklearn

from aegishunt.datasets.artifacts import safe_git_sha
from aegishunt.datasets.labels import LabelMapper
from aegishunt.ml.anomaly.config import AnomalyTrainingConfig
from aegishunt.ml.fusion.artifacts import (
    FusionExperimentStore,
    load_policy,
    policy_size_bytes,
    save_policy,
    sha256_file,
    write_experiment_evidence,
    write_final_experiment_evidence,
)
from aegishunt.ml.fusion.config import FusionExperimentConfig
from aegishunt.ml.fusion.contracts import FusionScoreInput, FusionScoreResult, PolicyManifest
from aegishunt.ml.fusion.dataset import (
    ControlledExperimentDataset,
    build_controlled_experiment_dataset,
)
from aegishunt.ml.fusion.errors import FusionArtifactError, FusionContractError
from aegishunt.ml.fusion.experiments import FusionExperimentRun, run_experiments
from aegishunt.ml.fusion.scoring import fuse_score
from aegishunt.ml.supervised.config import SupervisedTrainingConfig


@dataclass(frozen=True, slots=True)
class FusionRunResult:
    experiment_directory: Path
    policy_directory: Path
    dataset: ControlledExperimentDataset
    experiment: FusionExperimentRun
    policy: PolicyManifest


class FusionEvaluationService:
    """Coordinate independent controlled evidence without touching Phase 5/6 artifacts."""

    def __init__(
        self,
        *,
        fusion_config_path: Path,
        supervised_config_path: Path,
        anomaly_config_path: Path,
        label_mapping_path: Path,
        experiment_root: Path,
        policy_root: Path,
    ) -> None:
        self._fusion_config_path = fusion_config_path
        self._supervised_config_path = supervised_config_path
        self._anomaly_config_path = anomaly_config_path
        self._label_mapping_path = label_mapping_path
        self._experiment_root = experiment_root
        self._policy_root = policy_root

    def _load_inputs(
        self,
    ) -> tuple[
        FusionExperimentConfig,
        SupervisedTrainingConfig,
        AnomalyTrainingConfig,
        LabelMapper,
    ]:
        return (
            FusionExperimentConfig.load(self._fusion_config_path),
            SupervisedTrainingConfig.load(self._supervised_config_path),
            AnomalyTrainingConfig.load(self._anomaly_config_path),
            LabelMapper.load(self._label_mapping_path),
        )

    def evaluate(self, *, allow_controlled_demo: bool = False) -> FusionRunResult:
        """Run all pre-registered comparisons and freeze one policy exactly once."""

        if not allow_controlled_demo:
            raise FusionContractError(
                "controlled Phase 7 evidence requires explicit pipeline-verification permission"
            )
        fusion, supervised, anomaly, label_mapper = self._load_inputs()
        experiment_directory = self._experiment_root / fusion.experiment_id
        policy_directory = self._policy_root / fusion.policy_version
        if experiment_directory.exists() or experiment_directory.is_symlink():
            raise FusionArtifactError("fusion experiment identity already exists")
        if policy_directory.exists() or policy_directory.is_symlink():
            raise FusionArtifactError("fusion policy version already exists")
        dataset = build_controlled_experiment_dataset(fusion, label_mapper)
        run = run_experiments(
            dataset,
            fusion_config=fusion,
            supervised_config=supervised,
            anomaly_config=anomaly,
        )
        store = write_experiment_evidence(
            self._experiment_root,
            config=fusion,
            dataset=dataset,
            run=run,
        )
        policy = self._build_policy(fusion, store, run)
        saved_policy = save_policy(self._policy_root, policy, self._policy_card(policy, run))
        verified = load_policy(saved_policy, root=self._policy_root)
        if verified != policy:
            raise FusionArtifactError("independently loaded fusion policy differs")
        write_final_experiment_evidence(
            store,
            run=run,
            policy_artifact_size_bytes=policy_size_bytes(saved_policy),
        )
        return FusionRunResult(
            experiment_directory=store.directory,
            policy_directory=saved_policy,
            dataset=dataset,
            experiment=run,
            policy=policy,
        )

    def _build_policy(
        self,
        config: FusionExperimentConfig,
        store: FusionExperimentStore,
        run: FusionExperimentRun,
    ) -> PolicyManifest:
        return PolicyManifest(
            manifest_schema_version="1.0.0",
            policy_id=config.policy_id,
            policy_version=config.policy_version,
            status="controlled_experiment_evaluated",
            experiment_id=config.experiment_id,
            dataset_id=config.dataset_id,
            dataset_version=config.dataset_version,
            dataset_manifest_checksum=sha256_file(
                store.path("phase_07_dataset_manifest.json")
            ),
            split_manifest_checksum=sha256_file(store.path("phase_07_split_manifest.json")),
            experiment_protocol_checksum=sha256_file(
                store.path("phase_07_experiment_protocol.json")
            ),
            feature_schema_version=config.feature_schema_version,
            supervised_model_id=config.supervised_model_id,
            supervised_model_version=config.supervised_model_version,
            supervised_score_semantics="calibrated supervised probability",
            anomaly_model_id=config.anomaly_model_id,
            anomaly_model_version=config.anomaly_model_version,
            anomaly_score_semantics="bounded normalized anomaly score; not probability",
            selected_candidate_id=run.selection.selected_candidate_id,
            selected_weights=run.selection.selected_weights,
            selected_threshold=run.selection.selected_threshold,
            selection_policy_version=config.selection_policy_version,
            false_positive_rate_ceiling=config.false_positive_rate_ceiling,
            recommendation_status=run.selection.recommendation_status,
            known_evidence_checksum=sha256_file(store.path("known_attack_metrics.csv")),
            unseen_evidence_checksum=sha256_file(store.path("unseen_attack_metrics.csv")),
            temporal_evidence_checksum=sha256_file(store.path("temporal_holdout.csv")),
            parameter_shift_evidence_checksum=sha256_file(
                store.path("parameter_shift.csv")
            ),
            confidence_interval_checksum=sha256_file(
                store.path("confidence_intervals.json")
            ),
            git_commit_sha=safe_git_sha(),
            python_version=platform.python_version(),
            dependency_versions={
                "numpy": np.__version__,
                "scikit-learn": sklearn.__version__,
            },
            pipeline_verification_only=True,
            public_benchmark=False,
            fusion_score_semantics=(
                "experimental suspiciousness score; not probability, risk, severity, "
                "or attack confirmation"
            ),
            created_at=config.protocol_frozen_at,
        )

    @staticmethod
    def _policy_card(policy: PolicyManifest, run: FusionExperimentRun) -> str:
        return "\n".join(
            (
                "# AegisHunt Phase 7 Fusion Policy Card",
                "",
                "**CONTROLLED SYNTHETIC PIPELINE VERIFICATION ONLY.**",
                "",
                "This JSON-only policy combines a supervised probability and a bounded ",
                "normalized anomaly score. Its fusion score is experimental suspiciousness, ",
                "not attack probability, production risk, severity, or attack confirmation.",
                "",
                f"- Policy: `{policy.policy_id}` `{policy.policy_version}`",
                f"- Recommendation: `{policy.recommendation_status}`",
                f"- Selected candidate: `{policy.selected_candidate_id}`",
                f"- LOAO families evaluated: `{len(run.leave_one_family_out)}`",
                "- No historical Phase 5/6 frozen test was used for selection.",
                "- No public benchmark, real-world, production, or zero-day claim is made.",
                "- Negative and inconclusive results are retained.",
                "",
            )
        )

    def verify(self, policy_version: str) -> PolicyManifest:
        return load_policy(self._policy_root / policy_version, root=self._policy_root)

    def score(self, policy_version: str, score_input: FusionScoreInput) -> FusionScoreResult:
        policy = self.verify(policy_version)
        return fuse_score(score_input, policy)
