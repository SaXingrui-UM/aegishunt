"""Phase 7 controlled experiment and policy-integrity integration tests."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aegishunt.api.evaluation_service import FusionEvaluationArtifactReader
from aegishunt.config import ApplicationSettings, RuntimeSettings
from aegishunt.ml.fusion.artifacts import load_policy
from aegishunt.ml.fusion.contracts import FusionScoreInput
from aegishunt.ml.fusion.errors import FusionArtifactError
from aegishunt.ml.fusion.service import FusionEvaluationService
from tests.fixtures.anomaly import LOF_CANDIDATE_CONFIG_PATH
from tests.fixtures.datasets import LABEL_ROOT
from tests.fixtures.fusion import FUSION_CONFIG_PATH
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH


def _service(root: Path) -> FusionEvaluationService:
    return FusionEvaluationService(
        fusion_config_path=FUSION_CONFIG_PATH,
        supervised_config_path=CORRECTIVE_CONFIG_PATH,
        anomaly_config_path=LOF_CANDIDATE_CONFIG_PATH,
        label_mapping_path=LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml",
        experiment_root=root / "experiments",
        policy_root=root / "policies",
    )


def test_full_controlled_workflow_writes_truthful_evidence_and_verified_policy(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    result = service.evaluate(allow_controlled_demo=True)

    expected = {
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
    }
    assert {path.name for path in result.experiment_directory.iterdir()} == expected
    assert result.dataset.manifest.historical_frozen_test_reused is False
    assert len(result.experiment.leave_one_family_out) == 5
    assert len(result.experiment.parameter_shifts) == 4
    assert result.experiment.selection.evaluation_data_accessed is False
    assert result.experiment.selection.held_out_family_accessed is False
    assert result.experiment.known.fusion.selection_used_validation_only is True
    assert set(result.experiment.known.fusion_minus_supervised) == {
        "recall",
        "f1",
        "macro_f1",
        "pr_auc",
        "benign_false_positive_rate",
        "anomaly_false_negative_rate",
    }
    assert {
        comparison.held_out_family for comparison in result.experiment.leave_one_family_out
    } == set(result.dataset.eligible_attack_families)
    assert all(
        set(comparison.family_distribution) == {"benign", comparison.held_out_family}
        for comparison in result.experiment.leave_one_family_out
    )
    assert all(
        comparison.isolation.held_out_family_absent_from_train is True
        and comparison.isolation.held_out_family_absent_from_validation is True
        for comparison in result.experiment.leave_one_family_out
    )
    assert all(
        comparison.parameter_shift_audit is not None
        and comparison.parameter_shift_audit.group_overlap == ()
        for comparison in result.experiment.parameter_shifts
    )
    assert result.experiment.latency["temporary_supervised_model_size_bytes"] > 0
    assert result.experiment.latency["temporary_anomaly_model_size_bytes"] > 0
    assert {item.shift_axis for item in result.experiment.parameter_shifts} == {
        "flow_duration",
        "packet_rate",
        "packet_size_pattern",
        "connection_frequency",
    }
    assert all(
        comparison.confidence_intervals["fusion.recall"].requested_draws == 1000
        for comparison in (
            result.experiment.known,
            *result.experiment.leave_one_family_out,
            result.experiment.temporal,
            *result.experiment.parameter_shifts,
        )
    )
    assert result.policy.public_benchmark is False
    assert len(result.policy.candidate_weights) == 3
    assert result.policy.protocol_frozen_at < result.policy.created_at
    assert "not probability" in result.policy.fusion_score_semantics
    assert service.verify("1.0.0") == result.policy
    assert not any(path.suffix in {".pkl", ".joblib", ".skops"} for path in tmp_path.rglob("*"))
    descriptor, discovery = FusionEvaluationArtifactReader(
        ApplicationSettings(
            runtime=RuntimeSettings(
                fusion_policy_root=tmp_path / "policies",
                fusion_evaluation_root=tmp_path / "experiments",
                fusion_evaluation_experiment_id="phase-07-controlled-fusion-001",
            )
        )
    ).read()
    assert descriptor is not None
    assert descriptor.engine == "fusion"
    assert descriptor.metrics is not None
    assert descriptor.metrics["recommendation"] == "inconclusive"
    assert descriptor.metrics["known_attack_comparison"]
    assert descriptor.metrics["unseen_family_comparison"]
    assert descriptor.metrics["supervised_anomaly_fusion_comparison"]
    assert descriptor.metrics["confidence_intervals"]
    assert discovery.status == "available"
    assert discovery.recommendation == "inconclusive"
    assert discovery.artifact_hash is not None
    assert discovery.dataset_reference is not None
    assert discovery.split_reference is not None
    with pytest.raises(FusionArtifactError, match="already exists"):
        service.evaluate(allow_controlled_demo=True)


def test_policy_reload_is_deterministic_and_rejects_extra_corrupt_or_unsafe_files(
    tmp_path: Path,
) -> None:
    service = _service(tmp_path)
    result = service.evaluate(allow_controlled_demo=True)
    score_input = FusionScoreInput(
        supervised_probability=0.75,
        normalized_anomaly_score=0.25,
        supervised_model_id=result.policy.supervised_model_id,
        supervised_model_version=result.policy.supervised_model_version,
        anomaly_model_id=result.policy.anomaly_model_id,
        anomaly_model_version=result.policy.anomaly_model_version,
        feature_schema_version=result.policy.feature_schema_version,
    )
    first = service.score("1.0.0", score_input)
    second = service.score("1.0.0", score_input)
    assert first.fusion_score == second.fusion_score
    assert first.fusion_positive == second.fusion_positive

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(__file__).parents[2] / "src")
    independent = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; import sys; "
                "from aegishunt.ml.fusion.artifacts import load_policy; "
                "p=load_policy(Path(sys.argv[1]), root=Path(sys.argv[2])); "
                "print(p.policy_id, p.policy_version)"
            ),
            str(result.policy_directory),
            str(tmp_path / "policies"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
        cwd=Path(__file__).parents[2],
    )
    assert independent.returncode == 0
    assert independent.stdout.strip() == "aegishunt-fusion-controlled 1.0.0"

    copies = tmp_path / "copies"
    extra = copies / "extra" / "1.0.0"
    corrupt = copies / "corrupt" / "1.0.0"
    missing = copies / "missing" / "1.0.0"
    for destination in (extra, corrupt, missing):
        shutil.copytree(result.policy_directory, destination)
    (extra / "unexpected.json").write_text("{}\n", encoding="utf-8")
    manifest = corrupt / "fusion_policy_manifest.json"
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["selected_threshold"] = 0.99
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    (missing / "fusion_policy_card.md").unlink()

    with pytest.raises(FusionArtifactError, match="inventory"):
        load_policy(extra, root=copies / "extra")
    with pytest.raises(FusionArtifactError, match="checksum"):
        load_policy(corrupt, root=copies / "corrupt")
    with pytest.raises(FusionArtifactError, match="inventory"):
        load_policy(missing, root=copies / "missing")
    with pytest.raises(FusionArtifactError, match="outside"):
        load_policy(result.policy_directory, root=tmp_path / "different-root")

    symlink = copies / "symlink" / "1.0.0"
    shutil.copytree(result.policy_directory, symlink)
    card = symlink / "fusion_policy_card.md"
    external = tmp_path / "external-card.md"
    external.write_text("outside policy root\n", encoding="utf-8")
    card.unlink()
    card.symlink_to(external)
    with pytest.raises(FusionArtifactError, match="regular files"):
        load_policy(symlink, root=copies / "symlink")
