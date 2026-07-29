"""Offline CLI E2E from controlled groups through reloaded fusion policy."""

import json
from pathlib import Path

from typer.testing import CliRunner

from aegishunt.cli import app
from aegishunt.ml.fusion.contracts import FusionScoreInput
from tests.fixtures.anomaly import LOF_CANDIDATE_CONFIG_PATH
from tests.fixtures.datasets import LABEL_ROOT
from tests.fixtures.fusion import FUSION_CONFIG_PATH
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH

runner = CliRunner()


def test_phase_07_cli_evaluates_verifies_and_scores_offline(tmp_path: Path) -> None:
    experiment_root = tmp_path / "experiments"
    policy_root = tmp_path / "policies"
    evaluation = runner.invoke(
        app,
        [
            "fusion",
            "evaluate",
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--supervised-config",
            str(CORRECTIVE_CONFIG_PATH),
            "--anomaly-config",
            str(LOF_CANDIDATE_CONFIG_PATH),
            "--label-mapping",
            str(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml"),
            "--experiment-root",
            str(experiment_root),
            "--policy-root",
            str(policy_root),
            "--allow-controlled-demo",
        ],
    )

    assert evaluation.exit_code == 0, evaluation.stdout
    payload = json.loads(evaluation.stdout)
    assert payload["known_attack_comparison"] is True
    assert payload["loao_family_count"] == 5
    assert payload["temporal_holdout"] is True
    assert payload["parameter_shift_count"] == 4
    assert payload["bootstrap_draws"] == 1000
    assert payload["pipeline_verification_only"] is True
    assert payload["public_benchmark"] is False
    assert "not probability" in payload["fusion_score_semantics"]

    verification = runner.invoke(
        app,
        ["fusion", "verify", "1.0.0", "--policy-root", str(policy_root)],
    )
    assert verification.exit_code == 0
    assert json.loads(verification.stdout)["status"] == "verified"

    score_input = FusionScoreInput(
        supervised_probability=0.7,
        normalized_anomaly_score=0.4,
        supervised_model_id="aegishunt-supervised-1.0.1",
        supervised_model_version="1.0.1",
        anomaly_model_id="aegishunt-anomaly-1.1.0-candidate",
        anomaly_model_version="1.1.0-candidate",
        feature_schema_version="1.0.0",
    )
    input_path = tmp_path / "score-input.json"
    input_path.write_text(score_input.model_dump_json(), encoding="utf-8")
    scoring = runner.invoke(
        app,
        [
            "fusion",
            "score",
            "1.0.0",
            "--input",
            str(input_path),
            "--policy-root",
            str(policy_root),
        ],
    )
    score_payload = json.loads(scoring.stdout)
    assert scoring.exit_code == 0
    assert "fusion_score" in score_payload
    assert "not probability" in score_payload["semantics"]
    assert not any(key in score_payload for key in ("alert", "risk", "severity", "reason"))


def test_phase_07_cli_refuses_implicit_controlled_evidence(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "fusion",
            "evaluate",
            "--fusion-config",
            str(FUSION_CONFIG_PATH),
            "--supervised-config",
            str(CORRECTIVE_CONFIG_PATH),
            "--anomaly-config",
            str(LOF_CANDIDATE_CONFIG_PATH),
            "--label-mapping",
            str(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml"),
            "--experiment-root",
            str(tmp_path / "experiments"),
            "--policy-root",
            str(tmp_path / "policies"),
        ],
    )

    assert result.exit_code == 1
    assert "explicit pipeline-verification permission" in result.output
    assert "Traceback" not in result.output
    assert str(tmp_path) not in result.output
