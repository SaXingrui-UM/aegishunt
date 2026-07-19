"""Offline Phase 7 evaluation, policy verification, and pure scoring CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from aegishunt.errors import AegisHuntError
from aegishunt.ml.fusion.contracts import FusionScoreInput
from aegishunt.ml.fusion.errors import FusionError
from aegishunt.ml.fusion.service import FusionEvaluationService

fusion_app = typer.Typer(
    name="fusion",
    help="Run controlled dual-engine experiments without alerts, risk, or severity.",
    no_args_is_help=True,
)

def _service(
    fusion_config: Path,
    supervised_config: Path,
    anomaly_config: Path,
    label_mapping: Path,
    experiment_root: Path,
    policy_root: Path,
) -> FusionEvaluationService:
    return FusionEvaluationService(
        fusion_config_path=fusion_config,
        supervised_config_path=supervised_config,
        anomaly_config_path=anomaly_config,
        label_mapping_path=label_mapping,
        experiment_root=experiment_root,
        policy_root=policy_root,
    )


def _fail(exc: AegisHuntError | OSError | ValidationError) -> None:
    message = str(exc) if isinstance(exc, FusionError) else "configuration or input was rejected"
    typer.echo(f"Fusion operation failed: {message}", err=True)
    raise typer.Exit(code=1) from exc


@fusion_app.command("evaluate")
def evaluate_fusion(
    fusion_config: Annotated[
        Path,
        typer.Option("--fusion-config", exists=True, dir_okay=False, readable=True),
    ],
    supervised_config: Annotated[
        Path,
        typer.Option("--supervised-config", exists=True, dir_okay=False, readable=True),
    ],
    anomaly_config: Annotated[
        Path,
        typer.Option("--anomaly-config", exists=True, dir_okay=False, readable=True),
    ],
    label_mapping: Annotated[
        Path,
        typer.Option("--label-mapping", exists=True, dir_okay=False, readable=True),
    ],
    experiment_root: Annotated[
        Path,
        typer.Option("--experiment-root", file_okay=False, writable=True),
    ],
    policy_root: Annotated[
        Path,
        typer.Option("--policy-root", file_okay=False, writable=True),
    ],
    allow_controlled_demo: Annotated[
        bool,
        typer.Option(
            "--allow-controlled-demo",
            help="Explicitly permit controlled synthetic pipeline verification.",
        ),
    ] = False,
) -> None:
    """Run known, LOAO, temporal, and fixed parameter-shift comparisons."""

    try:
        result = _service(
            fusion_config,
            supervised_config,
            anomaly_config,
            label_mapping,
            experiment_root,
            policy_root,
        ).evaluate(allow_controlled_demo=allow_controlled_demo)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "experiment_id": result.policy.experiment_id,
                "policy_id": result.policy.policy_id,
                "policy_version": result.policy.policy_version,
                "recommendation_status": result.policy.recommendation_status,
                "selected_candidate_id": result.policy.selected_candidate_id,
                "known_attack_comparison": True,
                "loao_family_count": len(result.experiment.leave_one_family_out),
                "temporal_holdout": True,
                "parameter_shift_count": len(result.experiment.parameter_shifts),
                "bootstrap_draws": result.experiment.known.confidence_intervals[
                    "fusion.recall"
                ].requested_draws,
                "pipeline_verification_only": True,
                "public_benchmark": False,
                "fusion_score_semantics": result.policy.fusion_score_semantics,
            },
            indent=2,
            sort_keys=True,
        )
    )


@fusion_app.command("verify")
def verify_policy(
    policy_version: str,
    policy_root: Annotated[Path, typer.Option("--policy-root", file_okay=False, readable=True)],
) -> None:
    """Verify exact JSON policy inventory and checksums before loading."""

    try:
        policy = FusionEvaluationService(
            fusion_config_path=Path(),
            supervised_config_path=Path(),
            anomaly_config_path=Path(),
            label_mapping_path=Path(),
            experiment_root=Path(),
            policy_root=policy_root,
        ).verify(policy_version)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(
        json.dumps(
            {
                "policy_id": policy.policy_id,
                "policy_version": policy.policy_version,
                "status": "verified",
                "recommendation_status": policy.recommendation_status,
                "fusion_score_semantics": policy.fusion_score_semantics,
            },
            indent=2,
            sort_keys=True,
        )
    )


@fusion_app.command("describe")
def describe_policy(
    policy_version: str,
    policy_root: Annotated[Path, typer.Option("--policy-root", file_okay=False, readable=True)],
) -> None:
    """Print a verified policy manifest without local filesystem paths."""

    try:
        policy = FusionEvaluationService(
            fusion_config_path=Path(),
            supervised_config_path=Path(),
            anomaly_config_path=Path(),
            label_mapping_path=Path(),
            experiment_root=Path(),
            policy_root=policy_root,
        ).verify(policy_version)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(json.dumps(policy.model_dump(mode="json"), indent=2, sort_keys=True))


@fusion_app.command("score")
def score_fusion(
    policy_version: str,
    input_path: Annotated[
        Path,
        typer.Option("--input", exists=True, dir_okay=False, readable=True),
    ],
    policy_root: Annotated[Path, typer.Option("--policy-root", file_okay=False, readable=True)],
) -> None:
    """Apply one verified policy without creating alerts or risk output."""

    try:
        score_input = FusionScoreInput.model_validate_json(input_path.read_text(encoding="utf-8"))
        result = FusionEvaluationService(
            fusion_config_path=Path(),
            supervised_config_path=Path(),
            anomaly_config_path=Path(),
            label_mapping_path=Path(),
            experiment_root=Path(),
            policy_root=policy_root,
        ).score(policy_version, score_input)
    except (AegisHuntError, OSError, ValidationError) as exc:
        _fail(exc)
    typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True))
