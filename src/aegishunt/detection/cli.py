"""Typed Phase 8 detection, alert, and explanation command groups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from aegishunt.config import ApplicationSettings, load_settings
from aegishunt.detection.adapters import ModelBundleScoreAdapter
from aegishunt.detection.config import load_risk_policy
from aegishunt.detection.service import DetectionAlertService
from aegishunt.errors import AegisHuntError
from aegishunt.explainability.artifacts import load_explanation_artifact
from aegishunt.ml.anomaly.bundle import load_bundle as load_anomaly_bundle
from aegishunt.ml.fusion.artifacts import load_policy, sha256_file
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised_bundle
from aegishunt.schemas.enums import AnalystVerdict
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AuditLogRepository,
    DetectionResultRepository,
    NetworkFlowRepository,
    SecurityAlertRepository,
)

detection_app = typer.Typer(name="detection", help="Evaluate and inspect Phase 8 detections.")
alerts_app = typer.Typer(name="alerts", help="Inspect alerts and record analyst verdicts.")
explainability_app = typer.Typer(
    name="explainability",
    help="Verify data-only Phase 8 explanation artifacts.",
)

ConfigOption = Annotated[Path | None, typer.Option("--config", dir_okay=False)]


def _database(config: Path | None) -> tuple[Database, ApplicationSettings]:
    settings = load_settings(config)
    database = Database(settings.database)
    database.initialize()
    return database, settings


@detection_app.command("list")
def list_detections(config: ConfigOption = None) -> None:
    """List persisted detection records in stable identifier order."""

    try:
        database, _ = _database(config)
        try:
            with database.session() as session:
                rows = DetectionResultRepository(session).list()
                typer.echo(json.dumps([row.model_dump(mode="json") for row in rows], indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Detection listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@detection_app.command("describe")
def describe_detection(detection_id: UUID, config: ConfigOption = None) -> None:
    """Describe one persisted detection without emitting a traceback."""

    try:
        database, _ = _database(config)
        try:
            with database.session() as session:
                row = DetectionResultRepository(session).get(detection_id)
                if row is None:
                    typer.echo("Detection does not exist.", err=True)
                    raise typer.Exit(code=2)
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Detection lookup failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@detection_app.command("evaluate")
def evaluate_detection(
    flow_id: UUID,
    supervised_bundle: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    supervised_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    anomaly_bundle: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    anomaly_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    fusion_policy: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    fusion_root: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    explanation_artifact: Annotated[Path, typer.Option(exists=True, file_okay=False)],
    actor: Annotated[str, typer.Option(min=1, max=255)] = "cli-analyst",
    config: ConfigOption = None,
) -> None:
    """Evaluate one persisted canonical flow through verified offline artifacts."""

    try:
        database, settings = _database(config)
        try:
            risk_policy = load_risk_policy(settings.detection.risk_policy_path)
            explanation = load_explanation_artifact(
                explanation_artifact,
                root=settings.detection.explanation_artifact_root,
            )
            supervised = load_supervised_bundle(
                supervised_bundle,
                artifact_root=supervised_root,
            )
            anomaly = load_anomaly_bundle(anomaly_bundle, artifact_root=anomaly_root)
            policy = load_policy(fusion_policy, root=fusion_root)
            scorer = ModelBundleScoreAdapter(
                supervised_model=supervised,
                anomaly_model=anomaly,
                fusion_policy=policy,
                fusion_policy_checksum=sha256_file(
                    fusion_policy / "fusion_policy_manifest.json"
                ),
            )
            with database.session() as session, session.begin():
                flow = NetworkFlowRepository(session).get(flow_id)
                if flow is None:
                    typer.echo("Flow does not exist.", err=True)
                    raise typer.Exit(code=2)
                service = DetectionAlertService(
                    session,
                    risk_policy=risk_policy,
                    explanation_artifact=explanation,
                    local_top_k=settings.detection.local_explanation_top_k,
                    local_max_features=settings.detection.local_explanation_max_features,
                )
                detection, alert = service.evaluate_flow(flow, scorer, actor=actor)
                output = {
                    "detection_id": str(detection.detection_id),
                    "alert_id": None if alert is None else str(alert.alert_id),
                    "alert_created": alert is not None,
                }
                typer.echo(json.dumps(output, indent=2, sort_keys=True))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Detection evaluation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@alerts_app.command("list")
def list_alerts(config: ConfigOption = None) -> None:
    """List persisted alerts without correlation or grouping."""

    try:
        database, _ = _database(config)
        try:
            with database.session() as session:
                rows = SecurityAlertRepository(session).list()
                typer.echo(json.dumps([row.model_dump(mode="json") for row in rows], indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@alerts_app.command("describe")
def describe_alert(alert_id: UUID, config: ConfigOption = None) -> None:
    """Describe one analyst-reviewable alert."""

    try:
        database, _ = _database(config)
        try:
            with database.session() as session:
                row = SecurityAlertRepository(session).get(alert_id)
                if row is None:
                    typer.echo("Alert does not exist.", err=True)
                    raise typer.Exit(code=2)
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert lookup failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@alerts_app.command("verdict")
def set_alert_verdict(
    alert_id: UUID,
    verdict: AnalystVerdict,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    config: ConfigOption = None,
) -> None:
    """Set the alert-level verdict without training, cases, or hypotheses."""

    try:
        database, _ = _database(config)
        try:
            with database.session() as session, session.begin():
                row = SecurityAlertRepository(
                    session,
                    audit_log=None,
                ).get(alert_id)
                if row is None:
                    typer.echo("Alert does not exist.", err=True)
                    raise typer.Exit(code=2)
                updated = SecurityAlertRepository(
                    session,
                    AuditLogRepository(session),
                ).update_verdict(alert_id, verdict, actor=actor)
                typer.echo(updated.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert verdict update failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@explainability_app.command("verify")
def verify_explanation_artifact(
    artifact: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    config: ConfigOption = None,
) -> None:
    """Verify the exact inventory, checksums, and identities of one artifact."""

    try:
        settings = load_settings(config)
        loaded = load_explanation_artifact(
            artifact,
            root=settings.detection.explanation_artifact_root,
        )
    except AegisHuntError as exc:
        typer.echo(f"Explanation verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        json.dumps(
            {
                "status": "verified",
                "artifact_id": loaded.manifest.artifact_id,
                "artifact_version": loaded.manifest.artifact_version,
                "feature_schema_version": loaded.manifest.feature_schema_version,
                "semantics": "non-causal evidence for analyst review",
            },
            indent=2,
            sort_keys=True,
        )
    )


@explainability_app.command("describe")
def describe_explanation_artifact(
    artifact: Annotated[Path, typer.Argument(exists=True, file_okay=False)],
    config: ConfigOption = None,
) -> None:
    """Describe one verified explanation artifact manifest."""

    try:
        settings = load_settings(config)
        loaded = load_explanation_artifact(
            artifact,
            root=settings.detection.explanation_artifact_root,
        )
    except AegisHuntError as exc:
        typer.echo(f"Explanation lookup failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(loaded.manifest.model_dump_json(indent=2))
