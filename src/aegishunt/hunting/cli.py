"""Typed operator commands for Phase 9 correlation and hunting leads."""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from aegishunt.config import load_settings
from aegishunt.correlation.config import LoadedCorrelationPolicy, load_correlation_policy
from aegishunt.correlation.service import AlertCorrelationService
from aegishunt.errors import AegisHuntError
from aegishunt.hunting.service import ThreatHypothesisService
from aegishunt.schemas.enums import HypothesisStatus
from aegishunt.storage import Database
from aegishunt.storage.repositories import AlertGroupRepository, ThreatHypothesisRepository

hunt_app = typer.Typer(
    name="hunt",
    help="Correlate alerts and inspect deterministic proposed hunting hypotheses.",
)
alert_groups_app = typer.Typer(name="alert-groups", help="Inspect persisted alert groups.")
hypotheses_app = typer.Typer(name="hypotheses", help="Inspect and review hypotheses.")
hunt_config_app = typer.Typer(name="config", help="Verify Phase 9 correlation policy.")
hunt_app.add_typer(alert_groups_app)
hunt_app.add_typer(hypotheses_app)
hunt_app.add_typer(hunt_config_app)

ConfigOption = Annotated[Path | None, typer.Option("--config", dir_okay=False)]


class HypothesisReviewStatus(StrEnum):
    """CLI-safe analyst transitions; confirmation is intentionally absent."""

    UNDER_REVIEW = "under_review"
    NEEDS_MORE_INFORMATION = "needs_more_information"
    DISMISSED = "dismissed"
    CLOSED_UNRESOLVED = "closed_unresolved"
    REJECTED = "rejected"


def _resources(config: Path | None) -> tuple[Database, LoadedCorrelationPolicy]:
    settings = load_settings(config)
    database = Database(settings.database)
    database.initialize()
    loaded = load_correlation_policy(settings.correlation.policy_path)
    return database, loaded


@hunt_app.command("correlate")
def correlate(
    actor: Annotated[str, typer.Option(min=1, max=255)] = "cli-analyst",
    config: ConfigOption = None,
) -> None:
    """Correlate eligible persisted alerts without modifying their evidence."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                groups = AlertCorrelationService(session, loaded).correlate(actor=actor)
                typer.echo(
                    json.dumps(
                        {
                            "group_count": len(groups),
                            "group_ids": [str(item.group_id) for item in groups],
                            "semantics": "correlation strength is not attack probability",
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert correlation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@alert_groups_app.command("list")
def list_alert_groups(
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    config: ConfigOption = None,
) -> None:
    """List alert groups in stable identifier order."""

    try:
        database, _ = _resources(config)
        try:
            with database.session() as session:
                rows, total = AlertGroupRepository(session).list_page(
                    limit=limit,
                    offset=offset,
                )
                typer.echo(
                    json.dumps(
                        {
                            "items": [row.model_dump(mode="json") for row in rows],
                            "limit": limit,
                            "offset": offset,
                            "total": total,
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert-group listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@alert_groups_app.command("describe")
def describe_alert_group(group_id: UUID, config: ConfigOption = None) -> None:
    """Describe one alert group and its retained rule evidence."""

    try:
        database, _ = _resources(config)
        try:
            with database.session() as session:
                repository = AlertGroupRepository(session)
                row = repository.get(group_id)
                if row is None:
                    typer.echo("Alert group does not exist.", err=True)
                    raise typer.Exit(code=2)
                payload = row.model_dump(mode="json")
                payload["member_alerts"] = [
                    member.model_dump(mode="json")
                    for member in repository.list_members(group_id)
                ]
                typer.echo(json.dumps(payload, indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Alert-group lookup failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@hunt_app.command("generate-hypotheses")
def generate_hypotheses(
    actor: Annotated[str, typer.Option(min=1, max=255)] = "cli-analyst",
    config: ConfigOption = None,
) -> None:
    """Generate deterministic proposed leads for eligible persisted groups."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                rows = ThreatHypothesisService(session, loaded).generate(actor=actor)
                typer.echo(
                    json.dumps(
                        {
                            "hypothesis_count": len(rows),
                            "hypothesis_ids": [str(item.hypothesis_id) for item in rows],
                            "status": "proposed",
                            "semantics": "hunting leads requiring analyst review",
                        },
                        indent=2,
                        sort_keys=True,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Hypothesis generation failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@hypotheses_app.command("list")
def list_hypotheses(
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    config: ConfigOption = None,
) -> None:
    """List persisted hypotheses without asserting confirmation."""

    try:
        database, _ = _resources(config)
        try:
            with database.session() as session:
                rows, total = ThreatHypothesisRepository(session).list_page(
                    limit=limit,
                    offset=offset,
                )
                typer.echo(
                    json.dumps(
                        {
                            "items": [row.model_dump(mode="json") for row in rows],
                            "limit": limit,
                            "offset": offset,
                            "total": total,
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Hypothesis listing failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@hypotheses_app.command("describe")
def describe_hypothesis(hypothesis_id: UUID, config: ConfigOption = None) -> None:
    """Describe one proposed or analyst-reviewed hypothesis."""

    try:
        database, _ = _resources(config)
        try:
            with database.session() as session:
                row = ThreatHypothesisRepository(session).get(hypothesis_id)
                if row is None:
                    typer.echo("Hypothesis does not exist.", err=True)
                    raise typer.Exit(code=2)
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Hypothesis lookup failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@hypotheses_app.command("update-status")
def update_hypothesis_status(
    hypothesis_id: UUID,
    status: HypothesisReviewStatus,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    config: ConfigOption = None,
) -> None:
    """Apply a safe analyst lifecycle transition; direct confirmation is prohibited."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = ThreatHypothesisService(session, loaded).update_status(
                    hypothesis_id,
                    HypothesisStatus(status.value),
                    actor=actor,
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        typer.echo(f"Hypothesis status update failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@hunt_config_app.command("verify")
def verify_config(config: ConfigOption = None) -> None:
    """Validate and checksum the configured correlation policy."""

    try:
        settings = load_settings(config)
        loaded = load_correlation_policy(settings.correlation.policy_path)
    except AegisHuntError as exc:
        typer.echo(f"Correlation configuration verification failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        json.dumps(
            {
                "status": "verified",
                "policy_id": loaded.policy.policy_id,
                "policy_version": loaded.policy.policy_version,
                "checksum": loaded.configuration_checksum,
                "semantics": loaded.policy.score_semantics,
            },
            indent=2,
            sort_keys=True,
        )
    )
