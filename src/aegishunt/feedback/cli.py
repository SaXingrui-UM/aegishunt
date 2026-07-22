"""Typed Phase 10 analyst-feedback and data-only artifact commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from aegishunt.cases.config import LoadedCaseFeedbackPolicy, load_case_feedback_policy
from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.feedback.candidates import RetrainingCandidateService
from aegishunt.feedback.export import FeedbackExportService
from aegishunt.feedback.service import AnalystFeedbackService
from aegishunt.schemas.enums import AnalystVerdict, FeedbackObjectType
from aegishunt.storage import Database
from aegishunt.storage.repositories import AnalystFeedbackRepository

feedback_app = typer.Typer(
    name="feedback",
    help="Record and export auditable human judgments without automatic training.",
)
ConfigOption = Annotated[Path | None, typer.Option("--config", dir_okay=False)]


def _resources(config: Path | None) -> tuple[Database, LoadedCaseFeedbackPolicy]:
    settings = load_settings(config)
    database = Database(settings.database)
    database.initialize()
    return database, load_case_feedback_policy(settings.case_feedback.policy_path)


def _failure(operation: str, exc: AegisHuntError) -> None:
    typer.echo(f"{operation} failed: {exc}", err=True)
    raise typer.Exit(code=1) from exc


def _record_alert(
    alert_id: UUID,
    verdict: AnalystVerdict,
    confidence: float,
    notes: str,
    actor: str,
    source: str,
    allow_update: bool,
    correction_reason: str | None,
    related_case_id: UUID | None,
    config: Path | None,
) -> None:
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = AnalystFeedbackService(session, loaded).record_alert(
                    alert_id,
                    verdict,
                    confidence=confidence,
                    notes=notes,
                    actor=actor,
                    source=source,
                    allow_update=allow_update,
                    correction_reason=correction_reason,
                    related_case_id=related_case_id,
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Alert feedback", exc)


@feedback_app.command("record-alert")
def record_alert(
    alert_id: UUID,
    verdict: AnalystVerdict,
    confidence: Annotated[float, typer.Option(min=0.0, max=1.0)],
    notes: Annotated[str, typer.Option(min=1, max=4_000)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    source: Annotated[str, typer.Option(min=1, max=255)] = "analyst_cli",
    related_case_id: UUID | None = None,
    config: ConfigOption = None,
) -> None:
    """Create alert feedback and keep the alert verdict consistent transactionally."""

    _record_alert(
        alert_id,
        verdict,
        confidence,
        notes,
        actor,
        source,
        False,
        None,
        related_case_id,
        config,
    )


@feedback_app.command("update-alert")
def update_alert(
    alert_id: UUID,
    verdict: AnalystVerdict,
    confidence: Annotated[float, typer.Option(min=0.0, max=1.0)],
    notes: Annotated[str, typer.Option(min=1, max=4_000)],
    correction_reason: Annotated[str, typer.Option(min=1, max=4_000)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    source: Annotated[str, typer.Option(min=1, max=255)] = "analyst_cli",
    related_case_id: UUID | None = None,
    config: ConfigOption = None,
) -> None:
    """Explicitly correct alert feedback without silently overwriting history."""

    _record_alert(
        alert_id,
        verdict,
        confidence,
        notes,
        actor,
        source,
        True,
        correction_reason,
        related_case_id,
        config,
    )


@feedback_app.command("record-case")
def record_case(
    case_id: UUID,
    verdict: AnalystVerdict,
    confidence: Annotated[float, typer.Option(min=0.0, max=1.0)],
    notes: Annotated[str, typer.Option(min=1, max=4_000)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    source: Annotated[str, typer.Option(min=1, max=255)] = "case_verdict",
    allow_update: Annotated[bool, typer.Option("--allow-update")] = False,
    correction_reason: str | None = None,
    config: ConfigOption = None,
) -> None:
    """Record case feedback only when it matches the persisted explicit case verdict."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = AnalystFeedbackService(session, loaded).record_case(
                    case_id,
                    verdict,
                    confidence=confidence,
                    notes=notes,
                    actor=actor,
                    source=source,
                    allow_update=allow_update,
                    correction_reason=correction_reason,
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case feedback", exc)


@feedback_app.command("describe")
def describe(feedback_id: UUID, config: ConfigOption = None) -> None:
    """Describe one persisted human judgment."""

    try:
        database, _ = _resources(config)
        try:
            with database.session() as session:
                row = AnalystFeedbackRepository(session).get(feedback_id)
                if row is None:
                    typer.echo("Feedback does not exist.", err=True)
                    raise typer.Exit(code=2)
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Feedback lookup", exc)


@feedback_app.command("list")
def list_feedback(
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    object_type: FeedbackObjectType | None = None,
    object_id: str | None = None,
    verdict: AnalystVerdict | None = None,
    actor: str | None = None,
    config: ConfigOption = None,
) -> None:
    """List bounded feedback with deterministic order and typed filters."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session:
                rows, total = AnalystFeedbackService(session, loaded).list(
                    limit=limit,
                    offset=offset,
                    object_type=object_type,
                    object_id=object_id,
                    verdict=verdict,
                    actor=actor,
                )
                typer.echo(
                    json.dumps(
                        {
                            "items": [item.model_dump(mode="json") for item in rows],
                            "limit": limit,
                            "offset": offset,
                            "total": total,
                            "trust_boundary": "human supplied; potentially noisy",
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Feedback listing", exc)


@feedback_app.command("export")
def export_feedback(
    version: Annotated[str, typer.Option(min=1, max=128)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    object_type: FeedbackObjectType | None = None,
    verdict: AnalystVerdict | None = None,
    config: ConfigOption = None,
) -> None:
    """Explicitly export feedback as checksummed data, not a training dataset."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                path, manifest = FeedbackExportService(
                    session, loaded, project_root=Path.cwd()
                ).export(version, actor=actor, object_type=object_type, verdict=verdict)
                typer.echo(
                    json.dumps(
                        {
                            "export_id": manifest.export_id,
                            "record_count": manifest.record_count,
                            "relative_location": str(path.relative_to(Path.cwd())),
                            "training_invoked": False,
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except (AegisHuntError, ValueError) as exc:
        _failure("Feedback export", AegisHuntError(str(exc)))


@feedback_app.command("verify-export")
def verify_export(
    version: Annotated[str, typer.Option(min=1, max=128)],
    config: ConfigOption = None,
) -> None:
    """Verify feedback-export path containment, inventory, and checksums."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session:
                manifest = FeedbackExportService(
                    session, loaded, project_root=Path.cwd()
                ).verify(version)
                typer.echo(manifest.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Feedback export verification", exc)


@feedback_app.command("build-retraining-candidates")
def build_retraining_candidates(
    version: Annotated[str, typer.Option(min=1, max=128)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    config: ConfigOption = None,
) -> None:
    """Build review-only candidate data; never train or activate a model."""

    if not confirm:
        raise typer.BadParameter("--confirm is required for candidate construction")
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                path, manifest = RetrainingCandidateService(
                    session, loaded, project_root=Path.cwd()
                ).build(version, actor=actor)
                typer.echo(
                    json.dumps(
                        {
                            "dataset_id": manifest.dataset_id,
                            "status": manifest.status,
                            "eligibility_status": manifest.eligibility_status,
                            "candidate_count": manifest.candidate_count,
                            "exclusion_count": manifest.exclusion_count,
                            "conflict_count": manifest.conflict_count,
                            "relative_location": str(path.relative_to(Path.cwd())),
                            "training_invoked": False,
                            "model_activation_invoked": False,
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Candidate construction", exc)


@feedback_app.command("verify-candidates")
def verify_candidates(
    version: Annotated[str, typer.Option(min=1, max=128)],
    config: ConfigOption = None,
) -> None:
    """Verify a candidate artifact without invoking model code."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session:
                manifest = RetrainingCandidateService(
                    session, loaded, project_root=Path.cwd()
                ).verify(version)
                typer.echo(manifest.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Candidate verification", exc)
