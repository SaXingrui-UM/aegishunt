"""Typed Phase 10 investigation-case operator commands."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import UUID

import typer

from aegishunt.cases.config import LoadedCaseFeedbackPolicy, load_case_feedback_policy
from aegishunt.cases.reports import CaseReportService
from aegishunt.cases.service import InvestigationCaseService
from aegishunt.config import load_settings
from aegishunt.errors import AegisHuntError
from aegishunt.schemas.enums import (
    AnalystVerdict,
    CaseEvidenceObjectType,
    CasePriority,
    CaseStatus,
)
from aegishunt.storage import Database
from aegishunt.storage.repositories import InvestigationCaseRepository

cases_app = typer.Typer(
    name="cases",
    help="Manage analyst-controlled investigation cases without confirming attacks.",
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


@cases_app.command("create-from-hypothesis")
def create_from_hypothesis(
    hypothesis_id: UUID,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    config: ConfigOption = None,
) -> None:
    """Create or return the deterministic primary case for one reviewable hypothesis."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).create_from_hypothesis(
                    hypothesis_id, actor=actor
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case creation", exc)


@cases_app.command("list")
def list_cases(
    limit: Annotated[int, typer.Option(min=1, max=1_000)] = 100,
    offset: Annotated[int, typer.Option(min=0)] = 0,
    status: CaseStatus | None = None,
    priority: CasePriority | None = None,
    assigned_to: str | None = None,
    config: ConfigOption = None,
) -> None:
    """List a bounded stable page of investigation work items."""

    try:
        database, loaded = _resources(config)
        try:
            if limit > loaded.policy.maximum_cases_per_query:
                raise typer.BadParameter("limit exceeds case policy")
            with database.session() as session:
                rows, total = InvestigationCaseRepository(session).list_page(
                    limit=limit,
                    offset=offset,
                    status=status,
                    priority=priority,
                    assigned_to=assigned_to,
                )
                typer.echo(
                    json.dumps(
                        {
                            "items": [item.model_dump(mode="json") for item in rows],
                            "limit": limit,
                            "offset": offset,
                            "total": total,
                            "semantics": "investigation work items; not confirmed attacks",
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case listing", exc)


@cases_app.command("describe")
def describe(case_id: UUID, config: ConfigOption = None) -> None:
    """Describe one case together with append-only notes and evidence references."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session:
                case, notes, references = InvestigationCaseService(
                    session, loaded
                ).describe(case_id)
                typer.echo(
                    json.dumps(
                        {
                            "case": case.model_dump(mode="json"),
                            "notes": [item.model_dump(mode="json") for item in notes],
                            "evidence_references": [
                                item.model_dump(mode="json") for item in references
                            ],
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case lookup", exc)


@cases_app.command("update-status")
def update_status(
    case_id: UUID,
    status: CaseStatus,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    reason: Annotated[str, typer.Option(min=1, max=4_000)],
    config: ConfigOption = None,
) -> None:
    """Apply a configured non-close lifecycle transition."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).update_status(
                    case_id, status, actor=actor, reason=reason
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case status update", exc)


@cases_app.command("set-priority")
def set_priority(
    case_id: UUID,
    priority: CasePriority,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    reason: Annotated[str, typer.Option(min=1, max=4_000)],
    config: ConfigOption = None,
) -> None:
    """Set investigation triage priority, which is not attack certainty."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).set_priority(
                    case_id, priority, actor=actor, reason=reason
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case priority update", exc)


def _assignment(
    case_id: UUID,
    assignee: str | None,
    actor: str,
    reason: str,
    config: Path | None,
) -> None:
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).assign(
                    case_id, assignee, actor=actor, reason=reason
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case assignment", exc)


@cases_app.command("assign")
def assign(
    case_id: UUID,
    assigned_to: Annotated[str, typer.Option(min=1, max=255)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    reason: Annotated[str, typer.Option(min=1, max=4_000)],
    config: ConfigOption = None,
) -> None:
    """Assign or reassign a bounded local analyst identifier."""

    _assignment(case_id, assigned_to, actor, reason, config)


@cases_app.command("unassign")
def unassign(
    case_id: UUID,
    actor: Annotated[str, typer.Option(min=1, max=255)],
    reason: Annotated[str, typer.Option(min=1, max=4_000)],
    config: ConfigOption = None,
) -> None:
    """Remove the local analyst assignment without external identity lookup."""

    _assignment(case_id, None, actor, reason, config)


@cases_app.command("add-note")
def add_note(
    case_id: UUID,
    body: Annotated[str, typer.Option(min=1)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    note_type: Annotated[
        str, typer.Option(help="investigation, closure, or correction")
    ] = "investigation",
    config: ConfigOption = None,
) -> None:
    """Append a note; notes cannot be edited or deleted."""

    if note_type not in {"investigation", "closure", "correction"}:
        raise typer.BadParameter("unsupported note type")
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).add_note(
                    case_id,
                    body,
                    actor=actor,
                    note_type=cast(
                        Literal["investigation", "closure", "correction"], note_type
                    ),
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case note append", exc)


@cases_app.command("add-evidence")
def add_evidence(
    case_id: UUID,
    object_type: CaseEvidenceObjectType,
    object_id: str,
    description: Annotated[str, typer.Option(min=1, max=1_000)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    config: ConfigOption = None,
) -> None:
    """Attach an allowlisted persisted object snapshot; files and URLs are unsupported."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).add_evidence(
                    case_id,
                    object_type,
                    object_id,
                    description=description,
                    actor=actor,
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case evidence attachment", exc)


@cases_app.command("set-verdict")
def set_verdict(
    case_id: UUID,
    verdict: AnalystVerdict,
    confidence: Annotated[float, typer.Option(min=0.0, max=1.0)],
    reason: Annotated[str, typer.Option(min=1, max=4_000)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    allow_update: Annotated[bool, typer.Option("--allow-update")] = False,
    config: ConfigOption = None,
) -> None:
    """Record a current analyst judgment, not machine or benchmark ground truth."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).set_verdict(
                    case_id,
                    verdict,
                    confidence=confidence,
                    reason=reason,
                    actor=actor,
                    allow_update=allow_update,
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case verdict update", exc)


@cases_app.command("close")
def close(
    case_id: UUID,
    closure_note: Annotated[str, typer.Option(min=1)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    config: ConfigOption = None,
) -> None:
    """Close a case after explicit confirmation, final verdict, and closure note."""

    if not confirm:
        raise typer.BadParameter("--confirm is required to close a case")
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                row = InvestigationCaseService(session, loaded).close(
                    case_id, closure_note=closure_note, actor=actor
                )
                typer.echo(row.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case closure", exc)


@cases_app.command("report")
def report(
    case_id: UUID,
    version: Annotated[str, typer.Option(min=1, max=128)],
    actor: Annotated[str, typer.Option(min=1, max=255)],
    confirm: Annotated[bool, typer.Option("--confirm")] = False,
    config: ConfigOption = None,
) -> None:
    """Generate a checksummed JSON/Markdown report without executing queries."""

    if not confirm:
        raise typer.BadParameter("--confirm is required to generate a case report")
    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session, session.begin():
                path, manifest = CaseReportService(
                    session, loaded, project_root=Path.cwd()
                ).generate(case_id, version, actor=actor)
                typer.echo(
                    json.dumps(
                        {
                            "report_id": manifest.report_id,
                            "report_version": manifest.report_version,
                            "relative_location": str(path.relative_to(Path.cwd())),
                        },
                        indent=2,
                    )
                )
        finally:
            database.dispose()
    except (AegisHuntError, ValueError) as exc:
        _failure("Case report", AegisHuntError(str(exc)))


@cases_app.command("verify-report")
def verify_report(
    case_id: UUID,
    version: Annotated[str, typer.Option(min=1, max=128)],
    config: ConfigOption = None,
) -> None:
    """Verify an existing report's containment, inventory, and checksums."""

    try:
        database, loaded = _resources(config)
        try:
            with database.session() as session:
                manifest = CaseReportService(
                    session, loaded, project_root=Path.cwd()
                ).verify(case_id, version)
                typer.echo(manifest.model_dump_json(indent=2))
        finally:
            database.dispose()
    except AegisHuntError as exc:
        _failure("Case report verification", exc)
