"""Controlled Phase 10 case/feedback evidence with explicit provenance."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from aegishunt.cases.config import LoadedCaseFeedbackPolicy, load_case_feedback_policy
from aegishunt.correlation.service import AlertCorrelationService
from aegishunt.hunting.service import ThreatHypothesisService
from aegishunt.schemas import SecurityAlert, ThreatHypothesis
from aegishunt.storage import Database
from aegishunt.storage.repositories import TelemetrySourceRepository
from tests.fixtures.hunting import (
    GROUP_GENERATED_AT,
    HYPOTHESIS_GENERATED_AT,
    alert,
    correlation_policy,
    seed_alerts,
)

CASE_CREATED_AT = HYPOTHESIS_GENERATED_AT + timedelta(days=40)
CASE_UPDATED_AT = CASE_CREATED_AT + timedelta(minutes=1)
CASE_CLOSED_AT = CASE_CREATED_AT + timedelta(minutes=10)


def case_policy() -> LoadedCaseFeedbackPolicy:
    return load_case_feedback_policy(
        Path(__file__).parents[2] / "configs" / "case_feedback.yaml"
    )


def eligible_source_metadata() -> dict[str, str]:
    return {
        "provenance_partition": "runtime",
        "provenance_type": "operational_feedback",
        "dataset_id": "phase-10-controlled-observation",
        "dataset_version": "1.0.0",
        "scenario_id": "controlled-case-workflow",
        "group_id": "capture-session-001",
    }


def seed_reviewable_hypothesis(
    database: Database,
    *,
    source_metadata: dict[str, str] | None = None,
    source_alerts: list[SecurityAlert] | None = None,
) -> ThreatHypothesis:
    """Persist FK-complete Phase 8/9 evidence and one proposed hypothesis."""

    alerts = source_alerts or [
        alert(1, destination_ip="198.51.100.10", seconds=0),
        alert(2, destination_ip="198.51.100.11", seconds=10),
        alert(3, destination_ip="198.51.100.12", seconds=20),
    ]
    seed_alerts(database, alerts)
    if source_metadata is not None:
        with database.session() as session, session.begin():
            repository = TelemetrySourceRepository(session)
            source = repository.list()[0]
            repository.update(
                source.model_copy(update={"source_metadata": source_metadata}),
                actor="phase-10-fixture",
            )
    loaded = correlation_policy()
    with database.session() as session, session.begin():
        groups = AlertCorrelationService(
            session, loaded, clock=lambda: GROUP_GENERATED_AT
        ).correlate(actor="phase-10-fixture")
        hypotheses = ThreatHypothesisService(
            session, loaded, clock=lambda: HYPOTHESIS_GENERATED_AT
        ).generate(actor="phase-10-fixture")
        assert len(groups) == len(hypotheses) == 1
        return hypotheses[0]
