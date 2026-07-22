"""Phase 9 persistence, restart, idempotency, and lifecycle integration."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from aegishunt.config import DatabaseSettings
from aegishunt.correlation.service import AlertCorrelationService
from aegishunt.hunting.errors import HypothesisTransitionError
from aegishunt.hunting.service import ThreatHypothesisService
from aegishunt.schemas.enums import HypothesisStatus
from aegishunt.storage import Database
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    SecurityAlertRepository,
    ThreatHypothesisRepository,
)
from tests.fixtures.hunting import (
    GROUP_GENERATED_AT,
    HYPOTHESIS_GENERATED_AT,
    STATUS_UPDATED_AT,
    alert,
    correlation_policy,
    seed_alerts,
)


def _database(path: Path) -> Database:
    database = Database(DatabaseSettings(url=f"sqlite:///{path}"))
    assert database.initialize() == 3
    return database


def test_correlation_hypothesis_restart_and_audited_status(tmp_path: Path) -> None:
    path = tmp_path / "phase-09.sqlite3"
    database = _database(path)
    alerts = [
        alert(1, destination_ip="198.51.100.10", seconds=0),
        alert(2, destination_ip="198.51.100.11", seconds=10),
        alert(3, destination_ip="198.51.100.12", seconds=20),
    ]
    original_evidence = {str(item.alert_id): item.evidence for item in alerts}
    seed_alerts(database, alerts)
    loaded = correlation_policy()
    try:
        with database.session() as session, session.begin():
            correlation = AlertCorrelationService(
                session,
                loaded,
                clock=lambda: GROUP_GENERATED_AT,
            )
            first_groups = correlation.correlate(actor="integration-correlation")
            second_groups = AlertCorrelationService(
                session,
                loaded,
                clock=lambda: GROUP_GENERATED_AT + timedelta(days=10),
            ).correlate(actor="integration-correlation")
            assert first_groups == second_groups
            assert len(first_groups) == 1
            assert first_groups[0].first_seen < first_groups[0].last_seen
            assert first_groups[0].created_at == GROUP_GENERATED_AT
            assert first_groups[0].created_at != first_groups[0].last_seen

            hypotheses = ThreatHypothesisService(
                session,
                loaded,
                clock=lambda: HYPOTHESIS_GENERATED_AT,
            )
            first_hypotheses = hypotheses.generate(actor="integration-hunting")
            second_hypotheses = ThreatHypothesisService(
                session,
                loaded,
                clock=lambda: HYPOTHESIS_GENERATED_AT + timedelta(days=10),
            ).generate(actor="integration-hunting")
            assert first_hypotheses == second_hypotheses
            assert len(first_hypotheses) == 1
            assert first_hypotheses[0].status is HypothesisStatus.PROPOSED
            assert first_hypotheses[0].created_at == HYPOTHESIS_GENERATED_AT
            assert first_hypotheses[0].updated_at == HYPOTHESIS_GENERATED_AT
            assert first_hypotheses[0].created_at != first_groups[0].last_seen

        database.dispose()
        database = _database(path)
        with database.session() as session, session.begin():
            groups = AlertGroupRepository(session).list()
            hypotheses = ThreatHypothesisRepository(session).list()
            assert groups == list(first_groups)
            assert groups[0].created_at == GROUP_GENERATED_AT
            member_ids = [
                str(item.alert_id)
                for item in AlertGroupRepository(session).list_members(groups[0].group_id)
            ]
            assert member_ids == groups[0].alert_ids
            assert hypotheses == list(first_hypotheses)
            assert {
                str(item.alert_id): item.evidence
                for item in SecurityAlertRepository(session).list()
            } == original_evidence

            service = ThreatHypothesisService(
                session,
                loaded,
                clock=lambda: STATUS_UPDATED_AT,
            )
            immutable_hypothesis = hypotheses[0].model_dump(
                exclude={"status", "updated_at"}
            )
            reviewed = service.update_status(
                hypotheses[0].hypothesis_id,
                HypothesisStatus.UNDER_REVIEW,
                actor="integration-analyst",
            )
            assert reviewed.status is HypothesisStatus.UNDER_REVIEW
            assert reviewed.created_at == HYPOTHESIS_GENERATED_AT
            assert reviewed.updated_at == STATUS_UPDATED_AT
            assert reviewed.updated_at > reviewed.created_at
            assert reviewed.model_dump(exclude={"status", "updated_at"}) == immutable_hypothesis
            with pytest.raises(HypothesisTransitionError, match="confirmed"):
                service.update_status(
                    hypotheses[0].hypothesis_id,
                    HypothesisStatus.CONFIRMED,
                    actor="integration-analyst",
                )

        with database.session() as session:
            events = AuditLogRepository(session).list()
            actions = [event.action for event in events]
            assert actions.count("create") == 2
            assert actions.count("update_status") == 1
            status_event = next(item for item in events if item.action == "update_status")
            assert status_event.actor == "integration-analyst"
            assert status_event.details["status"] == "under_review"
    finally:
        database.dispose()
