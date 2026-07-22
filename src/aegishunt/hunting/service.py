"""Transactional hypothesis generation and analyst-controlled lifecycle service."""

from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from aegishunt.correlation.config import LoadedCorrelationPolicy
from aegishunt.hunting.generator import generate_hypothesis, hypothesis_gate_failure
from aegishunt.schemas import ThreatHypothesis
from aegishunt.schemas.enums import HypothesisStatus
from aegishunt.storage.repositories import (
    AlertGroupRepository,
    AuditLogRepository,
    ThreatHypothesisRepository,
)


class ThreatHypothesisService:
    """Generate append-only hypotheses and audit explicit analyst transitions."""

    def __init__(self, session: Session, loaded_policy: LoadedCorrelationPolicy) -> None:
        audit = AuditLogRepository(session)
        self._groups = AlertGroupRepository(session, audit)
        self._hypotheses = ThreatHypothesisRepository(session, audit)
        self._policy = loaded_policy

    def generate(self, *, actor: str = "hypothesis-service") -> tuple[ThreatHypothesis, ...]:
        output: list[ThreatHypothesis] = []
        for group in self._groups.list_open():
            existing = self._hypotheses.get_by_group(group.group_id)
            if existing is not None:
                output.append(existing)
                continue
            if hypothesis_gate_failure(group, self._policy) is not None:
                continue
            hypothesis = generate_hypothesis(group, self._policy)
            output.append(self._hypotheses.add(hypothesis, actor=actor))
        return tuple(output)

    def update_status(
        self,
        hypothesis_id: UUID,
        status: HypothesisStatus,
        *,
        actor: str,
    ) -> ThreatHypothesis:
        return self._hypotheses.update_status(hypothesis_id, status, actor=actor)
