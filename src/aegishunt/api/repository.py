"""Bounded read repository for Phase 12 API projections and aggregations."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from aegishunt.api.contracts import FlowSummary
from aegishunt.schemas import (
    AlertGroup,
    DetectionResult,
    InvestigationCase,
    NetworkFlow,
    SecurityAlert,
    ThreatHypothesis,
)
from aegishunt.schemas.enums import (
    AlertStatus,
    AnalystVerdict,
    HypothesisStatus,
    NetworkProtocol,
    Severity,
)
from aegishunt.storage.models import (
    AlertGroupRecord,
    DetectionResultRecord,
    InvestigationCaseRecord,
    NetworkFlowRecord,
    SecurityAlertRecord,
    ThreatHypothesisRecord,
)


class ApiReadRepository:
    """Own SQL used by web adapters so routers never compose database queries."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def list_flows(
        self,
        *,
        limit: int,
        offset: int,
        source_id: UUID | None = None,
        capture_session_id: str | None = None,
        protocol: NetworkProtocol | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        time_from: datetime | None = None,
        time_to: datetime | None = None,
        supervised_label: str | None = None,
        alert_present: bool | None = None,
        minimum_risk: float | None = None,
        minimum_anomaly_score: float | None = None,
    ) -> tuple[list[NetworkFlow], int]:
        """Return a stable filtered page without exposing evaluation-only ground truth."""

        query = select(NetworkFlowRecord)
        count_query = select(func.count(NetworkFlowRecord.flow_id))
        joined_detection = any(
            value is not None
            for value in (
                supervised_label,
                alert_present,
                minimum_risk,
                minimum_anomaly_score,
            )
        )
        if joined_detection:
            query = query.join(
                DetectionResultRecord,
                DetectionResultRecord.flow_id == NetworkFlowRecord.flow_id,
            )
            count_query = count_query.join(
                DetectionResultRecord,
                DetectionResultRecord.flow_id == NetworkFlowRecord.flow_id,
            )
        if alert_present is not None:
            query = query.outerjoin(
                SecurityAlertRecord,
                SecurityAlertRecord.detection_id == DetectionResultRecord.detection_id,
            )
            count_query = count_query.outerjoin(
                SecurityAlertRecord,
                SecurityAlertRecord.detection_id == DetectionResultRecord.detection_id,
            )
        conditions: list[ColumnElement[bool]] = []
        optional_pairs = (
            (source_id, NetworkFlowRecord.source_id),
            (capture_session_id, NetworkFlowRecord.capture_session_id),
            (protocol, NetworkFlowRecord.protocol),
            (source_ip, NetworkFlowRecord.source_ip),
            (destination_ip, NetworkFlowRecord.destination_ip),
            (supervised_label, DetectionResultRecord.supervised_label),
        )
        conditions.extend(column == value for value, column in optional_pairs if value is not None)
        if time_from is not None:
            conditions.append(NetworkFlowRecord.first_seen >= time_from)
        if time_to is not None:
            conditions.append(NetworkFlowRecord.last_seen <= time_to)
        if minimum_risk is not None:
            conditions.append(DetectionResultRecord.risk_score >= minimum_risk)
        if minimum_anomaly_score is not None:
            conditions.append(
                DetectionResultRecord.normalized_anomaly_score >= minimum_anomaly_score
            )
        if alert_present is True:
            conditions.append(SecurityAlertRecord.alert_id.is_not(None))
        elif alert_present is False:
            conditions.append(SecurityAlertRecord.alert_id.is_(None))
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(NetworkFlowRecord.first_seen, NetworkFlowRecord.flow_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [NetworkFlow.model_validate(row) for row in rows], total

    def flow_summary(self, *, source_id: UUID | None = None) -> FlowSummary:
        """Aggregate bounded summary fields in SQL instead of the frontend."""

        condition = (
            () if source_id is None else (NetworkFlowRecord.source_id == source_id,)
        )
        total, packets, byte_count, first_seen, last_seen = self._session.execute(
            select(
                func.count(NetworkFlowRecord.flow_id),
                func.coalesce(
                    func.sum(
                        NetworkFlowRecord.forward_packet_count
                        + NetworkFlowRecord.backward_packet_count
                    ),
                    0,
                ),
                func.coalesce(
                    func.sum(
                        NetworkFlowRecord.forward_bytes + NetworkFlowRecord.backward_bytes
                    ),
                    0,
                ),
                func.min(NetworkFlowRecord.first_seen),
                func.max(NetworkFlowRecord.last_seen),
            ).where(*condition)
        ).one()
        protocols = {
            str(protocol.value): int(count)
            for protocol, count in self._session.execute(
                select(NetworkFlowRecord.protocol, func.count(NetworkFlowRecord.flow_id))
                .where(*condition)
                .group_by(NetworkFlowRecord.protocol)
                .order_by(NetworkFlowRecord.protocol)
            ).all()
        }
        pairs = [
            {"source_ip": source, "destination_ip": destination, "count": int(count)}
            for source, destination, count in self._session.execute(
                select(
                    NetworkFlowRecord.source_ip,
                    NetworkFlowRecord.destination_ip,
                    func.count(NetworkFlowRecord.flow_id).label("flow_count"),
                )
                .where(*condition)
                .group_by(
                    NetworkFlowRecord.source_ip,
                    NetworkFlowRecord.destination_ip,
                )
                .order_by(
                    func.count(NetworkFlowRecord.flow_id).desc(),
                    NetworkFlowRecord.source_ip,
                    NetworkFlowRecord.destination_ip,
                )
                .limit(20)
            ).all()
        ]
        return FlowSummary(
            total=int(total),
            protocol_distribution=protocols,
            total_packets=int(packets),
            total_bytes=int(byte_count),
            first_seen=first_seen,
            last_seen=last_seen,
            top_source_destination_pairs=pairs,
        )

    def list_alerts(
        self,
        *,
        limit: int,
        offset: int,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        analyst_verdict: AnalystVerdict | None = None,
        minimum_risk: float | None = None,
    ) -> tuple[list[SecurityAlert], int]:
        query = select(SecurityAlertRecord)
        count_query = select(func.count(SecurityAlertRecord.alert_id))
        conditions: list[ColumnElement[bool]] = []
        for value, column in (
            (severity, SecurityAlertRecord.severity),
            (status, SecurityAlertRecord.status),
            (analyst_verdict, SecurityAlertRecord.analyst_verdict),
        ):
            if value is not None:
                conditions.append(column == value)
        if minimum_risk is not None:
            conditions.append(SecurityAlertRecord.risk_score >= minimum_risk)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(SecurityAlertRecord.created_at.desc(), SecurityAlertRecord.alert_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [SecurityAlert.model_validate(row) for row in rows], total

    def list_detections(
        self,
        *,
        limit: int,
        offset: int,
        flow_id: UUID | None = None,
        supervised_label: str | None = None,
        minimum_risk: float | None = None,
        minimum_anomaly_score: float | None = None,
    ) -> tuple[list[DetectionResult], int]:
        """Return immutable detection evidence with bounded deterministic ordering."""

        query = select(DetectionResultRecord)
        count_query = select(func.count(DetectionResultRecord.detection_id))
        conditions: list[ColumnElement[bool]] = []
        if flow_id is not None:
            conditions.append(DetectionResultRecord.flow_id == flow_id)
        if supervised_label is not None:
            conditions.append(DetectionResultRecord.supervised_label == supervised_label)
        if minimum_risk is not None:
            conditions.append(DetectionResultRecord.risk_score >= minimum_risk)
        if minimum_anomaly_score is not None:
            conditions.append(
                DetectionResultRecord.normalized_anomaly_score >= minimum_anomaly_score
            )
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(
                DetectionResultRecord.detected_at.desc(),
                DetectionResultRecord.detection_id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [DetectionResult.model_validate(row) for row in rows], total

    def alert_relations(self, alert_id: UUID) -> tuple[list[UUID], list[UUID]]:
        """Resolve bounded group and hypothesis relations from stored identities."""

        identifier = str(alert_id)
        groups = self._session.scalars(
            select(AlertGroupRecord).order_by(AlertGroupRecord.group_id).limit(1_000)
        ).all()
        group_ids = [row.group_id for row in groups if identifier in row.alert_ids]
        hypotheses = (
            self._session.scalars(
                select(ThreatHypothesisRecord)
                .where(ThreatHypothesisRecord.group_id.in_(group_ids))
                .order_by(ThreatHypothesisRecord.hypothesis_id)
                .limit(1_000)
            ).all()
            if group_ids
            else []
        )
        return group_ids, [row.hypothesis_id for row in hypotheses]

    def list_groups(
        self,
        *,
        limit: int,
        offset: int,
        severity: Severity | None = None,
        status: str | None = None,
    ) -> tuple[list[AlertGroup], int]:
        query = select(AlertGroupRecord)
        count_query = select(func.count(AlertGroupRecord.group_id))
        conditions: list[ColumnElement[bool]] = []
        if severity is not None:
            conditions.append(AlertGroupRecord.severity == severity)
        if status is not None:
            conditions.append(AlertGroupRecord.status == status)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(AlertGroupRecord.first_seen.desc(), AlertGroupRecord.group_id)
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [AlertGroup.model_validate(row) for row in rows], total

    def list_hypotheses(
        self,
        *,
        limit: int,
        offset: int,
        status: HypothesisStatus | None = None,
        severity: Severity | None = None,
    ) -> tuple[list[ThreatHypothesis], int]:
        query = select(ThreatHypothesisRecord)
        count_query = select(func.count(ThreatHypothesisRecord.hypothesis_id))
        conditions: list[ColumnElement[bool]] = []
        if status is not None:
            conditions.append(ThreatHypothesisRecord.status == status)
        if severity is not None:
            conditions.append(ThreatHypothesisRecord.severity == severity)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(
                ThreatHypothesisRecord.created_at.desc(),
                ThreatHypothesisRecord.hypothesis_id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [ThreatHypothesis.model_validate(row) for row in rows], total

    def hypothesis_case_id(self, hypothesis_id: UUID) -> UUID | None:
        return self._session.scalar(
            select(InvestigationCaseRecord.case_id).where(
                InvestigationCaseRecord.hypothesis_id == hypothesis_id
            )
        )

    def list_cases(
        self,
        *,
        limit: int,
        offset: int,
        status: object | None,
        priority: object | None,
        assigned_to: str | None,
    ) -> tuple[list[InvestigationCase], int]:
        query = select(InvestigationCaseRecord)
        count_query = select(func.count(InvestigationCaseRecord.case_id))
        conditions: list[ColumnElement[bool]] = []
        if status is not None:
            conditions.append(InvestigationCaseRecord.status == status)
        if priority is not None:
            conditions.append(InvestigationCaseRecord.priority == priority)
        if assigned_to is not None:
            conditions.append(InvestigationCaseRecord.assigned_to == assigned_to)
        if conditions:
            query = query.where(*conditions)
            count_query = count_query.where(*conditions)
        rows = self._session.scalars(
            query.order_by(
                InvestigationCaseRecord.updated_at.desc(),
                InvestigationCaseRecord.case_id,
            )
            .limit(limit)
            .offset(offset)
        ).all()
        total = self._session.scalar(count_query) or 0
        return [InvestigationCase.model_validate(row) for row in rows], total
