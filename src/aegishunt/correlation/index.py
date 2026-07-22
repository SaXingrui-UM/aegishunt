"""Bounded canonical entity index and deterministic event-time windows."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from aegishunt.correlation.config import CorrelationPolicy
from aegishunt.correlation.contracts import IndexedAlert
from aegishunt.correlation.entities import index_alert
from aegishunt.correlation.errors import CorrelationInputError
from aegishunt.schemas import SecurityAlert

_CANDIDATE_TYPES = {
    "source_ip",
    "destination_ip",
    "source_host",
    "destination_host",
    "user",
    "source_destination_pair",
}


@dataclass(frozen=True, slots=True)
class CandidateCluster:
    """One earliest-event anchored candidate sharing an entity key."""

    entity_key: str
    alerts: tuple[IndexedAlert, ...]


class EntityIndex:
    """Bounded entity-to-alert index with stable ordering."""

    def __init__(self, alerts: tuple[IndexedAlert, ...], policy: CorrelationPolicy) -> None:
        self.alerts = alerts
        self.policy = policy
        mutable: dict[str, list[IndexedAlert]] = defaultdict(list)
        for alert in alerts:
            for key in alert.entity_keys:
                mutable[key.serialized].append(alert)
        self.by_entity = {
            key: tuple(sorted(rows, key=lambda item: (item.event_start, item.alert_id)))
            for key, rows in sorted(mutable.items())
        }

    @classmethod
    def build(
        cls,
        alerts: list[SecurityAlert] | tuple[SecurityAlert, ...],
        policy: CorrelationPolicy,
    ) -> EntityIndex:
        if len(alerts) > policy.maximum_alerts_per_run:
            raise CorrelationInputError("correlation run exceeds the configured alert limit")
        seen: set[str] = set()
        indexed: list[IndexedAlert] = []
        for alert in alerts:
            identifier = str(alert.alert_id)
            if identifier in seen:
                raise CorrelationInputError("duplicate alert identity in correlation input")
            seen.add(identifier)
            verdict = "unreviewed" if alert.analyst_verdict is None else alert.analyst_verdict.value
            if verdict in policy.excluded_verdicts:
                continue
            if verdict not in policy.included_verdicts:
                raise CorrelationInputError(
                    "alert verdict is not covered by the eligibility policy"
                )
            item = index_alert(alert, policy)
            if (
                item.event_end - item.event_start
            ).total_seconds() > policy.correlation_window_seconds:
                raise CorrelationInputError(
                    "alert observed span exceeds the configured correlation window"
                )
            indexed.append(item)
        ordered = tuple(sorted(indexed, key=lambda item: (item.event_start, item.alert_id)))
        return cls(ordered, policy)

    def candidate_clusters(self) -> tuple[CandidateCluster, ...]:
        """Return deterministic non-overlapping anchored windows per relationship key."""

        output: list[CandidateCluster] = []
        window = timedelta(seconds=self.policy.correlation_window_seconds)
        for entity_key, rows in self.by_entity.items():
            if entity_key.split(":", maxsplit=1)[0] not in _CANDIDATE_TYPES:
                continue
            start = 0
            while start < len(rows):
                boundary = rows[start].event_start + window
                end = start
                while end < len(rows) and rows[end].event_end <= boundary:
                    end += 1
                cluster = rows[start:end]
                if len(cluster) > self.policy.maximum_alerts_per_group:
                    raise CorrelationInputError(
                        "candidate group exceeds the configured alert limit"
                    )
                if len(cluster) >= self.policy.minimum_alerts:
                    output.append(CandidateCluster(entity_key=entity_key, alerts=cluster))
                start = end
        return tuple(output)
