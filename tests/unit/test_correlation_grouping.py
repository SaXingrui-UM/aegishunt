"""Phase 9 rule, window, score, and stable-group unit coverage."""

from __future__ import annotations

import math
from datetime import timedelta

import pytest

from aegishunt.correlation.config import LoadedCorrelationPolicy
from aegishunt.correlation.errors import CorrelationInputError
from aegishunt.correlation.grouping import correlate_alerts as correlate_with_time
from aegishunt.schemas import AlertGroup, SecurityAlert
from aegishunt.schemas.enums import AnalystVerdict
from tests.fixtures.hunting import GROUP_GENERATED_AT, alert, correlation_policy


def correlate_alerts(
    alerts: list[SecurityAlert],
    loaded: LoadedCorrelationPolicy,
) -> tuple[AlertGroup, ...]:
    return correlate_with_time(alerts, loaded, generated_at=GROUP_GENERATED_AT)


def test_source_fan_out_group_is_deterministic_and_evidence_backed() -> None:
    loaded = correlation_policy()
    alerts = [
        alert(1, destination_ip="198.51.100.10", seconds=0),
        alert(2, destination_ip="198.51.100.11", seconds=10),
        alert(3, destination_ip="198.51.100.12", seconds=20),
    ]
    snapshots = [item.model_dump() for item in alerts]
    first = correlate_alerts(alerts, loaded)
    second = correlate_alerts(list(reversed(alerts)), loaded)

    assert first == second
    assert len(first) == 1
    group = first[0]
    assert group.alert_ids == sorted(group.alert_ids)
    assert "source_centered_reconnaissance" in group.matched_rule_ids
    assert "source_fan_out" in group.matched_rule_ids
    assert "multi_engine_evidence" in group.matched_rule_ids
    assert 0.0 <= group.correlation_score <= 1.0
    assert group.evidence["score_semantics"] == (
        "correlation evidence strength for analyst triage; not attack probability"
    )
    assert "ground_truth" not in str(group.evidence)
    assert group.created_at == GROUP_GENERATED_AT
    assert group.created_at != group.last_seen
    assert group.evidence["generated_at"] == GROUP_GENERATED_AT.isoformat()
    assert [item.model_dump() for item in alerts] == snapshots

    exact = loaded.model_copy(
        update={
            "policy": loaded.policy.model_copy(
                update={"group_score_threshold": group.correlation_score}
            )
        }
    )
    above = exact.model_copy(
        update={
            "policy": exact.policy.model_copy(
                update={
                    "group_score_threshold": math.nextafter(
                        group.correlation_score,
                        1.0,
                    )
                }
            )
        }
    )
    assert correlate_alerts(alerts, exact)
    assert correlate_alerts(alerts, above) == ()


def test_window_boundary_is_inclusive_and_created_at_is_not_used() -> None:
    loaded = correlation_policy()
    inside = [alert(1, seconds=0), alert(2, seconds=299)]
    assert correlate_alerts(inside, loaded)

    outside = [alert(1, seconds=0), alert(2, seconds=299.000001)]
    assert correlate_alerts(outside, loaded) == ()
    changed_created_at = [
        item.model_copy(update={"created_at": item.created_at + timedelta(days=900)})
        for item in inside
    ]
    assert correlate_alerts(changed_created_at, loaded) == correlate_alerts(inside, loaded)


def test_protocol_only_relationship_does_not_merge_unrelated_alerts() -> None:
    loaded = correlation_policy()
    alerts = [
        alert(1, source_ip="192.0.2.1", destination_ip="198.51.100.1"),
        alert(2, source_ip="192.0.2.2", destination_ip="198.51.100.2"),
    ]
    assert correlate_alerts(alerts, loaded) == ()


def test_false_positive_is_excluded_and_duplicate_identity_fails_closed() -> None:
    loaded = correlation_policy()
    eligible = [alert(1, seconds=0), alert(2, seconds=10)]
    excluded = alert(3, seconds=20, verdict=AnalystVerdict.FALSE_POSITIVE)
    groups = correlate_alerts([*eligible, excluded], loaded)
    assert len(groups) == 1
    assert str(excluded.alert_id) not in groups[0].alert_ids

    with pytest.raises(CorrelationInputError, match="duplicate"):
        correlate_alerts([eligible[0], eligible[0]], loaded)


def test_repeated_failure_periodicity_and_destination_fan_in_rules() -> None:
    loaded = correlation_policy()
    failures = [
        alert(index, seconds=offset, reason_codes=("CONNECTION_FAILED",))
        for index, offset in enumerate((0, 10, 20), start=1)
    ]
    failure_group = correlate_alerts(failures, loaded)[0]
    assert "repeated_source_destination_failures" in failure_group.matched_rule_ids
    assert "periodic_beacon_like_activity" in failure_group.matched_rule_ids

    fan_in = [
        alert(10, source_ip="192.0.2.10", seconds=0),
        alert(11, source_ip="192.0.2.11", seconds=5),
    ]
    assert "destination_fan_in" in correlate_alerts(fan_in, loaded)[0].matched_rule_ids


def test_overlap_policy_allows_one_alert_in_distinct_relationship_groups() -> None:
    loaded = correlation_policy()
    shared = alert(1, source_ip="192.0.2.10", destination_ip="198.51.100.20")
    same_source = alert(2, source_ip="192.0.2.10", destination_ip="198.51.100.21")
    same_destination = alert(3, source_ip="192.0.2.11", destination_ip="198.51.100.20")
    groups = correlate_alerts([shared, same_source, same_destination], loaded)
    assert len(groups) == 2
    assert sum(str(shared.alert_id) in item.alert_ids for item in groups) == 2


@pytest.mark.parametrize(
    "verdict",
    [None, AnalystVerdict.TRUE_POSITIVE, AnalystVerdict.NEEDS_MORE_INFORMATION],
)
def test_included_verdicts_and_low_risk_accumulation(
    verdict: AnalystVerdict | None,
) -> None:
    alerts = [
        alert(
            20,
            risk_score=0.4,
            alert_type="behavioral_pattern",
            verdict=verdict,
        ),
        alert(
            21,
            seconds=1,
            risk_score=0.4,
            alert_type="behavioral_pattern",
            verdict=verdict,
        ),
    ]
    groups = correlate_alerts(alerts, correlation_policy())
    assert groups and "multi_alert_accumulation" in groups[0].matched_rule_ids


def test_configured_bounds_and_unknown_verdict_policy_fail_closed() -> None:
    loaded = correlation_policy()
    tiny = loaded.model_copy(
        update={
            "policy": loaded.policy.model_copy(update={"maximum_alerts_per_run": 2})
        }
    )
    with pytest.raises(CorrelationInputError, match="run exceeds"):
        correlate_alerts([alert(1), alert(2), alert(3)], tiny)

    unsupported = alert(4, verdict=AnalystVerdict.BENIGN_EXPECTED)
    policy = loaded.policy.model_copy(
        update={"excluded_verdicts": ("false_positive",)}
    )
    changed = loaded.model_copy(update={"policy": policy})
    with pytest.raises(CorrelationInputError, match="not covered"):
        correlate_alerts([unsupported], changed)
