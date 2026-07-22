"""Phase 9 policy, entity-index, eligibility, and event-time tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from aegishunt.correlation.config import CorrelationPolicy, load_correlation_policy
from aegishunt.correlation.entities import canonical_entity, index_alert
from aegishunt.correlation.errors import CorrelationConfigError, CorrelationInputError
from aegishunt.correlation.index import EntityIndex
from aegishunt.schemas import SecurityAlert
from aegishunt.schemas.enums import AnalystVerdict, Severity

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 7, 22, 1, 0, tzinfo=UTC)


def policy() -> CorrelationPolicy:
    return load_correlation_policy(ROOT / "configs/correlation.yaml").policy


def alert(
    identifier: int,
    *,
    source: str = "192.0.2.10",
    destination: str = "198.51.100.20",
    start: datetime = NOW,
    verdict: AnalystVerdict | None = None,
) -> SecurityAlert:
    end = start + timedelta(seconds=1)
    facts = {
        "flow_id": str(UUID(int=identifier + 100)),
        "source_ip": source,
        "destination_ip": destination,
        "source_host": " Scanner.EXAMPLE ",
        "user": " Analyst ",
        "protocol": "TCP",
        "capture_session_id": "session-1",
        "first_seen": start.isoformat(),
        "last_seen": end.isoformat(),
    }
    return SecurityAlert(
        alert_id=UUID(int=identifier),
        detection_id=UUID(int=identifier + 10),
        alert_type="multi_engine_suspicion",
        severity=Severity.MEDIUM,
        risk_score=0.7,
        title="Evidence requires review",
        description="Possible activity; not a confirmed attack.",
        involved_entities=[
            f"source_ip:{source}",
            f"destination_ip:{destination}",
            f"flow_id:{UUID(int=identifier + 100)}",
            "service:HTTPS",
            "user:   ",
        ],
        evidence={
            "observed_facts": facts,
            "top_local_contributions": [{"feature_name": "syn_ratio", "value": 0.8}],
        },
        reason_codes=["HIGH_SYN_RATIO", "MULTI_ENGINE_SUPPORT"],
        explanation={"observed_facts": facts, "limitations": ["non-causal"]},
        model_versions={"supervised": "1.0.1", "anomaly": "1.1.0-candidate"},
        policy_versions={"fusion": "1.0.0", "risk": "1.0.0"},
        analyst_verdict=verdict,
        created_at=start,
        updated_at=start,
    )


def test_checked_policy_has_stable_identity_and_safe_semantics() -> None:
    loaded = load_correlation_policy(ROOT / "configs/correlation.yaml")

    assert loaded.policy.policy_id == "aegishunt-correlation-controlled"
    assert len(loaded.configuration_checksum) == 64
    assert sum(loaded.policy.score_weights.model_dump().values()) == 1.0
    assert "not attack probability" in loaded.policy.score_semantics


def test_policy_rejects_missing_rules_bad_weights_and_symlink(tmp_path: Path) -> None:
    payload = policy().model_dump(mode="python")
    payload["rule_versions"].pop("source_fan_out")
    with pytest.raises(ValidationError, match="every Phase 9 correlation rule"):
        CorrelationPolicy.model_validate(payload)

    payload = policy().model_dump(mode="python")
    payload["score_weights"]["risk"] = 0.5
    with pytest.raises(ValidationError, match="sum to 1.0"):
        CorrelationPolicy.model_validate(payload)

    link = tmp_path / "policy.yaml"
    link.symlink_to(ROOT / "configs/correlation.yaml")
    with pytest.raises(CorrelationConfigError, match="regular file"):
        load_correlation_policy(link)


def test_canonical_entities_are_typed_normalized_and_bounded() -> None:
    assert canonical_entity("source_ip", "2001:0DB8::1", maximum_length=255).serialized == (
        "source_ip:2001:db8::1"
    )
    assert canonical_entity("source_host", " Host.EXAMPLE ", maximum_length=255).serialized == (
        "source_host:host.example"
    )
    assert canonical_entity("user", " Alice ", maximum_length=255).serialized == "user:alice"
    assert canonical_entity("protocol", "TCP", maximum_length=255).serialized == "protocol:tcp"
    with pytest.raises(CorrelationInputError, match="valid IP"):
        canonical_entity("destination_ip", "not-an-ip", maximum_length=255)
    with pytest.raises(CorrelationInputError, match="configured limit"):
        canonical_entity("service", "x" * 5, maximum_length=4)


def test_index_alert_uses_observed_utc_time_and_never_created_at() -> None:
    indexed = index_alert(alert(1), policy())

    assert indexed.event_start == NOW
    assert indexed.event_end == NOW + timedelta(seconds=1)
    assert indexed.entity_keys == tuple(
        sorted(indexed.entity_keys, key=lambda item: item.serialized)
    )
    serialized = {item.serialized for item in indexed.entity_keys}
    assert "source_ip:192.0.2.10" in serialized
    assert "destination_ip:198.51.100.20" in serialized
    assert "source_destination_pair:192.0.2.10->198.51.100.20" in serialized
    assert "source_host:scanner.example" in serialized
    assert "user:analyst" in serialized
    assert "service:https" in serialized
    assert "user:" not in serialized

    missing = alert(2).model_copy(
        update={"evidence": {"observed_facts": {"source_ip": "192.0.2.10"}}}
    )
    with pytest.raises(CorrelationInputError, match="first_seen is missing"):
        index_alert(missing, policy())


def test_index_is_permutation_stable_inclusive_and_verdict_aware() -> None:
    exact = NOW + timedelta(seconds=policy().correlation_window_seconds - 1)
    rows = [
        alert(3, start=exact),
        alert(1),
        alert(4, start=exact + timedelta(microseconds=1)),
        alert(2, start=NOW + timedelta(seconds=1)),
        alert(5, verdict=AnalystVerdict.FALSE_POSITIVE),
    ]
    first = EntityIndex.build(rows, policy())
    second = EntityIndex.build(list(reversed(rows)), policy())

    assert first.alerts == second.alerts
    source_clusters = [
        item for item in first.candidate_clusters() if item.entity_key == "source_ip:192.0.2.10"
    ]
    assert tuple(item.alert_id for item in source_clusters[0].alerts) == (
        str(UUID(int=1)),
        str(UUID(int=2)),
        str(UUID(int=3)),
    )
    assert all(
        str(UUID(int=4)) not in {row.alert_id for row in item.alerts}
        for item in source_clusters
    )
    assert all(str(UUID(int=5)) != item.alert_id for item in first.alerts)


def test_duplicate_and_overflow_inputs_fail_closed() -> None:
    with pytest.raises(CorrelationInputError, match="duplicate alert"):
        EntityIndex.build([alert(1), alert(1)], policy())

    limited = policy().model_copy(update={"maximum_alerts_per_run": 2})
    with pytest.raises(CorrelationInputError, match="run exceeds"):
        EntityIndex.build([alert(1), alert(2), alert(3)], limited)
