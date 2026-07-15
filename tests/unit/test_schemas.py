"""Validation tests for Phase 1 core Pydantic schemas."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from aegishunt.schemas import DetectionResult, NetworkFlow, TelemetrySource, ThreatHypothesis
from aegishunt.schemas.enums import (
    HypothesisStatus,
    IngestionMode,
    LifecycleStatus,
    NetworkProtocol,
    Severity,
    SourceType,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_telemetry_source_accepts_metadata_alias_and_normalizes_checksum() -> None:
    source = TelemetrySource.model_validate(
        {
            "source_type": SourceType.PCAP,
            "filename_or_interface": "reviewed-sample.pcap",
            "ingestion_mode": IngestionMode.IMPORT,
            "status": LifecycleStatus.PENDING,
            "checksum": "A" * 64,
            "metadata": {"purpose": "schema-test"},
        }
    )

    assert source.checksum == "a" * 64
    assert source.source_metadata == {"purpose": "schema-test"}
    assert source.model_dump(by_alias=True)["metadata"] == {"purpose": "schema-test"}


def test_network_flow_rejects_invalid_ip_and_time_order() -> None:
    values = {
        "source_id": uuid4(),
        "capture_session_id": "session-1",
        "first_seen": NOW,
        "last_seen": NOW,
        "duration": 0.0,
        "source_ip": "not-an-ip",
        "destination_ip": "192.0.2.2",
        "protocol": NetworkProtocol.TCP,
        "forward_packet_count": 1,
        "backward_packet_count": 0,
        "forward_bytes": 60,
        "backward_bytes": 0,
    }

    with pytest.raises(ValidationError, match="invalid IP address"):
        NetworkFlow.model_validate(values)


def test_scores_must_stay_in_declared_range() -> None:
    with pytest.raises(ValidationError):
        DetectionResult(
            flow_id=uuid4(),
            combined_risk_score=1.1,
            severity=Severity.HIGH,
        )


def test_hypothesis_is_never_confirmed_by_default() -> None:
    hypothesis = ThreatHypothesis(
        title="Possible structured activity",
        description="Evidence requires analyst validation.",
        confidence=0.5,
        severity=Severity.MEDIUM,
        first_seen=NOW,
        last_seen=NOW,
    )

    assert hypothesis.status is HypothesisStatus.PROPOSED


def test_naive_timestamp_is_rejected() -> None:
    with pytest.raises(ValidationError, match="timezone"):
        ThreatHypothesis(
            title="Possible structured activity",
            description="Evidence requires analyst validation.",
            confidence=0.5,
            severity=Severity.MEDIUM,
            first_seen=datetime(2026, 1, 1),
            last_seen=NOW,
        )
