"""Finite deterministic flow finalization and feature-registry tests."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegishunt.flows.errors import FeatureCalculationError
from aegishunt.flows.features import extract_features
from aegishunt.flows.finalizer import finalize_network_flow
from aegishunt.flows.packets import PacketRecord
from aegishunt.flows.registry import (
    FEATURE_DEFINITIONS,
    FEATURE_SCHEMA_VERSION,
    export_feature_schema,
    feature_names,
    feature_schema_json,
)
from aegishunt.flows.state import FlowState
from aegishunt.schemas.enums import NetworkProtocol
from aegishunt.schemas.telemetry import NetworkFlow
from tests.unit.test_flow_aggregation import SOURCE_ID, aggregator, packet, reverse


def finalized_flow(*packets: PacketRecord) -> NetworkFlow:
    flow_aggregator = aggregator()
    for item in packets:
        assert flow_aggregator.process(item) == []
    finalized = flow_aggregator.flush_capture_end()
    assert len(finalized) == 1
    return finalize_network_flow(finalized[0])


def test_single_packet_zero_duration_features_are_finite_and_ordered() -> None:
    flow = finalized_flow(packet(0, flags=0x02))

    assert flow.duration == 0.0
    assert flow.forward_packet_count == 1
    assert flow.backward_packet_count == 0
    assert tuple(flow.behavioral_features) == feature_names()
    assert flow.behavioral_features["packets_per_second"] == 0.0
    assert flow.behavioral_features["backward_mean_packet_size"] == 0.0
    assert flow.behavioral_features["mean_inter_arrival_time"] == 0.0
    assert flow.behavioral_features["failed_connection_indicator"] == 1
    assert all(
        isinstance(value, (int, float)) and math.isfinite(float(value))
        for value in flow.behavioral_features.values()
    )


def test_tcp_flags_handshake_ratios_and_directional_volume() -> None:
    syn = packet(0, size=60, flags=0x02)
    syn_ack = reverse(packet(0, size=70, flags=0x12), 0.1)
    ack = packet(0.2, size=52, flags=0x10)

    flow = finalized_flow(syn, syn_ack, ack)
    features = flow.behavioral_features

    assert (flow.forward_packet_count, flow.backward_packet_count) == (2, 1)
    assert (flow.forward_bytes, flow.backward_bytes) == (112, 70)
    assert features["syn_count"] == 2
    assert features["ack_count"] == 2
    assert features["completed_handshake_indicator"] == 1
    assert features["failed_connection_indicator"] == 0
    assert features["syn_ratio"] == pytest.approx(2 / 3)
    assert features["ack_ratio"] == pytest.approx(2 / 3)


def test_rst_non_tcp_and_out_of_order_time_semantics() -> None:
    rst_flow = finalized_flow(packet(2, flags=0x04), reverse(packet(2, flags=0x04), 1))
    assert rst_flow.first_seen < rst_flow.last_seen
    assert rst_flow.duration == 1.0
    assert rst_flow.behavioral_features["rst_count"] == 2
    assert rst_flow.behavioral_features["failed_connection_indicator"] == 1
    assert rst_flow.behavioral_features["min_inter_arrival_time"] >= 0.0

    udp = packet(
        0,
        protocol=NetworkProtocol.UDP,
        protocol_number=17,
        flags=0x3F,
    )
    udp_flow = finalized_flow(udp)
    assert udp_flow.behavioral_features["syn_count"] == 0
    assert udp_flow.behavioral_features["completed_handshake_indicator"] == 0
    assert udp_flow.behavioral_features["failed_connection_indicator"] == 0


def test_single_udp_icmp_and_ipv6_flows_finalize_with_finite_defaults() -> None:
    udp = finalized_flow(
        packet(0, protocol=NetworkProtocol.UDP, protocol_number=17, flags=0)
    )
    icmp = finalized_flow(
        packet(
            0,
            source_port=None,
            destination_port=None,
            protocol=NetworkProtocol.ICMP,
            protocol_number=1,
            icmp_type=8,
            icmp_identifier=7,
        )
    )
    ipv6 = finalized_flow(
        packet(
            0,
            source_ip="2001:db8::1",
            destination_ip="2001:db8::2",
            protocol=NetworkProtocol.UDP,
            protocol_number=17,
            flags=0,
        )
    )

    assert udp.protocol is NetworkProtocol.UDP
    assert icmp.protocol is NetworkProtocol.ICMP
    assert icmp.source_port is None and icmp.destination_port is None
    assert ipv6.source_ip == "2001:db8::1"
    for flow in (udp, icmp, ipv6):
        assert all(math.isfinite(float(value)) for value in flow.behavioral_features.values())


def test_packet_size_quantiles_and_identical_timestamps_are_stable() -> None:
    first = packet(0, size=40)
    flow = finalized_flow(first, reverse(first, 0), packet(0, size=80))
    features = flow.behavioral_features

    assert flow.duration == 0.0
    assert features["min_packet_size"] == 40.0
    assert features["max_packet_size"] == 80.0
    assert features["median_packet_size"] == 40.0
    assert features["packet_size_q25"] == 40.0
    assert features["packet_size_q75"] == 60.0
    assert features["max_inter_arrival_time"] == 0.0
    assert features["bytes_per_second"] == 0.0


def test_repeated_finalization_is_deterministic() -> None:
    packets = (packet(0), reverse(packet(0), 0.5))

    first = finalized_flow(*packets)
    second = finalized_flow(*packets)

    assert first == second
    assert json.dumps(first.behavioral_features) == json.dumps(second.behavioral_features)


def test_feature_schema_export_has_fixed_version_order_and_bytes(tmp_path: Path) -> None:
    first = export_feature_schema(tmp_path / "one" / "feature_schema.json")
    second = export_feature_schema(tmp_path / "two" / "feature_schema.json")

    assert first.read_bytes() == second.read_bytes()
    assert first.read_text(encoding="utf-8") == feature_schema_json()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["schema_version"] == FEATURE_SCHEMA_VERSION
    assert payload["feature_count"] == len(FEATURE_DEFINITIONS) == len(feature_names())
    assert tuple(item["name"] for item in payload["features"]) == feature_names()

    committed = Path(__file__).parents[2] / "artifacts" / "feature_schema.json"
    assert committed.read_text(encoding="utf-8") == feature_schema_json()


def test_network_flow_rejects_non_finite_or_non_numeric_features() -> None:
    flow = finalized_flow(packet(0))
    payload = flow.model_dump(mode="python")
    non_finite = dict(flow.behavioral_features)
    non_finite["flow_duration"] = float("nan")
    payload["behavioral_features"] = non_finite
    with pytest.raises(ValidationError, match="finite"):
        NetworkFlow.model_validate(payload)
    non_numeric = dict(flow.behavioral_features)
    non_numeric["flow_duration"] = "not-numeric"
    payload["behavioral_features"] = non_numeric
    with pytest.raises(ValidationError, match="numeric"):
        NetworkFlow.model_validate(payload)
    payload["behavioral_features"] = {"total_packets": 1}
    with pytest.raises(ValidationError, match="order"):
        NetworkFlow.model_validate(payload)


def test_extract_features_requires_finalized_state() -> None:
    active_state = FlowState.from_first_packet(
        packet(0),
        source_id=SOURCE_ID,
        capture_session_id="test",
        max_packets=10,
    )
    with pytest.raises(FeatureCalculationError, match="finalized"):
        extract_features(active_state)
