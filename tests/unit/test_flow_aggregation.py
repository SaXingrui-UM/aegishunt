"""Canonical key, direction, timeout, segmentation, and flush tests."""

from __future__ import annotations

from uuid import UUID

from aegishunt.config import FlowSettings
from aegishunt.flows.aggregator import FlowAggregator
from aegishunt.flows.keys import canonical_flow_key
from aegishunt.flows.packets import PacketRecord
from aegishunt.flows.state import FlowEndReason
from aegishunt.schemas.enums import NetworkProtocol
from tests.fixtures.packets import at

SOURCE_ID = UUID("11111111-1111-1111-1111-111111111111")


def packet(
    seconds: float,
    *,
    source_ip: str = "192.0.2.1",
    destination_ip: str = "198.51.100.2",
    source_port: int | None = 40_000,
    destination_port: int | None = 443,
    protocol: NetworkProtocol = NetworkProtocol.TCP,
    protocol_number: int = 6,
    size: int = 60,
    flags: int = 0,
    icmp_type: int | None = None,
    icmp_identifier: int | None = None,
) -> PacketRecord:
    return PacketRecord(
        timestamp=at(seconds),
        ip_version=6 if ":" in source_ip else 4,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        protocol_number=protocol_number,
        network_bytes=size,
        tcp_flags=flags,
        icmp_type=icmp_type,
        icmp_code=0 if icmp_type is not None else None,
        icmp_identifier=icmp_identifier,
    )


def reverse(original: PacketRecord, seconds: float) -> PacketRecord:
    return packet(
        seconds,
        source_ip=original.destination_ip,
        destination_ip=original.source_ip,
        source_port=original.destination_port,
        destination_port=original.source_port,
        protocol=original.protocol,
        protocol_number=original.protocol_number,
        size=original.network_bytes,
        flags=original.tcp_flags,
        icmp_type=original.icmp_type,
        icmp_identifier=original.icmp_identifier,
    )


def settings(**overrides: float | int) -> FlowSettings:
    return FlowSettings.model_validate(
        {
            "idle_timeout_seconds": 10.0,
            "active_timeout_seconds": 100.0,
            "max_packets_per_flow": 100,
            "max_active_flows": 100,
            "max_packet_bytes": 2_048,
            **overrides,
        }
    )


def aggregator(flow_settings: FlowSettings | None = None) -> FlowAggregator:
    return FlowAggregator(
        flow_settings or settings(),
        source_id=SOURCE_ID,
        capture_session_id="capture-test",
    )


def test_canonical_key_merges_reverse_direction_and_separates_connections() -> None:
    first = packet(0)
    backward = reverse(first, 1)

    assert canonical_flow_key(first) == canonical_flow_key(backward)
    assert canonical_flow_key(first) != canonical_flow_key(
        packet(0, destination_port=80)
    )
    assert canonical_flow_key(first) != canonical_flow_key(
        packet(0, destination_ip="198.51.100.3")
    )
    assert canonical_flow_key(first) != canonical_flow_key(
        packet(
            0,
            protocol=NetworkProtocol.UDP,
            protocol_number=17,
        )
    )
    assert canonical_flow_key(first) != canonical_flow_key(
        packet(0, source_ip="2001:db8::1", destination_ip="2001:db8::2")
    )


def test_icmp_echo_key_pairs_request_and_reply_by_identifier() -> None:
    request = packet(
        0,
        source_port=None,
        destination_port=None,
        protocol=NetworkProtocol.ICMP,
        protocol_number=1,
        icmp_type=8,
        icmp_identifier=42,
    )
    reply = packet(
        1,
        source_ip=request.destination_ip,
        destination_ip=request.source_ip,
        source_port=None,
        destination_port=None,
        protocol=NetworkProtocol.ICMP,
        protocol_number=1,
        icmp_type=0,
        icmp_identifier=42,
    )
    other_identifier = packet(
        1,
        source_port=None,
        destination_port=None,
        protocol=NetworkProtocol.ICMP,
        protocol_number=1,
        icmp_type=8,
        icmp_identifier=43,
    )

    assert canonical_flow_key(request) == canonical_flow_key(reply)
    assert canonical_flow_key(request) != canonical_flow_key(other_identifier)


def test_first_packet_defines_forward_for_bidirectional_flow() -> None:
    first = packet(
        0,
        source_ip="198.51.100.2",
        destination_ip="192.0.2.1",
        source_port=443,
        destination_port=40_000,
    )
    second = reverse(first, 1)
    flow_aggregator = aggregator()

    assert flow_aggregator.process(first) == []
    assert flow_aggregator.process(second) == []
    finalized = flow_aggregator.flush_capture_end()

    assert len(finalized) == 1
    state = finalized[0].state
    assert state.forward_source.address == first.source_ip
    assert state.forward_packet_count == 1
    assert state.backward_packet_count == 1


def test_directional_tcp_flag_counts_track_forward_and_backward() -> None:
    first = packet(0, flags=0x02)
    flow_aggregator = aggregator()
    flow_aggregator.process(first)
    flow_aggregator.process(reverse(packet(0, flags=0x12), 1))
    state = flow_aggregator.flush_capture_end()[0].state

    assert state.tcp_flag_counts["syn"] == 2
    assert state.forward_tcp_flag_counts["syn"] == 1
    assert state.forward_tcp_flag_counts["ack"] == 0
    assert state.backward_tcp_flag_counts["syn"] == 1
    assert state.backward_tcp_flag_counts["ack"] == 1


def test_idle_timeout_boundary_starts_a_new_segment() -> None:
    flow_aggregator = aggregator(settings(idle_timeout_seconds=5.0))
    first = packet(0)

    flow_aggregator.process(first)
    finalized = flow_aggregator.process(reverse(first, 5.0))

    assert len(finalized) == 1
    assert finalized[0].reason is FlowEndReason.IDLE_TIMEOUT
    assert finalized[0].segment_index == 0
    remaining = flow_aggregator.flush_capture_end()
    assert len(remaining) == 1
    assert remaining[0].segment_index == 1


def test_active_timeout_has_priority_when_both_boundaries_match() -> None:
    flow_aggregator = aggregator(
        settings(idle_timeout_seconds=5.0, active_timeout_seconds=5.0)
    )
    first = packet(0)
    flow_aggregator.process(first)

    finalized = flow_aggregator.process(reverse(first, 5.0))

    assert finalized[0].reason is FlowEndReason.ACTIVE_TIMEOUT
    assert len(flow_aggregator.flush_capture_end()) == 1


def test_global_idle_expiry_and_capture_manual_flush_are_deterministic() -> None:
    first = packet(0)
    different = packet(10, destination_port=80)
    flow_aggregator = aggregator(settings(idle_timeout_seconds=5.0))
    flow_aggregator.process(first)

    expired = flow_aggregator.process(different)
    assert len(expired) == 1
    assert expired[0].reason is FlowEndReason.IDLE_TIMEOUT
    assert flow_aggregator.flush_manual()[0].reason is FlowEndReason.MANUAL
    assert flow_aggregator.flush_manual() == []
    assert flow_aggregator.flush_capture_end() == []


def test_capacity_and_out_of_order_timestamps_never_duplicate_or_go_negative() -> None:
    first = packet(10)
    flow_aggregator = aggregator(settings(max_packets_per_flow=1))
    flow_aggregator.process(first)

    capacity = flow_aggregator.process(reverse(first, 5))
    assert capacity[0].reason is FlowEndReason.CAPACITY
    remaining = flow_aggregator.flush_capture_end()
    assert len(remaining) == 1
    assert remaining[0].state.first_seen == at(5)
    assert remaining[0].state.last_seen == at(5)
