"""Bounded, typed state for one bidirectional flow segment."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from aegishunt.flows.errors import FlowLimitError, FlowStateError
from aegishunt.flows.keys import (
    CanonicalFlowKey,
    FlowEndpoint,
    canonical_flow_key,
    packet_endpoints,
)
from aegishunt.flows.packets import PacketRecord
from aegishunt.schemas.enums import NetworkProtocol

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20
TCP_FLAGS = {
    "fin": TCP_FIN,
    "syn": TCP_SYN,
    "rst": TCP_RST,
    "psh": TCP_PSH,
    "ack": TCP_ACK,
    "urg": TCP_URG,
}


class FlowDirection(StrEnum):
    FORWARD = "forward"
    BACKWARD = "backward"


class FlowEndReason(StrEnum):
    IDLE_TIMEOUT = "idle_timeout"
    ACTIVE_TIMEOUT = "active_timeout"
    CAPACITY = "capacity"
    CAPTURE_END = "capture_end"
    MANUAL = "manual"


@dataclass(frozen=True, slots=True)
class TcpObservation:
    direction: FlowDirection
    flags: int
    timestamp: datetime


@dataclass(slots=True)
class FlowState:
    """Accumulate bounded packet evidence while preserving first-packet direction."""

    key: CanonicalFlowKey
    source_id: UUID
    capture_session_id: str
    protocol: NetworkProtocol
    forward_source: FlowEndpoint
    forward_destination: FlowEndpoint
    max_packets: int
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    forward_packet_count: int = 0
    backward_packet_count: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    packet_sizes: list[int] = field(default_factory=list)
    forward_packet_sizes: list[int] = field(default_factory=list)
    backward_packet_sizes: list[int] = field(default_factory=list)
    packet_timestamps: list[datetime] = field(default_factory=list)
    forward_timestamps: list[datetime] = field(default_factory=list)
    backward_timestamps: list[datetime] = field(default_factory=list)
    tcp_flag_counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in TCP_FLAGS}
    )
    forward_tcp_flag_counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in TCP_FLAGS}
    )
    backward_tcp_flag_counts: dict[str, int] = field(
        default_factory=lambda: {name: 0 for name in TCP_FLAGS}
    )
    tcp_observations: list[TcpObservation] = field(default_factory=list)
    finalized: bool = False

    @classmethod
    def from_first_packet(
        cls,
        packet: PacketRecord,
        *,
        source_id: UUID,
        capture_session_id: str,
        max_packets: int,
    ) -> FlowState:
        source, destination = packet_endpoints(packet)
        state = cls(
            key=canonical_flow_key(packet),
            source_id=source_id,
            capture_session_id=capture_session_id,
            protocol=packet.protocol,
            forward_source=source,
            forward_destination=destination,
            max_packets=max_packets,
        )
        state.add(packet)
        return state

    @property
    def packet_count(self) -> int:
        return self.forward_packet_count + self.backward_packet_count

    def direction_for(self, packet: PacketRecord) -> FlowDirection:
        source, destination = packet_endpoints(packet)
        if source == self.forward_source and destination == self.forward_destination:
            return FlowDirection.FORWARD
        if source == self.forward_destination and destination == self.forward_source:
            return FlowDirection.BACKWARD
        raise FlowStateError("packet endpoints do not match the active flow direction")

    def add(self, packet: PacketRecord) -> FlowDirection:
        """Add one packet without exceeding the configured observation bound."""

        if self.finalized:
            raise FlowStateError("cannot add a packet to a finalized flow")
        if canonical_flow_key(packet) != self.key:
            raise FlowStateError("packet canonical key does not match the active flow")
        if self.packet_count >= self.max_packets:
            raise FlowLimitError("flow reached the configured packet observation limit")

        direction = self.direction_for(packet)
        self.first_seen = (
            packet.timestamp if self.first_seen is None else min(self.first_seen, packet.timestamp)
        )
        self.last_seen = (
            packet.timestamp if self.last_seen is None else max(self.last_seen, packet.timestamp)
        )
        self.packet_sizes.append(packet.network_bytes)
        self.packet_timestamps.append(packet.timestamp)

        if direction is FlowDirection.FORWARD:
            self.forward_packet_count += 1
            self.forward_bytes += packet.network_bytes
            self.forward_packet_sizes.append(packet.network_bytes)
            self.forward_timestamps.append(packet.timestamp)
            directional_flags = self.forward_tcp_flag_counts
        else:
            self.backward_packet_count += 1
            self.backward_bytes += packet.network_bytes
            self.backward_packet_sizes.append(packet.network_bytes)
            self.backward_timestamps.append(packet.timestamp)
            directional_flags = self.backward_tcp_flag_counts

        if packet.protocol is NetworkProtocol.TCP:
            for name, mask in TCP_FLAGS.items():
                if packet.tcp_flags & mask:
                    self.tcp_flag_counts[name] += 1
                    directional_flags[name] += 1
            self.tcp_observations.append(
                TcpObservation(
                    direction=direction,
                    flags=packet.tcp_flags,
                    timestamp=packet.timestamp,
                )
            )
        return direction

    def mark_finalized(self) -> None:
        if self.finalized:
            raise FlowStateError("flow was already finalized")
        if self.packet_count == 0 or self.first_seen is None or self.last_seen is None:
            raise FlowStateError("an empty flow cannot be finalized")
        self.finalized = True
