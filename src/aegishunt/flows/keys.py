"""Canonical, comparable bidirectional flow keys."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from aegishunt.flows.packets import PacketRecord


@dataclass(frozen=True, order=True, slots=True)
class FlowEndpoint:
    """Comparable network endpoint using normalized address bytes and port."""

    version: int
    packed_address: bytes
    address: str
    port_sort: int

    @classmethod
    def create(cls, address: str, port: int | None) -> FlowEndpoint:
        parsed = ipaddress.ip_address(address)
        return cls(
            version=parsed.version,
            packed_address=parsed.packed,
            address=str(parsed),
            port_sort=-1 if port is None else port,
        )

    @property
    def port(self) -> int | None:
        return None if self.port_sort < 0 else self.port_sort

    def serialized(self) -> list[str | int | None]:
        return [self.version, self.address, self.port]


@dataclass(frozen=True, order=True, slots=True)
class CanonicalFlowKey:
    """Direction-independent transport conversation identity."""

    ip_version: int
    protocol_number: int
    left: FlowEndpoint
    right: FlowEndpoint
    discriminator: str

    def serialize(self) -> str:
        """Return a stable JSON representation for provenance and tests."""

        return json.dumps(
            [
                self.ip_version,
                self.protocol_number,
                self.left.serialized(),
                self.right.serialized(),
                self.discriminator,
            ],
            separators=(",", ":"),
        )


def packet_endpoints(packet: PacketRecord) -> tuple[FlowEndpoint, FlowEndpoint]:
    """Return the packet's source and destination endpoints."""

    return (
        FlowEndpoint.create(packet.source_ip, packet.source_port),
        FlowEndpoint.create(packet.destination_ip, packet.destination_port),
    )


def _icmp_discriminator(packet: PacketRecord) -> str:
    echo_types = {0, 8, 128, 129}
    if packet.icmp_type in echo_types:
        identifier = "none" if packet.icmp_identifier is None else str(packet.icmp_identifier)
        return f"echo:{identifier}"
    return f"type:{packet.icmp_type}:code:{packet.icmp_code}"


def canonical_flow_key(packet: PacketRecord) -> CanonicalFlowKey:
    """Map both directions of one supported conversation to the same key."""

    source, destination = packet_endpoints(packet)
    left, right = sorted((source, destination))
    discriminator = "ports" if packet.source_port is not None else _icmp_discriminator(packet)
    return CanonicalFlowKey(
        ip_version=packet.ip_version,
        protocol_number=packet.protocol_number,
        left=left,
        right=right,
        discriminator=discriminator,
    )
