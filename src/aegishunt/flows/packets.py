"""Payload-independent IP packet decoding for offline captures."""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from aegishunt.flows.errors import PacketParseError
from aegishunt.schemas.enums import NetworkProtocol

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_VLAN_ETHERTYPES = {0x8100, 0x88A8}
_IP_PROTOCOL_TCP = 6
_IP_PROTOCOL_UDP = 17
_IP_PROTOCOL_ICMP = 1
_IP_PROTOCOL_ICMPV6 = 58
_IPV6_OPTION_HEADERS = {0, 43, 60}


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """Minimal packet evidence required by deterministic flow aggregation."""

    timestamp: datetime
    ip_version: Literal[4, 6]
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: NetworkProtocol
    protocol_number: int
    network_bytes: int
    tcp_flags: int = 0
    icmp_type: int | None = None
    icmp_code: int | None = None
    icmp_identifier: int | None = None


def _require_length(payload: bytes, required: int, context: str) -> None:
    if len(payload) < required:
        raise PacketParseError(f"truncated packet while reading {context}")


def _parse_transport(
    payload: bytes,
    *,
    timestamp: datetime,
    ip_version: Literal[4, 6],
    source_ip: str,
    destination_ip: str,
    protocol_number: int,
    network_bytes: int,
) -> PacketRecord | None:
    if protocol_number == _IP_PROTOCOL_TCP:
        _require_length(payload, 20, "TCP header")
        source_port, destination_port = struct.unpack("!HH", payload[:4])
        header_length = (payload[12] >> 4) * 4
        if header_length < 20 or header_length > len(payload):
            raise PacketParseError("invalid TCP header length")
        return PacketRecord(
            timestamp=timestamp,
            ip_version=ip_version,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=NetworkProtocol.TCP,
            protocol_number=protocol_number,
            network_bytes=network_bytes,
            tcp_flags=payload[13],
        )

    if protocol_number == _IP_PROTOCOL_UDP:
        _require_length(payload, 8, "UDP header")
        source_port, destination_port, udp_length = struct.unpack("!HHH", payload[:6])
        if udp_length < 8 or udp_length > len(payload):
            raise PacketParseError("invalid UDP datagram length")
        return PacketRecord(
            timestamp=timestamp,
            ip_version=ip_version,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=NetworkProtocol.UDP,
            protocol_number=protocol_number,
            network_bytes=network_bytes,
        )

    if protocol_number in {_IP_PROTOCOL_ICMP, _IP_PROTOCOL_ICMPV6}:
        _require_length(payload, 4, "ICMP header")
        icmp_type = payload[0]
        icmp_code = payload[1]
        echo_types = {0, 8} if protocol_number == _IP_PROTOCOL_ICMP else {128, 129}
        identifier = None
        if icmp_type in echo_types:
            _require_length(payload, 8, "ICMP echo header")
            identifier = struct.unpack("!H", payload[4:6])[0]
        return PacketRecord(
            timestamp=timestamp,
            ip_version=ip_version,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=None,
            destination_port=None,
            protocol=NetworkProtocol.ICMP,
            protocol_number=protocol_number,
            network_bytes=network_bytes,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_identifier=identifier,
        )

    return None


def _parse_ipv4(payload: bytes, timestamp: datetime) -> PacketRecord | None:
    _require_length(payload, 20, "IPv4 header")
    if payload[0] >> 4 != 4:
        raise PacketParseError("invalid IPv4 version")
    header_length = (payload[0] & 0x0F) * 4
    if header_length < 20:
        raise PacketParseError("invalid IPv4 header length")
    _require_length(payload, header_length, "IPv4 options")
    total_length = struct.unpack("!H", payload[2:4])[0]
    if total_length < header_length or total_length > len(payload):
        raise PacketParseError("invalid or truncated IPv4 total length")
    fragment_field = struct.unpack("!H", payload[6:8])[0]
    if fragment_field & 0x3FFF:
        return None
    protocol_number = payload[9]
    source_ip = str(ipaddress.IPv4Address(payload[12:16]))
    destination_ip = str(ipaddress.IPv4Address(payload[16:20]))
    return _parse_transport(
        payload[header_length:total_length],
        timestamp=timestamp,
        ip_version=4,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol_number=protocol_number,
        network_bytes=total_length,
    )


def _ipv6_transport_offset(payload: bytes, next_header: int) -> tuple[int, int] | None:
    offset = 40
    while next_header in _IPV6_OPTION_HEADERS or next_header in {44, 51}:
        if next_header == 44:
            _require_length(payload[offset:], 8, "IPv6 fragment header")
            following = payload[offset]
            fragment_field = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
            if fragment_field & 0xFFF9:
                return None
            next_header = following
            offset += 8
            continue
        _require_length(payload[offset:], 2, "IPv6 extension header")
        following = payload[offset]
        if next_header == 51:
            extension_length = (payload[offset + 1] + 2) * 4
        else:
            extension_length = (payload[offset + 1] + 1) * 8
        if extension_length < 8:
            raise PacketParseError("invalid IPv6 extension header length")
        _require_length(payload[offset:], extension_length, "IPv6 extension header")
        next_header = following
        offset += extension_length
    return offset, next_header


def _parse_ipv6(payload: bytes, timestamp: datetime) -> PacketRecord | None:
    _require_length(payload, 40, "IPv6 header")
    if payload[0] >> 4 != 6:
        raise PacketParseError("invalid IPv6 version")
    payload_length = struct.unpack("!H", payload[4:6])[0]
    total_length = 40 + payload_length
    if payload_length == 0:
        raise PacketParseError("IPv6 jumbo payloads are not supported")
    if total_length > len(payload):
        raise PacketParseError("truncated IPv6 payload")
    bounded = payload[:total_length]
    transport = _ipv6_transport_offset(bounded, payload[6])
    if transport is None:
        return None
    offset, protocol_number = transport
    if offset > total_length:
        raise PacketParseError("IPv6 extension headers exceed payload length")
    source_ip = str(ipaddress.IPv6Address(payload[8:24]))
    destination_ip = str(ipaddress.IPv6Address(payload[24:40]))
    return _parse_transport(
        bounded[offset:],
        timestamp=timestamp,
        ip_version=6,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol_number=protocol_number,
        network_bytes=total_length,
    )


def parse_packet(
    frame: bytes,
    *,
    timestamp: datetime,
    link_type: int,
) -> PacketRecord | None:
    """Decode one supported IP packet or return ``None`` for declared skips.

    Non-IP frames, fragmented packets, unsupported transports, and unsupported
    link layers are skipped. Structurally malformed supported packets raise a
    typed error so the caller can fail the capture without partial persistence.
    """

    network_payload = frame
    version_hint: Literal[4, 6] | None = None
    if link_type == LINKTYPE_ETHERNET:
        _require_length(frame, 14, "Ethernet header")
        offset = 14
        ethertype = struct.unpack("!H", frame[12:14])[0]
        vlan_count = 0
        while ethertype in _VLAN_ETHERTYPES:
            vlan_count += 1
            if vlan_count > 2:
                return None
            _require_length(frame, offset + 4, "VLAN header")
            ethertype = struct.unpack("!H", frame[offset + 2 : offset + 4])[0]
            offset += 4
        if ethertype == _ETHERTYPE_IPV4:
            version_hint = 4
        elif ethertype == _ETHERTYPE_IPV6:
            version_hint = 6
        else:
            return None
        network_payload = frame[offset:]
    elif link_type == LINKTYPE_RAW:
        _require_length(frame, 1, "raw IP version")
        raw_version = frame[0] >> 4
        if raw_version not in {4, 6}:
            return None
        version_hint = 4 if raw_version == 4 else 6
    elif link_type == LINKTYPE_IPV4:
        version_hint = 4
    elif link_type == LINKTYPE_IPV6:
        version_hint = 6
    else:
        return None

    if version_hint == 4:
        return _parse_ipv4(network_payload, timestamp)
    return _parse_ipv6(network_payload, timestamp)
