"""Synthetic, documentation-range packet and PCAP builders for tests."""

from __future__ import annotations

import ipaddress
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def at(seconds: float) -> datetime:
    return BASE_TIME + timedelta(seconds=seconds)


def tcp_segment(source_port: int, destination_port: int, flags: int) -> bytes:
    return struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        0,
        0,
        (5 << 12) | flags,
        8_192,
        0,
        0,
    )


def udp_datagram(source_port: int, destination_port: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def icmp_message(icmp_type: int, code: int = 0, identifier: int = 7) -> bytes:
    return struct.pack("!BBHHH", icmp_type, code, 0, identifier, 1)


def ipv4_packet(
    transport: bytes,
    *,
    protocol: int,
    source_ip: str = "192.0.2.1",
    destination_ip: str = "198.51.100.2",
) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        1,
        0,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(source_ip).packed,
        ipaddress.IPv4Address(destination_ip).packed,
    ) + transport


def ipv6_packet(
    transport: bytes,
    *,
    next_header: int,
    source_ip: str = "2001:db8::1",
    destination_ip: str = "2001:db8::2",
) -> bytes:
    return struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(transport),
        next_header,
        64,
        ipaddress.IPv6Address(source_ip).packed,
        ipaddress.IPv6Address(destination_ip).packed,
    ) + transport


def ethernet_frame(network_packet: bytes, *, ethertype: int) -> bytes:
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", ethertype) + network_packet


def tcp_ipv4_frame(
    *,
    source_ip: str = "192.0.2.1",
    destination_ip: str = "198.51.100.2",
    source_port: int = 40_000,
    destination_port: int = 443,
    flags: int = 0x02,
) -> bytes:
    return ethernet_frame(
        ipv4_packet(
            tcp_segment(source_port, destination_port, flags),
            protocol=6,
            source_ip=source_ip,
            destination_ip=destination_ip,
        ),
        ethertype=0x0800,
    )


def write_pcap(path: Path, packets: list[tuple[datetime, bytes]], *, link_type: int = 1) -> Path:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, link_type)
    body = bytearray(global_header)
    for timestamp, frame in packets:
        epoch = timestamp.timestamp()
        seconds = int(epoch)
        microseconds = int(round((epoch - seconds) * 1_000_000))
        body.extend(struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)))
        body.extend(frame)
    path.write_bytes(bytes(body))
    return path
