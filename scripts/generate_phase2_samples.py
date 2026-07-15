"""Generate the deterministic, target-free Phase 2 PCAP demonstration input."""

from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path


def _internet_checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    words = struct.unpack(f"!{len(payload) // 2}H", payload)
    value = sum(words)
    value = (value & 0xFFFF) + (value >> 16)
    value += value >> 16
    return (~value) & 0xFFFF


def _dns_query() -> bytes:
    labels = (b"aegishunt", b"test")
    question_name = b"".join(bytes([len(label)]) + label for label in labels) + b"\x00"
    return (
        struct.pack("!HHHHHH", 0xA2E1, 0x0100, 1, 0, 0, 0)
        + question_name
        + struct.pack("!HH", 1, 1)
    )


def _packet() -> bytes:
    dns = _dns_query()
    udp = struct.pack("!HHHH", 53_000, 53, 8 + len(dns), 0) + dns
    source_ip = socket.inet_aton("192.0.2.10")
    destination_ip = socket.inet_aton("198.51.100.53")
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        source_ip,
        destination_ip,
    )
    ipv4 = (
        header_without_checksum[:10]
        + struct.pack("!H", _internet_checksum(header_without_checksum))
        + header_without_checksum[12:]
    )
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return ethernet + ipv4 + udp


def generate(output: Path) -> None:
    """Write one deterministic classic PCAP containing a synthetic DNS query."""

    packet = _packet()
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    packet_header = struct.pack("<IIII", 1_767_225_600, 0, len(packet), len(packet))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(global_header + packet_header + packet)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    generate(arguments.output)


if __name__ == "__main__":
    main()
