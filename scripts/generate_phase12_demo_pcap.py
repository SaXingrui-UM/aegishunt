"""Generate the reviewed deterministic Phase 12 PCAP sample.

The sample contains two IPv4 flows sharing one source address:

* a bidirectional UDP exchange; and
* a minimal TCP SYN/SYN-ACK/ACK exchange.

It contains no application payload and performs no network activity.
"""

from __future__ import annotations

import hashlib
import ipaddress
import struct
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "data" / "sample" / "phase12-demo.pcap"
BASE_SECONDS = 1_767_225_600


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    words = struct.unpack(f"!{len(payload) // 2}H", payload)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(payload: bytes) -> bytes:
    destination = bytes.fromhex("020000000002")
    source = bytes.fromhex("020000000001")
    return destination + source + struct.pack("!H", 0x0800) + payload


def _ipv4(source: str, destination: str, protocol: int, payload: bytes, ident: int) -> bytes:
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        ident,
        0,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    checksum = _checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + payload


def _udp(source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8, 0)


def _tcp(source_port: int, destination_port: int, flags: int) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        1,
        0,
        5 << 4,
        flags,
        65_535,
        0,
        0,
    )


def _record(frame: bytes, *, seconds: int, microseconds: int) -> bytes:
    return struct.pack("<IIII", seconds, microseconds, len(frame), len(frame)) + frame


def build_sample() -> bytes:
    """Return stable little-endian PCAP bytes without touching a network device."""

    packets = (
        (
            0,
            0,
            _ethernet(
                _ipv4(
                    "192.0.2.10",
                    "198.51.100.53",
                    17,
                    _udp(53_000, 53),
                    1,
                )
            ),
        ),
        (
            0,
            100_000,
            _ethernet(
                _ipv4(
                    "198.51.100.53",
                    "192.0.2.10",
                    17,
                    _udp(53, 53_000),
                    2,
                )
            ),
        ),
        (
            1,
            0,
            _ethernet(
                _ipv4(
                    "192.0.2.10",
                    "198.51.100.80",
                    6,
                    _tcp(49_152, 443, 0x02),
                    3,
                )
            ),
        ),
        (
            1,
            100_000,
            _ethernet(
                _ipv4(
                    "198.51.100.80",
                    "192.0.2.10",
                    6,
                    _tcp(443, 49_152, 0x12),
                    4,
                )
            ),
        ),
        (
            1,
            200_000,
            _ethernet(
                _ipv4(
                    "192.0.2.10",
                    "198.51.100.80",
                    6,
                    _tcp(49_152, 443, 0x10),
                    5,
                )
            ),
        ),
    )
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    return header + b"".join(
        _record(
            frame,
            seconds=BASE_SECONDS + second_offset,
            microseconds=microseconds,
        )
        for second_offset, microseconds, frame in packets
    )


def main() -> None:
    payload = build_sample()
    OUTPUT.write_bytes(payload)
    print(f"{hashlib.sha256(payload).hexdigest()}  {OUTPUT.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
