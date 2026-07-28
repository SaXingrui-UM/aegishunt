"""Generate the controlled Phase 12 presentation PCAP and inventory manifest.

The capture is wholly synthetic, performs no network activity, and uses only
IANA documentation address ranges. Payload bytes are inert presentation
padding; there are no credentials, exploits, malware, or executable commands.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT = PROJECT_ROOT / "data" / "sample" / "phase12-presentation-demo.pcap"
MANIFEST = (
    PROJECT_ROOT / "data" / "sample" / "phase12-presentation-demo.manifest.json"
)
BASE_SECONDS = 1_767_225_600


@dataclass(frozen=True, slots=True)
class PacketSpec:
    offset_microseconds: int
    frame: bytes
    ip_version: int
    protocol: str
    profile: str
    source_ip: str
    destination_ip: str


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(int(value) for value in struct.unpack(f"!{len(payload) // 2}H", payload))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ethernet(payload: bytes, *, ip_version: int) -> bytes:
    destination = bytes.fromhex("020000000002")
    source = bytes.fromhex("020000000001")
    ethertype = 0x0800 if ip_version == 4 else 0x86DD
    return destination + source + struct.pack("!H", ethertype) + payload


def _ipv4(
    source: str,
    destination: str,
    protocol: int,
    payload: bytes,
    ident: int,
) -> bytes:
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
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    checksum = _checksum(header)
    return header[:10] + struct.pack("!H", checksum) + header[12:] + payload


def _ipv6(source: str, destination: str, next_header: int, payload: bytes) -> bytes:
    return (
        struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(payload),
            next_header,
            64,
            ipaddress.IPv6Address(source).packed,
            ipaddress.IPv6Address(destination).packed,
        )
        + payload
    )


def _udp(source_port: int, destination_port: int, payload_size: int = 0) -> bytes:
    payload = bytes([0x44]) * payload_size
    return (
        struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
        + payload
    )


def _tcp(
    source_port: int,
    destination_port: int,
    flags: int,
    payload_size: int = 0,
) -> bytes:
    return (
        struct.pack(
            "!HHIIHHHH",
            source_port,
            destination_port,
            1,
            0,
            (5 << 12) | flags,
            8_192,
            0,
            0,
        )
        + bytes([0x57]) * payload_size
    )


def _icmp(icmp_type: int, identifier: int, payload_size: int = 8) -> bytes:
    payload = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, 1)
    return payload + bytes([0x49]) * payload_size


def _packet(
    *,
    offset_microseconds: int,
    ip_version: int,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    transport: bytes,
    profile: str,
    ident: int,
) -> PacketSpec:
    protocol_number = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}[protocol]
    network = (
        _ipv4(source_ip, destination_ip, protocol_number, transport, ident)
        if ip_version == 4
        else _ipv6(source_ip, destination_ip, protocol_number, transport)
    )
    return PacketSpec(
        offset_microseconds=offset_microseconds,
        frame=_ethernet(network, ip_version=ip_version),
        ip_version=ip_version,
        protocol=protocol,
        profile=profile,
        source_ip=source_ip,
        destination_ip=destination_ip,
    )


def packet_specs() -> tuple[PacketSpec, ...]:
    """Return the ordered, deterministic presentation packet inventory."""

    specs: list[PacketSpec] = []
    ident = 1

    def add(
        offset: int,
        version: int,
        source: str,
        destination: str,
        protocol: str,
        transport: bytes,
        profile: str,
    ) -> None:
        nonlocal ident
        specs.append(
            _packet(
                offset_microseconds=offset,
                ip_version=version,
                source_ip=source,
                destination_ip=destination,
                protocol=protocol,
                transport=transport,
                profile=profile,
                ident=ident,
            )
        )
        ident += 1

    # Benign DNS-like request/response (port semantics only; inert payload).
    add(0, 4, "192.0.2.10", "198.51.100.53", "udp", _udp(53000, 53, 12), "dns-like")
    add(80_000, 4, "198.51.100.53", "192.0.2.10", "udp", _udp(53, 53000, 24), "dns-like")

    # Benign web-like IPv4 handshake and directional exchange.
    web = ("192.0.2.20", "203.0.113.80", 49152, 443)
    add(200_000, 4, web[0], web[1], "tcp", _tcp(web[2], web[3], 0x02), "web-like")
    add(250_000, 4, web[1], web[0], "tcp", _tcp(web[3], web[2], 0x12), "web-like")
    add(300_000, 4, web[0], web[1], "tcp", _tcp(web[2], web[3], 0x10), "web-like")
    add(350_000, 4, web[0], web[1], "tcp", _tcp(web[2], web[3], 0x18, 48), "web-like")
    add(420_000, 4, web[1], web[0], "tcp", _tcp(web[3], web[2], 0x18, 180), "web-like")

    # Three controlled short connections; no flood and no payload.
    for index, port in enumerate((50010, 50011, 50012)):
        base = 600_000 + index * 250_000
        add(
            base,
            4,
            "192.0.2.30",
            "203.0.113.81",
            "tcp",
            _tcp(port, 8443, 0x02),
            "repeated-short",
        )
        add(
            base + 40_000,
            4,
            "203.0.113.81",
            "192.0.2.30",
            "tcp",
            _tcp(8443, port, 0x12),
            "repeated-short",
        )
        add(
            base + 80_000,
            4,
            "192.0.2.30",
            "203.0.113.81",
            "tcp",
            _tcp(port, 8443, 0x10),
            "repeated-short",
        )

    # Periodic small IPv6 UDP request/response observations.
    for index in range(3):
        base = 1_500_000 + index * 500_000
        add(
            base,
            6,
            "2001:db8::10",
            "2001:db8::53",
            "udp",
            _udp(54000, 53, 8),
            "periodic-small",
        )
        add(
            base + 60_000,
            6,
            "2001:db8::53",
            "2001:db8::10",
            "udp",
            _udp(53, 54000, 12),
            "periodic-small",
        )

    # Controlled asymmetric IPv6 web-like transfer: one small request, larger replies.
    asymmetric = ("2001:db8::20", "2001:db8::80", 51000, 443)
    for offset, source, destination, transport in (
        (3_200_000, asymmetric[0], asymmetric[1], _tcp(asymmetric[2], asymmetric[3], 0x02)),
        (3_250_000, asymmetric[1], asymmetric[0], _tcp(asymmetric[3], asymmetric[2], 0x12)),
        (3_300_000, asymmetric[0], asymmetric[1], _tcp(asymmetric[2], asymmetric[3], 0x10)),
        (3_350_000, asymmetric[0], asymmetric[1], _tcp(asymmetric[2], asymmetric[3], 0x18, 24)),
        (3_450_000, asymmetric[1], asymmetric[0], _tcp(asymmetric[3], asymmetric[2], 0x18, 320)),
        (3_550_000, asymmetric[1], asymmetric[0], _tcp(asymmetric[3], asymmetric[2], 0x18, 480)),
    ):
        add(offset, 6, source, destination, "tcp", transport, "asymmetric-transfer-like")

    # Bidirectional IPv4 ICMP and IPv6 ICMPv6 echo exchanges.
    add(4_000_000, 4, "192.0.2.40", "198.51.100.40", "icmp", _icmp(8, 40), "icmp-echo")
    add(4_080_000, 4, "198.51.100.40", "192.0.2.40", "icmp", _icmp(0, 40), "icmp-echo")
    add(
        4_300_000,
        6,
        "2001:db8::40",
        "2001:db8::41",
        "icmpv6",
        _icmp(128, 41),
        "icmpv6-echo",
    )
    add(
        4_380_000,
        6,
        "2001:db8::41",
        "2001:db8::40",
        "icmpv6",
        _icmp(129, 41),
        "icmpv6-echo",
    )
    return tuple(specs)


def build_sample() -> bytes:
    """Return stable little-endian PCAP bytes without opening a network device."""

    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    records = bytearray(header)
    for spec in packet_specs():
        seconds, microseconds = divmod(spec.offset_microseconds, 1_000_000)
        records.extend(
            struct.pack(
                "<IIII",
                BASE_SECONDS + seconds,
                microseconds,
                len(spec.frame),
                len(spec.frame),
            )
        )
        records.extend(spec.frame)
    return bytes(records)


def build_manifest(payload: bytes) -> dict[str, object]:
    specs = packet_specs()
    return {
        "schema_version": "1.0.0",
        "sample_id": "phase12-presentation-demo-pcap",
        "filename": OUTPUT.name,
        "generator": "scripts/generate_phase12_presentation_pcap.py",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
        "packet_count": len(specs),
        "ip_version_inventory": dict(sorted(Counter(item.ip_version for item in specs).items())),
        "protocol_inventory": dict(sorted(Counter(item.protocol for item in specs).items())),
        "profile_inventory": dict(sorted(Counter(item.profile for item in specs).items())),
        "address_inventory": sorted(
            {item.source_ip for item in specs} | {item.destination_ip for item in specs}
        ),
        "safety": {
            "synthetic": True,
            "offline": True,
            "documentation_addresses_only": True,
            "contains_exploit_payload": False,
            "contains_credentials": False,
            "contains_malware": False,
            "contains_unrestricted_flood": False,
        },
        "limitations": [
            "synthetic controlled presentation telemetry",
            "not a performance benchmark",
            "not evidence of attack or model quality",
            "protocol names describe packet construction, not application validation",
        ],
    }


def main() -> None:
    payload = build_sample()
    OUTPUT.write_bytes(payload)
    MANIFEST.write_text(
        json.dumps(build_manifest(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{hashlib.sha256(payload).hexdigest()}  {OUTPUT.relative_to(PROJECT_ROOT)}")


if __name__ == "__main__":
    main()
