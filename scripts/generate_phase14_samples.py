"""Build safe final-delivery samples from uploaded-capture aggregate profiles.

The user-supplied source captures are never changed or copied. The committed
outputs contain only generated Ethernet/IPv4/TCP headers, no application
payload, and IANA documentation addresses. Profile names are not labels.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_ROOT = PROJECT_ROOT / "data" / "sample"
ATTACK_OUTPUT = SAMPLE_ROOT / "phase14-attack-like.pcap"
BENIGN_OUTPUT = SAMPLE_ROOT / "phase14-benign-like.pcap"
PROVENANCE_OUTPUT = SAMPLE_ROOT / "phase14-sample-provenance.json"
BASE_SECONDS = 1_767_225_600


@dataclass(frozen=True, slots=True)
class SourceProfile:
    """Reviewed aggregate facts retained without source payload or addresses."""

    profile: str
    source_filename: str
    source_sha256: str
    source_size_bytes: int
    observed_packet_count: int
    observed_flow_count: int
    observed_duration_seconds: float
    generated_destination_port: int


PROFILES = (
    SourceProfile(
        profile="attack-like",
        source_filename="traffic_attack.pcap",
        source_sha256="5bf949b7bed450968d220d8da26dbeea2009c2e4b68772d3b45c00e760f68ad5",
        source_size_bytes=89_711,
        observed_packet_count=1_017,
        observed_flow_count=42,
        observed_duration_seconds=59.0,
        generated_destination_port=21,
    ),
    SourceProfile(
        profile="benign-like",
        source_filename="traffic_benign.pcap",
        source_sha256="3ba50eb01e9727b7e23312e119d568f095616fb7fd504fb522b78f00ecde6800",
        source_size_bytes=102_675,
        observed_packet_count=571,
        observed_flow_count=51,
        observed_duration_seconds=88.0,
        generated_destination_port=80,
    ),
)


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = sum(struct.unpack(f"!{len(payload) // 2}H", payload))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    *,
    flags: int,
    identifier: int,
) -> bytes:
    tcp = struct.pack(
        "!HHIIHHHH",
        source_port,
        destination_port,
        identifier,
        0,
        (5 << 12) | flags,
        8_192,
        0,
        0,
    )
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        identifier % 65_535,
        0,
        64,
        6,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    ethernet = (
        bytes.fromhex("020000000002")
        + bytes.fromhex("020000000001")
        + struct.pack("!H", 0x0800)
    )
    return ethernet + header + tcp


def _packet_counts(total: int, flows: int) -> tuple[int, ...]:
    minimum, remainder = divmod(total, flows)
    return tuple(minimum + (1 if index < remainder else 0) for index in range(flows))


def build_profile(profile: SourceProfile) -> bytes:
    """Return a stable payload-free capture matching aggregate count and duration."""

    client = "192.0.2.10" if profile.profile == "attack-like" else "192.0.2.20"
    server = "198.51.100.10" if profile.profile == "attack-like" else "198.51.100.20"
    records = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    packet_index = 0
    denominator = max(profile.observed_packet_count - 1, 1)
    for flow_index, count in enumerate(
        _packet_counts(profile.observed_packet_count, profile.observed_flow_count)
    ):
        source_port = 40_000 + flow_index
        for flow_packet in range(count):
            forward = flow_packet % 3 != 1
            if flow_packet == 0:
                flags = 0x02
            elif flow_packet == 1:
                flags = 0x12
            elif flow_packet == count - 1:
                flags = 0x11
            else:
                flags = 0x10
            frame = _frame(
                client if forward else server,
                server if forward else client,
                source_port if forward else profile.generated_destination_port,
                profile.generated_destination_port if forward else source_port,
                flags=flags,
                identifier=packet_index + 1,
            )
            offset_us = round(
                profile.observed_duration_seconds * 1_000_000 * packet_index / denominator
            )
            seconds, microseconds = divmod(offset_us, 1_000_000)
            records.extend(
                struct.pack(
                    "<IIII",
                    BASE_SECONDS + seconds,
                    microseconds,
                    len(frame),
                    len(frame),
                )
            )
            records.extend(frame)
            packet_index += 1
    return bytes(records)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _verify_optional_source(path: Path | None, profile: SourceProfile) -> None:
    if path is None:
        return
    payload = path.read_bytes()
    if path.name != profile.source_filename:
        raise ValueError(f"source filename must be {profile.source_filename}")
    if len(payload) != profile.source_size_bytes or _sha256(payload) != profile.source_sha256:
        raise ValueError(f"{profile.source_filename} does not match reviewed source identity")


def build_provenance(outputs: dict[str, bytes]) -> dict[str, object]:
    """Return a canonical disclosure and checksum inventory."""

    return {
        "schema_version": "1.0.0",
        "generator": "scripts/generate_phase14_samples.py",
        "sources": [
            {
                "filename": profile.source_filename,
                "sha256": profile.source_sha256,
                "size_bytes": profile.source_size_bytes,
                "provenance": "user supplied; acquisition provenance and license not established",
                "observed_packet_count": profile.observed_packet_count,
                "observed_flow_count": profile.observed_flow_count,
                "observed_duration_seconds": profile.observed_duration_seconds,
            }
            for profile in PROFILES
        ],
        "transformation": {
            "copies_source_payload": False,
            "copies_source_addresses": False,
            "documentation_addresses_only": True,
            "generated_headers_only": True,
            "preserved_aggregate_fields": [
                "packet_count",
                "flow_count",
                "capture_duration",
                "destination-port profile",
            ],
        },
        "outputs": {
            name: {
                "sha256": _sha256(payload),
                "size_bytes": len(payload),
                "synthetic": True,
            }
            for name, payload in sorted(outputs.items())
        },
        "limitations": [
            "profile names are not verified ground-truth labels",
            "not a public benchmark or production validation",
            "not used for model, calibration, threshold, or policy selection",
            "does not preserve application payload or original network identities",
            "controlled offline pipeline demonstration only",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-attack", type=Path)
    parser.add_argument("--source-benign", type=Path)
    arguments = parser.parse_args()
    _verify_optional_source(arguments.source_attack, PROFILES[0])
    _verify_optional_source(arguments.source_benign, PROFILES[1])
    outputs = {
        ATTACK_OUTPUT.name: build_profile(PROFILES[0]),
        BENIGN_OUTPUT.name: build_profile(PROFILES[1]),
    }
    for filename, payload in outputs.items():
        (SAMPLE_ROOT / filename).write_bytes(payload)
    PROVENANCE_OUTPUT.write_text(
        json.dumps(build_provenance(outputs), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for filename, payload in sorted(outputs.items()):
        print(f"{_sha256(payload)}  data/sample/{filename}")


if __name__ == "__main__":
    main()
