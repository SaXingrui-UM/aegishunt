"""Bounded PCAP and PCAPNG container inspection for Phase 2 ingestion."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import BinaryIO

from aegishunt.ingestion.base import FilePolicy, TelemetryIngestor
from aegishunt.ingestion.errors import TelemetryFormatError
from aegishunt.ingestion.schemas import IngestionInspection
from aegishunt.schemas.enums import SourceType

_CLASSIC_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
    b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
    b"\x4d\x3c\xb2\xa1": ("<", "nanoseconds"),
    b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
}
_PCAPNG_SECTION_TYPE = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}
_PCAPNG_PACKET_BLOCKS = {2, 3, 6}


def _read_exact(stream: BinaryIO, size: int, context: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise TelemetryFormatError(f"truncated PCAP while reading {context}")
    return data


def _ensure_record_limit(count: int, max_records: int) -> None:
    if count > max_records:
        raise TelemetryFormatError(
            f"PCAP contains more than the configured {max_records} record limit"
        )


def _inspect_classic(
    stream: BinaryIO,
    *,
    magic: bytes,
    max_records: int,
) -> IngestionInspection:
    endian, timestamp_resolution = _CLASSIC_MAGIC[magic]
    header = _read_exact(stream, 20, "global header")
    major, minor, _zone, _sigfigs, snaplen, link_type = struct.unpack(
        f"{endian}HHIIII", header
    )
    if (major, minor) != (2, 4):
        raise TelemetryFormatError("unsupported classic PCAP version")
    if snaplen <= 0:
        raise TelemetryFormatError("classic PCAP snap length must be positive")

    count = 0
    while True:
        packet_header = stream.read(16)
        if not packet_header:
            break
        if len(packet_header) != 16:
            raise TelemetryFormatError("truncated classic PCAP packet header")
        _seconds, _fraction, included_length, original_length = struct.unpack(
            f"{endian}IIII", packet_header
        )
        if included_length > snaplen or included_length > original_length:
            raise TelemetryFormatError("classic PCAP packet lengths are inconsistent")
        _read_exact(stream, included_length, "packet payload")
        count += 1
        _ensure_record_limit(count, max_records)

    return IngestionInspection(
        records_processed=count,
        metadata={
            "container": "pcap",
            "version": f"{major}.{minor}",
            "timestamp_resolution": timestamp_resolution,
            "snap_length": snaplen,
            "link_type": link_type,
        },
    )


def _inspect_pcapng(stream: BinaryIO, *, max_records: int) -> IngestionInspection:
    prefix = _read_exact(stream, 8, "PCAPNG section prefix")
    if prefix[:4] != _PCAPNG_SECTION_TYPE:
        raise TelemetryFormatError("invalid PCAPNG section header")
    byte_order_magic = _read_exact(stream, 4, "PCAPNG byte-order magic")
    endian = _PCAPNG_BYTE_ORDER.get(byte_order_magic)
    if endian is None:
        raise TelemetryFormatError("invalid PCAPNG byte-order magic")
    section_length = struct.unpack(f"{endian}I", prefix[4:8])[0]
    if section_length < 28 or section_length % 4 != 0:
        raise TelemetryFormatError("invalid PCAPNG section block length")
    section_remainder = _read_exact(
        stream, section_length - 12, "PCAPNG section block"
    )
    if struct.unpack(f"{endian}I", section_remainder[-4:])[0] != section_length:
        raise TelemetryFormatError("PCAPNG section block length trailer does not match")
    major, minor = struct.unpack(f"{endian}HH", section_remainder[:4])
    if (major, minor) != (1, 0):
        raise TelemetryFormatError("unsupported PCAPNG version")

    count = 0
    block_count = 1
    while True:
        header = stream.read(8)
        if not header:
            break
        if len(header) != 8:
            raise TelemetryFormatError("truncated PCAPNG block header")
        if header[:4] == _PCAPNG_SECTION_TYPE:
            raise TelemetryFormatError("multiple PCAPNG sections are not supported in Phase 2")
        block_type, block_length = struct.unpack(f"{endian}II", header)
        if block_length < 12 or block_length % 4 != 0:
            raise TelemetryFormatError("invalid PCAPNG block length")
        remainder = _read_exact(stream, block_length - 8, "PCAPNG block")
        if struct.unpack(f"{endian}I", remainder[-4:])[0] != block_length:
            raise TelemetryFormatError("PCAPNG block length trailer does not match")
        block_count += 1
        if block_type in _PCAPNG_PACKET_BLOCKS:
            count += 1
            _ensure_record_limit(count, max_records)

    return IngestionInspection(
        records_processed=count,
        metadata={
            "container": "pcapng",
            "version": f"{major}.{minor}",
            "byte_order": "little" if endian == "<" else "big",
            "block_count": block_count,
        },
    )


class PcapIngestor(TelemetryIngestor):
    """Validate PCAP framing without decoding packets or deriving flows."""

    source_type = SourceType.PCAP
    policy = FilePolicy(
        extensions=frozenset({".pcap", ".pcapng"}),
        content_types=frozenset(
            {
                "application/octet-stream",
                "application/vnd.tcpdump.pcap",
                "application/x-pcap",
            }
        ),
    )

    def inspect(self, path: Path, *, max_records: int) -> IngestionInspection:
        try:
            with path.open("rb") as stream:
                magic = stream.read(4)
                if magic in _CLASSIC_MAGIC:
                    return _inspect_classic(
                        stream,
                        magic=magic,
                        max_records=max_records,
                    )
                if magic == _PCAPNG_SECTION_TYPE:
                    stream.seek(0)
                    return _inspect_pcapng(stream, max_records=max_records)
        except OSError as exc:
            raise TelemetryFormatError("unable to read staged PCAP") from exc
        raise TelemetryFormatError("file does not contain a recognized PCAP container")
