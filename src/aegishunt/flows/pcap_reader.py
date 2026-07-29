"""Streaming, bounded packet records from validated PCAP and PCAPNG files."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from aegishunt.flows.errors import CaptureFormatError

_CLASSIC_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION_TYPE = b"\x0a\x0d\x0d\x0a"
_PCAPNG_BYTE_ORDER = {
    b"\x4d\x3c\x2b\x1a": "<",
    b"\x1a\x2b\x3c\x4d": ">",
}
_PCAPNG_INTERFACE_BLOCK = 1
_PCAPNG_PACKET_BLOCK = 2
_PCAPNG_SIMPLE_PACKET_BLOCK = 3
_PCAPNG_ENHANCED_PACKET_BLOCK = 6
_MAX_INTERFACE_BLOCK_BYTES = 65_536


@dataclass(frozen=True, slots=True)
class CapturedPacket:
    timestamp: datetime
    frame: bytes
    original_length: int
    link_type: int


@dataclass(frozen=True, slots=True)
class _Interface:
    link_type: int
    snap_length: int
    timestamp_units: int


def _read_exact(stream: BinaryIO, size: int, context: str) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CaptureFormatError(f"truncated capture while reading {context}")
    return data


def _discard_exact(stream: BinaryIO, size: int, context: str) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 65_536))
        if not chunk:
            raise CaptureFormatError(f"truncated capture while reading {context}")
        remaining -= len(chunk)


def _timestamp(seconds: int, fraction: int, units: int) -> datetime:
    if fraction >= units:
        raise CaptureFormatError("capture timestamp fraction exceeds its resolution")
    try:
        return datetime.fromtimestamp(seconds, UTC) + timedelta(
            microseconds=(fraction * 1_000_000) // units
        )
    except (OverflowError, OSError, ValueError) as exc:
        raise CaptureFormatError("capture timestamp is outside the supported range") from exc


def _combined_timestamp(raw_value: int, units: int) -> datetime:
    seconds, fraction = divmod(raw_value, units)
    return _timestamp(seconds, fraction, units)


def _read_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise CaptureFormatError("truncated PCAPNG option header")
        code, length = struct.unpack(f"{endian}HH", data[offset : offset + 4])
        offset += 4
        padded_length = (length + 3) & ~3
        if padded_length > len(data) - offset:
            raise CaptureFormatError("truncated PCAPNG option value")
        value = data[offset : offset + length]
        offset += padded_length
        if code == 0:
            if length != 0:
                raise CaptureFormatError("invalid PCAPNG end-of-options marker")
            if any(data[offset:]):
                raise CaptureFormatError("non-zero bytes follow PCAPNG end-of-options")
            break
        options.setdefault(code, []).append(value)
    return options


def _timestamp_units(options: dict[int, list[bytes]]) -> int:
    values = options.get(9)
    if not values:
        return 1_000_000
    value = values[0]
    if len(value) != 1:
        raise CaptureFormatError("invalid PCAPNG timestamp-resolution option")
    exponent = int(value[0])
    if exponent & 0x80:
        power = exponent & 0x7F
        if power > 63:
            raise CaptureFormatError("unsupported PCAPNG binary timestamp resolution")
        return int(2**power)
    if exponent > 18:
        raise CaptureFormatError("unsupported PCAPNG decimal timestamp resolution")
    return int(10**exponent)


class PcapPacketReader:
    """Read packet bytes with record and allocation bounds independent of Phase 2."""

    def __init__(
        self,
        *,
        max_records: int,
        max_packet_bytes: int,
        max_interfaces: int = 256,
    ) -> None:
        self._max_records = max_records
        self._max_packet_bytes = max_packet_bytes
        self._max_interfaces = max_interfaces

    def packets(self, path: Path) -> Iterator[CapturedPacket]:
        """Yield captured packets without loading the capture into memory."""

        try:
            with path.open("rb") as stream:
                magic = _read_exact(stream, 4, "capture magic")
                if magic in _CLASSIC_MAGIC:
                    yield from self._classic_packets(stream, magic)
                    return
                if magic == _PCAPNG_SECTION_TYPE:
                    stream.seek(0)
                    yield from self._pcapng_packets(stream)
                    return
        except OSError as exc:
            raise CaptureFormatError("unable to read stored capture") from exc
        raise CaptureFormatError("stored file is not a supported PCAP container")

    def _classic_packets(
        self,
        stream: BinaryIO,
        magic: bytes,
    ) -> Iterator[CapturedPacket]:
        endian, timestamp_units = _CLASSIC_MAGIC[magic]
        header = _read_exact(stream, 20, "classic PCAP global header")
        major, minor, _zone, _sigfigs, snap_length, link_type = struct.unpack(
            f"{endian}HHIIII", header
        )
        if (major, minor) != (2, 4) or snap_length <= 0:
            raise CaptureFormatError("unsupported classic PCAP header")

        count = 0
        while True:
            packet_header = stream.read(16)
            if not packet_header:
                return
            if len(packet_header) != 16:
                raise CaptureFormatError("truncated classic PCAP packet header")
            seconds, fraction, included_length, original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            if (
                included_length > snap_length
                or included_length > original_length
                or included_length > self._max_packet_bytes
            ):
                raise CaptureFormatError("classic PCAP packet length exceeds declared bounds")
            frame = _read_exact(stream, included_length, "classic PCAP packet data")
            count += 1
            if count > self._max_records:
                raise CaptureFormatError("capture exceeds the configured packet record limit")
            yield CapturedPacket(
                timestamp=_timestamp(seconds, fraction, timestamp_units),
                frame=frame,
                original_length=original_length,
                link_type=link_type,
            )

    def _pcapng_section(self, stream: BinaryIO) -> str:
        prefix = _read_exact(stream, 8, "PCAPNG section prefix")
        if prefix[:4] != _PCAPNG_SECTION_TYPE:
            raise CaptureFormatError("invalid PCAPNG section header")
        byte_order_magic = _read_exact(stream, 4, "PCAPNG byte-order magic")
        endian = _PCAPNG_BYTE_ORDER.get(byte_order_magic)
        if endian is None:
            raise CaptureFormatError("invalid PCAPNG byte-order magic")
        section_length = struct.unpack(f"{endian}I", prefix[4:8])[0]
        if section_length < 28 or section_length % 4:
            raise CaptureFormatError("invalid PCAPNG section block length")
        fields = _read_exact(stream, 12, "PCAPNG section fields")
        if struct.unpack(f"{endian}HH", fields[:4]) != (1, 0):
            raise CaptureFormatError("unsupported PCAPNG version")
        _discard_exact(stream, section_length - 28, "PCAPNG section options")
        trailer = struct.unpack(
            f"{endian}I", _read_exact(stream, 4, "PCAPNG section trailer")
        )[0]
        if trailer != section_length:
            raise CaptureFormatError("PCAPNG section length trailer does not match")
        return endian

    def _pcapng_packets(self, stream: BinaryIO) -> Iterator[CapturedPacket]:
        endian = self._pcapng_section(stream)
        interfaces: list[_Interface] = []
        count = 0
        while True:
            header = stream.read(8)
            if not header:
                return
            if len(header) != 8:
                raise CaptureFormatError("truncated PCAPNG block header")
            if header[:4] == _PCAPNG_SECTION_TYPE:
                raise CaptureFormatError("multiple PCAPNG sections are not supported")
            block_type, block_length = struct.unpack(f"{endian}II", header)
            if block_length < 12 or block_length % 4:
                raise CaptureFormatError("invalid PCAPNG block length")
            body_length = block_length - 12

            packet: CapturedPacket | None = None
            if block_type == _PCAPNG_INTERFACE_BLOCK:
                if body_length > _MAX_INTERFACE_BLOCK_BYTES:
                    raise CaptureFormatError("PCAPNG interface block exceeds metadata limit")
                body = _read_exact(stream, body_length, "PCAPNG interface block")
                if len(body) < 8:
                    raise CaptureFormatError("truncated PCAPNG interface block")
                link_type, _reserved, snap_length = struct.unpack(f"{endian}HHI", body[:8])
                if snap_length <= 0:
                    raise CaptureFormatError("PCAPNG interface snap length must be positive")
                if len(interfaces) >= self._max_interfaces:
                    raise CaptureFormatError(
                        "PCAPNG interface inventory exceeds the configured limit"
                    )
                options = _read_options(body[8:], endian)
                interfaces.append(
                    _Interface(
                        link_type=link_type,
                        snap_length=snap_length,
                        timestamp_units=_timestamp_units(options),
                    )
                )
            elif block_type in {_PCAPNG_ENHANCED_PACKET_BLOCK, _PCAPNG_PACKET_BLOCK}:
                fixed_length = 20
                if body_length < fixed_length:
                    raise CaptureFormatError("truncated PCAPNG packet fields")
                fixed = _read_exact(stream, fixed_length, "PCAPNG packet fields")
                if block_type == _PCAPNG_ENHANCED_PACKET_BLOCK:
                    packet_fields = struct.unpack(f"{endian}IIIII", fixed)
                    (
                        interface_id,
                        timestamp_high,
                        timestamp_low,
                        captured_length,
                        original_length,
                    ) = packet_fields
                else:
                    packet_fields = struct.unpack(f"{endian}HHIIII", fixed)
                    (
                        interface_id,
                        _drops,
                        timestamp_high,
                        timestamp_low,
                        captured_length,
                        original_length,
                    ) = packet_fields
                if interface_id >= len(interfaces):
                    raise CaptureFormatError("PCAPNG packet references an unknown interface")
                interface = interfaces[interface_id]
                padded_length = (captured_length + 3) & ~3
                if (
                    captured_length > original_length
                    or captured_length > interface.snap_length
                    or captured_length > self._max_packet_bytes
                    or fixed_length + padded_length > body_length
                ):
                    raise CaptureFormatError("PCAPNG packet length exceeds declared bounds")
                frame = _read_exact(stream, captured_length, "PCAPNG packet data")
                _discard_exact(stream, padded_length - captured_length, "PCAPNG packet padding")
                _discard_exact(
                    stream,
                    body_length - fixed_length - padded_length,
                    "PCAPNG packet options",
                )
                raw_timestamp = (timestamp_high << 32) | timestamp_low
                packet = CapturedPacket(
                    timestamp=_combined_timestamp(raw_timestamp, interface.timestamp_units),
                    frame=frame,
                    original_length=original_length,
                    link_type=interface.link_type,
                )
            elif block_type == _PCAPNG_SIMPLE_PACKET_BLOCK:
                _discard_exact(stream, body_length, "PCAPNG simple packet block")
                raise CaptureFormatError(
                    "PCAPNG simple packet blocks lack timestamps and cannot form flows"
                )
            else:
                _discard_exact(stream, body_length, "PCAPNG block body")

            trailer = struct.unpack(
                f"{endian}I", _read_exact(stream, 4, "PCAPNG block trailer")
            )[0]
            if trailer != block_length:
                raise CaptureFormatError("PCAPNG block length trailer does not match")
            if packet is not None:
                count += 1
                if count > self._max_records:
                    raise CaptureFormatError("capture exceeds the configured packet record limit")
                yield packet
