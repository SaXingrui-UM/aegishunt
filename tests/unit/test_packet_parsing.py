"""Unit coverage for bounded capture and supported packet decoding."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aegishunt.flows.errors import CaptureFormatError, PacketParseError
from aegishunt.flows.packets import LINKTYPE_ETHERNET, parse_packet
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.schemas.enums import NetworkProtocol
from tests.fixtures.packets import (
    at,
    ethernet_frame,
    icmp_message,
    ipv4_packet,
    ipv6_packet,
    tcp_ipv4_frame,
    tcp_segment,
    udp_datagram,
    write_pcap,
)


def test_parses_ipv4_tcp_udp_and_icmp_without_payload_semantics() -> None:
    tcp = parse_packet(tcp_ipv4_frame(flags=0x12), timestamp=at(0), link_type=1)
    udp = parse_packet(
        ethernet_frame(
            ipv4_packet(udp_datagram(53_000, 53, b"opaque"), protocol=17),
            ethertype=0x0800,
        ),
        timestamp=at(1),
        link_type=1,
    )
    icmp = parse_packet(
        ethernet_frame(ipv4_packet(icmp_message(8, identifier=99), protocol=1), ethertype=0x0800),
        timestamp=at(2),
        link_type=1,
    )

    assert tcp is not None
    assert (tcp.protocol, tcp.source_port, tcp.destination_port, tcp.tcp_flags) == (
        NetworkProtocol.TCP,
        40_000,
        443,
        0x12,
    )
    assert udp is not None
    assert (udp.protocol, udp.network_bytes) == (NetworkProtocol.UDP, 34)
    assert icmp is not None
    assert (icmp.protocol, icmp.icmp_type, icmp.icmp_identifier) == (
        NetworkProtocol.ICMP,
        8,
        99,
    )


def test_parses_ipv6_tcp_and_icmpv6() -> None:
    tcp_frame = ethernet_frame(
        ipv6_packet(tcp_segment(443, 40_000, 0x10), next_header=6),
        ethertype=0x86DD,
    )
    icmp_frame = ethernet_frame(
        ipv6_packet(icmp_message(128, identifier=17), next_header=58),
        ethertype=0x86DD,
    )

    tcp = parse_packet(tcp_frame, timestamp=at(0), link_type=LINKTYPE_ETHERNET)
    icmp = parse_packet(icmp_frame, timestamp=at(1), link_type=LINKTYPE_ETHERNET)

    assert tcp is not None and tcp.ip_version == 6
    assert tcp.source_ip == "2001:db8::1"
    assert icmp is not None and icmp.protocol is NetworkProtocol.ICMP
    assert icmp.protocol_number == 58


def test_skips_non_ip_fragments_unknown_transports_and_link_layers() -> None:
    arp = bytes.fromhex("0200000000020200000000010806") + b"ignored"
    fragmented = bytearray(ipv4_packet(b"abcdefgh", protocol=99))
    fragmented[6:8] = struct.pack("!H", 0x2000)

    assert parse_packet(arp, timestamp=at(0), link_type=1) is None
    assert parse_packet(bytes(fragmented), timestamp=at(0), link_type=101) is None
    assert (
        parse_packet(ipv4_packet(b"abcdefgh", protocol=99), timestamp=at(0), link_type=101)
        is None
    )
    assert parse_packet(b"not-a-supported-link", timestamp=at(0), link_type=999) is None


def test_malformed_supported_packets_raise_typed_errors() -> None:
    with pytest.raises(PacketParseError, match="Ethernet"):
        parse_packet(b"short", timestamp=at(0), link_type=1)
    with pytest.raises(PacketParseError, match="IPv4"):
        parse_packet(b"\x45" + b"\x00" * 10, timestamp=at(0), link_type=101)
    malformed_udp = ipv4_packet(b"\x00" * 7, protocol=17)
    with pytest.raises(PacketParseError, match="UDP"):
        parse_packet(malformed_udp, timestamp=at(0), link_type=101)


def test_classic_reader_is_bounded_and_detects_truncation(tmp_path: Path) -> None:
    capture = write_pcap(tmp_path / "capture.pcap", [(at(0), tcp_ipv4_frame())])
    reader = PcapPacketReader(max_records=1, max_packet_bytes=2_048)

    packets = list(reader.packets(capture))
    assert len(packets) == 1
    assert packets[0].link_type == 1
    assert packets[0].timestamp == at(0)

    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(capture.read_bytes()[:-1])
    with pytest.raises(CaptureFormatError, match="truncated"):
        list(reader.packets(truncated))

    excessive_snap = tmp_path / "excessive-snap.pcap"
    excessive_snap.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 4_096, 1)
        + struct.pack("<IIII", 0, 0, 4_096, 4_096)
    )
    with pytest.raises(CaptureFormatError, match="bounds"):
        list(reader.packets(excessive_snap))


def test_pcapng_enhanced_packet_reader(tmp_path: Path) -> None:
    frame = tcp_ipv4_frame()
    padded_length = (len(frame) + 3) & ~3
    section = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65_535, 20)
    raw_timestamp = int(at(0).timestamp() * 1_000_000)
    block_length = 32 + padded_length
    enhanced = (
        struct.pack("<II", 6, block_length)
        + struct.pack(
            "<IIIII",
            0,
            raw_timestamp >> 32,
            raw_timestamp & 0xFFFFFFFF,
            len(frame),
            len(frame),
        )
        + frame
        + bytes(padded_length - len(frame))
        + struct.pack("<I", block_length)
    )
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(section + interface + enhanced)

    packets = list(PcapPacketReader(max_records=2, max_packet_bytes=2_048).packets(capture))
    assert len(packets) == 1
    assert packets[0].frame == frame
    assert packets[0].timestamp == at(0)


def test_pcapng_simple_packet_block_fails_without_inventing_a_timestamp(
    tmp_path: Path,
) -> None:
    section = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65_535, 20)
    frame = tcp_ipv4_frame()
    padded_length = (len(frame) + 3) & ~3
    block_length = 16 + padded_length
    simple = (
        struct.pack("<III", 3, block_length, len(frame))
        + frame
        + bytes(padded_length - len(frame))
        + struct.pack("<I", block_length)
    )
    capture = tmp_path / "simple.pcapng"
    capture.write_bytes(section + interface + simple)

    with pytest.raises(CaptureFormatError, match="lack timestamps"):
        list(PcapPacketReader(max_records=2, max_packet_bytes=2_048).packets(capture))
