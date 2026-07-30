"""Regression coverage for the safe final-delivery sample contract."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
from uuid import UUID

import pytest

from aegishunt.config import FlowSettings
from aegishunt.flows.service import PcapFlowProcessor
from scripts.generate_phase14_samples import (
    PROFILES,
    SourceProfile,
    build_profile,
    build_provenance,
)

ROOT = Path(__file__).parents[2]
EXPECTED = {
    "phase14-attack-like.pcap": (
        "efb3c6334ba5d484b1662fd34df748d90e5ee1208a5edda00adfbd76d7feaca8",
        1_017,
        42,
    ),
    "phase14-benign-like.pcap": (
        "5c93e494e6ebca226d22f4a0b888bda20d2e178c92f6096b40df0dfa75f6a61a",
        571,
        51,
    ),
}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@pytest.mark.parametrize(
    ("profile", "filename"),
    tuple(zip(PROFILES, EXPECTED, strict=True)),
)
def test_phase14_sample_generation_is_deterministic_and_payload_free(
    profile: SourceProfile,
    filename: str,
) -> None:
    generated = build_profile(profile)
    committed = (ROOT / "data/sample" / filename).read_bytes()

    assert generated == committed
    assert _sha256(generated) == EXPECTED[filename][0]
    assert profile.source_filename.encode() not in generated


@pytest.mark.parametrize(("filename", "expected"), EXPECTED.items())
def test_phase14_samples_parse_to_declared_aggregate_profiles(
    filename: str,
    expected: tuple[str, int, int],
) -> None:
    result = PcapFlowProcessor(
        FlowSettings(),
        max_records=2_000,
    ).process(
        ROOT / "data/sample" / filename,
        source_id=UUID(int=0),
        capture_session_id=f"phase14-{filename}",
    )

    assert result.captured_packets == expected[1]
    assert result.skipped_packets == 0
    assert len(result.flows) == expected[2]
    addresses = {
        address
        for flow in result.flows
        for address in (flow.source_ip, flow.destination_ip)
    }
    assert all(ipaddress.ip_address(address).is_private for address in addresses)


def test_phase14_provenance_distinguishes_profile_names_from_ground_truth() -> None:
    outputs = {
        "phase14-attack-like.pcap": build_profile(PROFILES[0]),
        "phase14-benign-like.pcap": build_profile(PROFILES[1]),
    }
    expected = build_provenance(outputs)
    committed = json.loads(
        (ROOT / "data/sample/phase14-sample-provenance.json").read_text(encoding="utf-8")
    )

    assert committed == expected
    assert committed["transformation"]["copies_source_payload"] is False
    assert committed["transformation"]["copies_source_addresses"] is False
    assert "profile names are not verified ground-truth labels" in committed["limitations"]
    assert "not a public benchmark or production validation" in committed["limitations"]
