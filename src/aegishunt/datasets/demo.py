"""Offline controlled flow generator backed by the Phase 3 feature engine."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, UUID, uuid5

from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.schemas import (
    CANONICAL_SCHEMA_VERSION,
    CONVERSION_VERSION,
    CanonicalDatasetRow,
    CanonicalFeatureVector,
    CanonicalMetadata,
)
from aegishunt.flows.aggregator import FinalizedFlowState
from aegishunt.flows.finalizer import finalize_network_flow
from aegishunt.flows.packets import PacketRecord
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.flows.state import FlowEndReason, FlowState
from aegishunt.schemas.enums import NetworkProtocol

DEMO_DATASET_ID = "aegishunt-controlled-demo"
DEMO_DATASET_VERSION = "1.0.0"
DEMO_GENERATOR_VERSION = "1.0.0"
DEFAULT_GROUPS_PER_PATTERN = 3
ROWS_PER_GROUP = 2
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class DemoPattern:
    code: str
    description: str
    original_label: str
    protocol: NetworkProtocol


DEMO_PATTERNS: tuple[DemoPattern, ...] = (
    DemoPattern("p01", "benign browsing-like flows", "benign", NetworkProtocol.TCP),
    DemoPattern("p02", "benign DNS-like flows", "normal", NetworkProtocol.UDP),
    DemoPattern("p03", "benign file-transfer-like flows", "benign", NetworkProtocol.TCP),
    DemoPattern("p04", "controlled scan-like flows", "scan", NetworkProtocol.TCP),
    DemoPattern(
        "p05",
        "controlled brute-force-like repeated connections",
        "brute-force",
        NetworkProtocol.TCP,
    ),
    DemoPattern(
        "p06",
        "controlled beacon-like periodic communication",
        "beacon",
        NetworkProtocol.TCP,
    ),
    DemoPattern(
        "p07",
        "controlled exfiltration-like asymmetric transfer",
        "exfiltration",
        NetworkProtocol.TCP,
    ),
    DemoPattern(
        "p08",
        "controlled connection-flood-like restricted behavior",
        "connection-flood",
        NetworkProtocol.TCP,
    ),
)


def _packet(
    *,
    timestamp: datetime,
    protocol: NetworkProtocol,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    size: int,
    flags: int = 0,
) -> PacketRecord:
    protocol_number = 6 if protocol is NetworkProtocol.TCP else 17
    return PacketRecord(
        timestamp=timestamp,
        ip_version=4,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        protocol_number=protocol_number,
        network_bytes=size,
        tcp_flags=flags,
    )


def _observations(
    pattern: DemoPattern,
    *,
    start: datetime,
    variant: int,
    row_index: int,
) -> tuple[PacketRecord, ...]:
    """Build harmless metadata-only packet observations for feature calculation."""

    source_ip = f"192.0.2.{10 + variant}"
    destination_ip = f"198.51.100.{20 + variant}"
    source_port = 40_000 + variant * 10 + row_index
    destination_port = 53 if pattern.code == "p02" else 443
    delta = 0.01 * (variant * 5 + row_index + 1)

    def packet(
        seconds: float,
        size: int,
        flags: int = 0,
        *,
        reverse: bool = False,
    ) -> PacketRecord:
        return _packet(
            timestamp=start + timedelta(seconds=seconds),
            protocol=pattern.protocol,
            source_ip=destination_ip if reverse else source_ip,
            destination_ip=source_ip if reverse else destination_ip,
            source_port=destination_port if reverse else source_port,
            destination_port=source_port if reverse else destination_port,
            size=size + variant * 11 + row_index,
            flags=flags,
        )

    if pattern.code == "p01":
        return (
            packet(0.0, 60, 0x02),
            packet(delta, 60, 0x12, reverse=True),
            packet(delta * 2, 52, 0x10),
            packet(0.4 + delta, 700, 0x18),
            packet(0.7 + delta, 1_100, 0x18, reverse=True),
        )
    if pattern.code == "p02":
        return (packet(0.0, 70), packet(0.03 + delta, 110, reverse=True))
    if pattern.code == "p03":
        return (
            packet(0.0, 60, 0x02),
            packet(delta, 60, 0x12, reverse=True),
            packet(delta * 2, 52, 0x10),
            *tuple(
                packet(0.2 + index * 0.08 + delta, 1_300 + index * 7, 0x18)
                for index in range(6)
            ),
            packet(0.9 + delta, 80, 0x10, reverse=True),
        )
    if pattern.code == "p04":
        return (packet(0.0, 60, 0x02), packet(0.15 + delta, 60, 0x04, reverse=True))
    if pattern.code == "p05":
        return (
            packet(0.0, 60, 0x02),
            packet(0.04 + delta, 60, 0x12, reverse=True),
            packet(0.08 + delta, 52, 0x10),
            packet(0.2 + delta, 90, 0x18),
            packet(0.25 + delta, 60, 0x04, reverse=True),
        )
    if pattern.code == "p06":
        return (
            packet(0.0, 60, 0x02),
            packet(delta, 60, 0x12, reverse=True),
            packet(delta * 2, 52, 0x10),
            packet(5.0 + delta, 88, 0x18),
            packet(10.0 + delta, 92, 0x18),
            packet(15.0 + delta, 86, 0x18),
            packet(20.0 + delta, 90, 0x18),
        )
    if pattern.code == "p07":
        return (
            packet(0.0, 60, 0x02),
            packet(delta, 60, 0x12, reverse=True),
            packet(delta * 2, 52, 0x10),
            *tuple(
                packet(0.2 + index * 0.12 + delta, 1_420 + index * 3, 0x18)
                for index in range(8)
            ),
            packet(1.4 + delta, 64, 0x10, reverse=True),
        )
    return tuple(packet(index * (0.006 + delta / 10), 60, 0x02) for index in range(7))


def _finalize_observations(
    observations: tuple[PacketRecord, ...],
    *,
    source_id: UUID,
    capture_session_id: str,
) -> dict[str, float]:
    state = FlowState.from_first_packet(
        observations[0],
        source_id=source_id,
        capture_session_id=capture_session_id,
        max_packets=1_000,
    )
    for observation in observations[1:]:
        state.add(observation)
    state.mark_finalized()
    flow = finalize_network_flow(
        FinalizedFlowState(
            state=state,
            reason=FlowEndReason.CAPTURE_END,
            segment_index=0,
        )
    )
    features: dict[str, float] = {}
    for name in feature_names():
        value = flow.behavioral_features[name]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("Phase 3 feature engine returned a non-numeric value")
        features[name] = float(value)
    return features


def build_controlled_demo(
    *,
    seed: int,
    label_mapper: LabelMapper,
    groups_per_pattern: int = DEFAULT_GROUPS_PER_PATTERN,
) -> tuple[CanonicalDatasetRow, ...]:
    """Create deterministic synthetic canonical rows without network or payload activity."""

    if groups_per_pattern < 3:
        raise ValueError("controlled demo requires at least three groups per pattern")
    randomizer = random.Random(seed)
    rows: list[CanonicalDatasetRow] = []
    group_number = 0
    for pattern in DEMO_PATTERNS:
        for variant in range(groups_per_pattern):
            group_number += 1
            group_id = f"group-{group_number:03d}"
            scenario_id = f"scenario-{group_number:03d}"
            capture_session_id = f"capture-{group_number:03d}"
            source_file = f"source-{group_number:03d}.flow"
            source_checksum = hashlib.sha256(
                f"{DEMO_GENERATOR_VERSION}:{seed}:{group_number}".encode()
            ).hexdigest()
            for row_index in range(ROWS_PER_GROUP):
                start_offset = group_number * 120 + row_index * 30 + randomizer.randint(0, 7)
                start = BASE_TIME + timedelta(seconds=start_offset)
                record_id = f"record-{group_number:03d}-{row_index + 1:02d}"
                source_id = uuid5(NAMESPACE_URL, f"{DEMO_DATASET_ID}:{group_id}")
                observations = _observations(
                    pattern,
                    start=start,
                    variant=variant,
                    row_index=row_index,
                )
                values_by_name = _finalize_observations(
                    observations,
                    source_id=source_id,
                    capture_session_id=capture_session_id,
                )
                rows.append(
                    CanonicalDatasetRow(
                        canonical_schema_version=CANONICAL_SCHEMA_VERSION,
                        metadata=CanonicalMetadata(
                            dataset_id=DEMO_DATASET_ID,
                            dataset_version=DEMO_DATASET_VERSION,
                            record_id=record_id,
                            source_file=source_file,
                            source_file_checksum=source_checksum,
                            capture_session_id=capture_session_id,
                            scenario_id=scenario_id,
                            group_id=group_id,
                            original_row_id=str(row_index + 1),
                            source_access_date=BASE_TIME.date(),
                            observed_at=start,
                            provenance={
                                "generator": "aegishunt-controlled-demo",
                                "generator_version": DEMO_GENERATOR_VERSION,
                                "pattern_code": pattern.code,
                                "synthetic": "true",
                            },
                            conversion_version=CONVERSION_VERSION,
                        ),
                        features=CanonicalFeatureVector(
                            schema_version=FEATURE_SCHEMA_VERSION,
                            names=feature_names(),
                            values=tuple(values_by_name[name] for name in feature_names()),
                        ),
                        labels=label_mapper.map(pattern.original_label),
                    )
                )
    return tuple(rows)


def demo_generation_config(seed: int, groups_per_pattern: int) -> dict[str, object]:
    """Return manifest-safe configuration with explicit scenario descriptions."""

    return {
        "generator_version": DEMO_GENERATOR_VERSION,
        "seed": seed,
        "groups_per_pattern": groups_per_pattern,
        "rows_per_group": ROWS_PER_GROUP,
        "controlled_synthetic": True,
        "network_access": False,
        "external_target": False,
        "patterns": [pattern.description for pattern in DEMO_PATTERNS],
    }
