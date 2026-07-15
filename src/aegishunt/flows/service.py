"""Pure PCAP-to-flow processing boundary without database access."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from aegishunt.config import FlowSettings
from aegishunt.flows.aggregator import FlowAggregator
from aegishunt.flows.finalizer import finalize_network_flow
from aegishunt.flows.packets import parse_packet
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.schemas.telemetry import NetworkFlow


@dataclass(frozen=True, slots=True)
class PcapFlowResult:
    """Deterministic extraction result and explicit packet handling counts."""

    flows: tuple[NetworkFlow, ...]
    captured_packets: int
    decoded_packets: int
    skipped_packets: int


class PcapFlowProcessor:
    """Stream one stored capture through parsing, aggregation, and finalization."""

    def __init__(self, settings: FlowSettings, *, max_records: int) -> None:
        self._settings = settings
        self._reader = PcapPacketReader(
            max_records=max_records,
            max_packet_bytes=settings.max_packet_bytes,
        )

    def process(
        self,
        path: Path,
        *,
        source_id: UUID,
        capture_session_id: str,
    ) -> PcapFlowResult:
        """Return all flows only after the entire capture has parsed successfully."""

        aggregator = FlowAggregator(
            self._settings,
            source_id=source_id,
            capture_session_id=capture_session_id,
        )
        flows: list[NetworkFlow] = []
        captured_packets = 0
        decoded_packets = 0
        skipped_packets = 0
        for captured in self._reader.packets(path):
            captured_packets += 1
            packet = parse_packet(
                captured.frame,
                timestamp=captured.timestamp,
                link_type=captured.link_type,
            )
            if packet is None:
                skipped_packets += 1
                continue
            decoded_packets += 1
            flows.extend(
                finalize_network_flow(finalized)
                for finalized in aggregator.process(packet)
            )
        flows.extend(
            finalize_network_flow(finalized)
            for finalized in aggregator.flush_capture_end()
        )
        return PcapFlowResult(
            flows=tuple(flows),
            captured_packets=captured_packets,
            decoded_packets=decoded_packets,
            skipped_packets=skipped_packets,
        )
