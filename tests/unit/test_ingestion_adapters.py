"""Unit tests for bounded Phase 2 telemetry container validation."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from aegishunt.ingestion.errors import SampleDataError, TelemetryFormatError
from aegishunt.ingestion.flow_csv import FlowCsvIngestor
from aegishunt.ingestion.json_events import JsonEventIngestor
from aegishunt.ingestion.pcap import PcapIngestor
from aegishunt.ingestion.samples import SampleDataRegistry

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def test_pcap_inspector_counts_container_records_without_deriving_flows() -> None:
    inspection = PcapIngestor().inspect(
        SAMPLE_ROOT / "phase2-benign.pcap",
        max_records=10,
    )

    assert inspection.records_processed == 1
    assert inspection.metadata["container"] == "pcap"
    assert inspection.metadata["link_type"] == 1


def test_pcap_inspector_rejects_truncation_and_record_overflow(tmp_path: Path) -> None:
    original = (SAMPLE_ROOT / "phase2-benign.pcap").read_bytes()
    truncated = tmp_path / "truncated.pcap"
    truncated.write_bytes(original[:-1])

    with pytest.raises(TelemetryFormatError, match="truncated"):
        PcapIngestor().inspect(truncated, max_records=10)
    with pytest.raises(TelemetryFormatError, match="record limit"):
        PcapIngestor().inspect(SAMPLE_ROOT / "phase2-benign.pcap", max_records=0)


def test_pcapng_inspector_counts_packet_blocks(tmp_path: Path) -> None:
    section = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )
    interface = struct.pack("<IIHHII", 1, 20, 1, 0, 65_535, 20)
    enhanced_packet = struct.pack("<IIIIIIII", 6, 32, 0, 0, 0, 0, 0, 32)
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(section + interface + enhanced_packet)

    inspection = PcapIngestor().inspect(capture, max_records=1)

    assert inspection.records_processed == 1
    assert inspection.metadata["container"] == "pcapng"
    assert inspection.metadata["version"] == "1.0"


def test_flow_csv_inspector_validates_canonical_rows(tmp_path: Path) -> None:
    inspection = FlowCsvIngestor().inspect(
        SAMPLE_ROOT / "phase2-flows.csv",
        max_records=10,
    )
    assert inspection.records_processed == 2
    assert inspection.metadata["container"] == "flow_csv"

    invalid = tmp_path / "invalid.csv"
    invalid.write_text(
        (SAMPLE_ROOT / "phase2-flows.csv").read_text(encoding="utf-8").replace(
            "192.0.2.10", "not-an-ip", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(TelemetryFormatError, match="source_ip"):
        FlowCsvIngestor().inspect(invalid, max_records=10)

    non_finite = tmp_path / "non-finite.csv"
    non_finite.write_text(
        (SAMPLE_ROOT / "phase2-flows.csv").read_text(encoding="utf-8").replace(
            "Z,0.125,192.0.2.10", "Z,inf,192.0.2.10", 1
        ),
        encoding="utf-8",
    )
    with pytest.raises(TelemetryFormatError, match="duration"):
        FlowCsvIngestor().inspect(non_finite, max_records=10)


def test_json_event_inspector_accepts_objects_and_rejects_invalid_values(
    tmp_path: Path,
) -> None:
    json_path = tmp_path / "events.json"
    json_path.write_text('[{"event": "login"}, {"event": "logout"}]', encoding="utf-8")
    inspection = JsonEventIngestor().inspect(json_path, max_records=2)
    assert inspection.records_processed == 2
    assert inspection.metadata == {"container": "json_array"}

    json_lines = tmp_path / "events.jsonl"
    json_lines.write_text('{"event": 1}\n{"event": 2}\n', encoding="utf-8")
    assert JsonEventIngestor().inspect(json_lines, max_records=2).records_processed == 2

    invalid = tmp_path / "invalid.json"
    invalid.write_text('{"score": NaN}', encoding="utf-8")
    with pytest.raises(TelemetryFormatError, match="non-finite"):
        JsonEventIngestor().inspect(invalid, max_records=2)


def test_sample_registry_verifies_manifest_checksum(tmp_path: Path) -> None:
    registry = SampleDataRegistry(SAMPLE_ROOT)
    descriptors = registry.list()

    assert {item.sample_id for item in descriptors} == {
        "phase2-benign-pcap",
        "phase2-flow-csv",
    }
    assert registry.resolve("phase2-benign-pcap").path.is_file()
    with pytest.raises(SampleDataError, match="unknown"):
        registry.resolve("not-declared")

    sample = tmp_path / "sample.json"
    sample.write_text("{}", encoding="utf-8")
    (tmp_path / "manifest.yaml").write_text(
        """
version: 1
samples:
  - sample_id: changed
    filename: sample.json
    source_type: json_event
    content_type: application/json
    checksum: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    description: Deliberately mismatched checksum fixture.
    synthetic: true
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(SampleDataError, match="checksum"):
        SampleDataRegistry(tmp_path).resolve("changed")
