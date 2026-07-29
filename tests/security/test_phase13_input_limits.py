"""Phase 13 regressions for bounded untrusted telemetry parsing."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import (
    ApplicationSettings,
    DatabaseSettings,
    IngestionSettings,
    WebSettings,
)
from aegishunt.flows.errors import CaptureFormatError
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.ingestion.errors import TelemetryFormatError
from aegishunt.ingestion.json_events import JsonEventIngestor


def _pcapng_section() -> bytes:
    return (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHqI", 1, 0, -1, 28)
    )


def _pcapng_interface() -> bytes:
    return struct.pack("<IIHHII", 1, 20, 1, 0, 65_535, 20)


def test_json_array_and_jsonl_enforce_limits_during_incremental_parsing(
    tmp_path: Path,
) -> None:
    array = tmp_path / "events.json"
    array.write_text(
        "[" + ",".join(f'{{\"event\": {index}}}' for index in range(20)) + "]",
        encoding="utf-8",
    )
    with pytest.raises(TelemetryFormatError, match="record limit"):
        JsonEventIngestor(maximum_record_bytes=64).inspect(array, max_records=5)

    jsonl = tmp_path / "events.jsonl"
    jsonl.write_text('{"payload":"' + ("a" * 256) + '"}\n', encoding="utf-8")
    with pytest.raises(TelemetryFormatError, match="per-record byte limit"):
        JsonEventIngestor(maximum_record_bytes=64).inspect(jsonl, max_records=5)


def test_json_parser_rejects_excessive_nesting_without_recursive_failure(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "nested.json"
    nested.write_text('{"value":' + ("[" * 12) + "0" + ("]" * 12) + "}", encoding="utf-8")

    with pytest.raises(TelemetryFormatError, match="nesting depth"):
        JsonEventIngestor(maximum_depth=8).inspect(nested, max_records=1)


def test_pcapng_interface_inventory_is_bounded_before_packet_processing(
    tmp_path: Path,
) -> None:
    capture = tmp_path / "interfaces.pcapng"
    capture.write_bytes(_pcapng_section() + (_pcapng_interface() * 3))

    reader = PcapPacketReader(
        max_records=10,
        max_packet_bytes=2_048,
        max_interfaces=2,
    )
    with pytest.raises(CaptureFormatError, match="interface inventory"):
        list(reader.packets(capture))


def test_api_rejects_raw_multipart_body_before_creating_an_ingestion_job(
    tmp_path: Path,
) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'api.db'}"),
        ingestion=IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=tmp_path / "samples",
            max_upload_bytes=8_192,
        ),
        web=WebSettings(
            maximum_json_upload_bytes=32,
            maximum_multipart_overhead_bytes=1_024,
        ),
    )

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/ingestion/json",
            files={
                "file": (
                    "events.json",
                    b'{"payload":"' + (b"a" * 4_096) + b'"}',
                    "application/json",
                )
            },
            data={
                "actor": "security-test",
                "reason": "pre-parser request body limit",
                "confirm": "true",
            },
        )
        jobs = client.get("/ingestion/jobs")

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "request_body_too_large"
    assert jobs.status_code == 200
    assert jobs.json()["total"] == 0
    assert not list((tmp_path / "raw").glob("*"))
