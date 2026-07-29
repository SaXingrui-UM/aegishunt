"""Phase 13 regressions for bounded untrusted telemetry parsing."""

from __future__ import annotations

import asyncio
import struct
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.responses import JSONResponse
from starlette.types import Message, Receive, Scope, Send

from aegishunt.api.app import create_app
from aegishunt.api.middleware import RequestBodyLimitMiddleware
from aegishunt.config import (
    ApplicationSettings,
    DatabaseSettings,
    IngestionSettings,
    WebSettings,
)
from aegishunt.flows.errors import CaptureFormatError
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.ingestion.errors import FilePolicyError, TelemetryFormatError
from aegishunt.ingestion.file_storage import SafeFileStorage
from aegishunt.ingestion.flow_csv import FlowCsvIngestor
from aegishunt.ingestion.json_events import JsonEventIngestor
from aegishunt.ingestion.pcap import PcapIngestor

SAMPLE_FLOW_CSV = Path(__file__).parents[2] / "data" / "sample" / "phase2-flows.csv"


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


def test_json_parser_rejects_extreme_nesting_before_decoder_recursion(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "extreme.json"
    nested.write_text(
        '{"value":' + ("[" * 20_000) + "0" + ("]" * 20_000) + "}",
        encoding="utf-8",
    )

    with pytest.raises(TelemetryFormatError, match="nesting depth"):
        JsonEventIngestor(
            maximum_record_bytes=100_000,
            maximum_depth=64,
        ).inspect(nested, max_records=1)


def test_json_depth_scanner_ignores_structural_characters_inside_strings(
    tmp_path: Path,
) -> None:
    event = tmp_path / "string-brackets.json"
    event.write_text('{"value":"[[[{{{\\"nested-looking\\"}}}]]]"}', encoding="utf-8")

    inspection = JsonEventIngestor(maximum_depth=2).inspect(event, max_records=1)

    assert inspection.records_processed == 1


def test_flow_csv_rejects_missing_and_extra_schema_columns(tmp_path: Path) -> None:
    source = SAMPLE_FLOW_CSV.read_text(encoding="utf-8")
    header, *rows = source.splitlines()
    columns = header.split(",")

    missing = tmp_path / "missing.csv"
    missing.write_text(
        ",".join(column for column in columns if column != "backward_bytes")
        + "\n"
        + "\n".join(rows),
        encoding="utf-8",
    )
    with pytest.raises(TelemetryFormatError, match="missing required columns"):
        FlowCsvIngestor().inspect(missing, max_records=10)

    extra = tmp_path / "extra.csv"
    extra.write_text(
        header + ",untrusted_field\n" + "\n".join(f"{row},value" for row in rows),
        encoding="utf-8",
    )
    with pytest.raises(TelemetryFormatError, match="unsupported columns"):
        FlowCsvIngestor().inspect(extra, max_records=10)


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


def test_raw_body_limit_rejects_underreported_streaming_content_length() -> None:
    messages = iter(
        (
            {"type": "http.request", "body": b"123", "more_body": True},
            {"type": "http.request", "body": b"456", "more_body": False},
        )
    )
    sent: list[Message] = []

    async def receive() -> Message:
        return next(messages)

    async def send(message: Message) -> None:
        sent.append(message)

    async def consume_body(scope: Scope, receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if not message.get("more_body", False):
                break
        await JSONResponse({"status": "unexpected"})(scope, receive, send)

    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/ingestion/json",
        "raw_path": b"/ingestion/json",
        "query_string": b"",
        "headers": [(b"content-length", b"1")],
        "client": ("127.0.0.1", 10000),
        "server": ("127.0.0.1", 8000),
    }
    middleware = RequestBodyLimitMiddleware(
        consume_body,
        limits={"/ingestion/json": 4},
    )

    asyncio.run(middleware(scope, receive, send))

    response_start = next(message for message in sent if message["type"] == "http.response.start")
    assert response_start["status"] == 413
    assert b"request_body_too_large" in b"".join(
        message.get("body", b"")
        for message in sent
        if message["type"] == "http.response.body"
    )


def test_upload_staging_accepts_exact_limit_and_cleans_exceeded_limit(
    tmp_path: Path,
) -> None:
    storage = SafeFileStorage(tmp_path, max_bytes=4, chunk_size=2)

    exact = storage.stage(
        BytesIO(b"1234"),
        filename="exact.pcap",
        content_type="application/octet-stream",
        policy=PcapIngestor.policy,
    )
    assert exact.byte_size == 4
    stored = storage.commit(exact)
    assert (tmp_path / stored.stored_filename).read_bytes() == b"1234"

    with pytest.raises(FilePolicyError, match="configured limit"):
        storage.stage(
            BytesIO(b"12345"),
            filename="exceeded.pcap",
            content_type="application/octet-stream",
            policy=PcapIngestor.policy,
        )
    assert not list(tmp_path.glob(".upload-*"))
