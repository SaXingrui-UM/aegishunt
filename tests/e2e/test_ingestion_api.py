"""No-root, target-free end-to-end tests for Phase 2 ingestion APIs."""

from pathlib import Path

from fastapi.testclient import TestClient

from aegishunt.api.app import create_app
from aegishunt.config import ApplicationSettings, DatabaseSettings, IngestionSettings

SAMPLE_ROOT = Path(__file__).parents[2] / "data" / "sample"


def test_upload_status_failure_and_sample_end_to_end(tmp_path: Path) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'api.db'}"),
        ingestion=IngestionSettings(
            storage_root=tmp_path / "raw",
            sample_root=SAMPLE_ROOT,
            max_upload_bytes=1_024,
            chunk_size_bytes=16,
            max_records=10,
        ),
    )
    pcap = (SAMPLE_ROOT / "phase2-benign.pcap").read_bytes()

    with TestClient(create_app(settings)) as client:
        uploaded = client.post(
            "/ingestion/pcap",
            files={"file": ("capture.pcap", pcap, "application/vnd.tcpdump.pcap")},
            data={"actor": "api-test", "reason": "ingestion regression", "confirm": "true"},
        )
        assert uploaded.status_code == 201
        payload = uploaded.json()
        assert payload["status"] == "completed"
        assert payload["records_processed"] == 1

        fetched = client.get(f"/ingestion/jobs/{payload['job_id']}")
        assert fetched.status_code == 200
        assert fetched.json() == payload
        listed = client.get("/ingestion/jobs", params={"limit": 10, "offset": 0})
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

        rejected = client.post(
            "/ingestion/pcap",
            files={"file": ("broken.pcap", b"broken", "application/octet-stream")},
            data={"actor": "api-test", "reason": "failure regression", "confirm": "true"},
        )
        assert rejected.status_code == 422
        error = rejected.json()
        assert error["error_code"] == "telemetry_format_error"
        assert error["details"] is not None
        failed = client.get(f"/ingestion/jobs/{error['details']['job_id']}")
        assert failed.json()["status"] == "failed"

        samples = client.get("/ingestion/samples")
        assert samples.status_code == 200
        assert {
            item["sample_id"] for item in samples.json()
        } == {
            "phase2-benign-pcap",
            "phase2-flow-csv",
            "phase12-demo-pcap",
            "phase12-presentation-demo-pcap",
            "phase14-attack-like-pcap",
            "phase14-benign-like-pcap",
        }
        sample_job = client.post("/ingestion/samples/phase2-flow-csv")
        assert sample_job.status_code == 201
        assert sample_job.json()["source_type"] == "sample"
        assert sample_job.json()["records_processed"] == 2

    assert len(list((tmp_path / "raw").glob("*"))) == 2
